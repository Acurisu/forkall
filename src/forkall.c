#include "forkall.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "sigpatch.h"

// Marker that does not appear anywhere under the "pause_me" function
#define MARKER              \
    0x0f, 0x1f, 0x44, 0x00, \
        0x00  // 5-byte NOP (nop   DWORD PTR [rax+rax*1+0x0])

#define STR_HELPER(...) #__VA_ARGS__
#define STR(x) STR_HELPER(x)

// General variables
static pthread_t threads[NUM_THREADS];

// Parent variables
static pid_t p_tids[NUM_THREADS] = {0};
static volatile int p_thread_cnt = 0;
pthread_mutex_t p_mutex;

// Child variables
static volatile sig_atomic_t c_thread_cnt = 0;

// Thread variables
_Thread_local pid_t tls_tid = -1;
_Thread_local int tls_idx = -1;

// Pause function to "stop" the threads cheaply
// in a non critical section. They cannot continue on their own but
// instead need RIP += 0xF to jump over the loop condition.
// We use a volatile variable to avoid DCE removing things after the loop
// and assembly to make sure the spacing is correct.
volatile int continue_loop = 1;
void pause_me() {
    __asm__ volatile(
        "jmp check_loop\n\t"

        "loop_body:\n\t"
        "movl $1000000, %%edi\n\t"
        "call usleep\n\t"

        "marker: .byte " STR(MARKER) "\n\t"

        "check_loop:\n\t"
        "movl continue_loop(%%rip), %%eax\n\t"
        "testl %%eax, %%eax\n\t"
        "jnz loop_body\n\t"

        : /* no outputs */
        : /* no inputs */
        : "eax", "edi", "memory"
    );
#ifdef DEBUG
    puts("Resuming....");
#endif
}

int get_task_tids(pid_t pid, pid_t *out, int max_count) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path);
    if (!d) {
        perror("opendir");
        return -1;
    }
    int count = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && count < max_count) {
        if (de->d_name[0] == '.') continue;
        pid_t tid = (pid_t)atoi(de->d_name);
        if (tid > 0) out[count++] = tid;
    }
    closedir(d);
    return count;
}

void setup_wait() {
    while (p_thread_cnt < NUM_THREADS) {
#ifdef DEBUG
        printf("[Setup]\tWaiting for real threads to start...\n");
#endif
        usleep(100 * 1000);
    }

#ifdef DEBUG
    printf("[Setup]\tAll real threads started.\n");
#endif
}

void setup_register() {
    if (pthread_mutex_lock(&p_mutex)) {
        perror("pthread_mutex_lock");
        exit(EXIT_FAILURE);
    }

    tls_tid = (pid_t)syscall(SYS_gettid);
    tls_idx = p_thread_cnt;
    p_tids[p_thread_cnt] = tls_tid;
    threads[p_thread_cnt] = pthread_self();
#ifdef DEBUG
    printf("[Setup]\tThread %d registered (TID=%d)\n", tls_idx, tls_tid);
#endif
    ++p_thread_cnt;

    if (pthread_mutex_unlock(&p_mutex)) {
        perror("pthread_mutex_unlock");
        exit(EXIT_FAILURE);
    }

    pause_me();
}

int snapshot(struct user_regs_struct saved_regs[]) {
    int status;
    const uint8_t marker_bytes[5] = {MARKER};

    for (int i = 0; i < NUM_THREADS; ++i) {
        pid_t tid = p_tids[i];
#ifdef DEBUG
        printf("[Snapshot]\tGetting regs for thread %d (TID=%d)\n", i, tid);
#endif
        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL)) {
            perror("ptrace attach");
            return -1;
        }

        if (waitpid(tid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }

        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "Thread %d did not stop as expected\n", tid);
            return -1;
        }

        // Loop to step out of the (potential) syscall
        while (1) {
            if (ptrace(PTRACE_GETREGS, tid, NULL, &saved_regs[i])) {
                perror("ptrace getregs");
                return -1;
            }

            errno = 0;
            long word =
                ptrace(PTRACE_PEEKTEXT, tid, (void *)saved_regs[i].rip, NULL);
            if (word && errno) {
                perror("ptrace peektext");
                return -1;
            }

            uint8_t instr_bytes[sizeof(word)];
            for (size_t i = 0; i < sizeof(word); ++i) {
                instr_bytes[i] = (word >> (i * 8)) & 0xFF;
            }

            int marker_found = 1;
            for (size_t i = 0; i < sizeof(marker_bytes); ++i) {
                if (instr_bytes[i] != marker_bytes[i]) {
                    marker_found = 0;
                    break;
                }
            }
            if (marker_found) {
#ifdef DEBUG
                printf("[Snapshot]\tMarker found at RIP: 0x%llx\n",
                       (unsigned long long)saved_regs[i].rip);
#endif
                break;
            }

            if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL)) {
                perror("ptrace single-step");
                return -1;
            }
            if (waitpid(tid, &status, 0) == -1) {
                perror("waitpid");
                return -1;
            }
            if (!WIFSTOPPED(status)) {
                fprintf(stderr, "Thread %d did not stop as expected\n", tid);
                return -1;
            }
        }

        // Increase RIP to skip to after the loop condition
        saved_regs[i].rip += 0xF;

        if (ptrace(PTRACE_DETACH, tid, NULL, NULL)) {
            perror("ptrace detach");
            return -1;
        }
    }
    return 0;
}

int restore(pid_t target_pid, struct user_regs_struct saved_regs[]) {
    int status;
    int N = NUM_THREADS + 1;
    int i = 0;
    pid_t tids[N];
    if (get_task_tids(target_pid, tids, N) == -1) {
        perror("get_task_tids");
        return -1;
    }
    for (int j = 0; j < N; ++j) {
        pid_t tid = tids[j];
        if (tid == target_pid) continue;

#ifdef DEBUG
        printf("[Restore]\tResuming thread %d (TID=%d)\n", i, tid);
#endif

        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL)) {
            perror("ptrace attach");
            return -1;
        }

        if (waitpid(tid, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }

        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "Thread %d did not stop as expected\n", tid);
            return -1;
        }

#ifdef DEBUG
        printf("[Restore]\tThread %d: rbp=0x%llx, rsp=0x%llx\n", i,
               (unsigned long long)saved_regs[i].rbp,
               (unsigned long long)saved_regs[i].rsp);
#endif

        if (ptrace(PTRACE_SETREGS, tid, NULL, &saved_regs[i])) {
            perror("ptrace setregs");
            return -1;
        }

        if (ptrace(PTRACE_DETACH, tid, NULL, NULL)) {
            perror("ptrace detach");
            return -1;
        }

        ++i;
    }

    return 0;
}

void *mock_routine(void *arg) {
#ifdef DEBUG
    printf("[Recreate]\tThread started (TID=%d)\n", (pid_t)syscall(SYS_gettid));
#endif

    __sync_fetch_and_add(&c_thread_cnt, 1);
    pause_me();

    assert(0 && "Mock routine continued, this should never happen");
}

int recreate() {
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_create(&threads[i], NULL, mock_routine, NULL)) {
            perror("pthread_create");
            return -1;
        }
    }

    while (c_thread_cnt < NUM_THREADS) {
#ifdef DEBUG
        printf("[Recreate]\tWaiting for child threads to start...\n");
#endif
        usleep(100 * 1000);
    }
}

void cleanup() {
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_join(threads[i], NULL)) {
            perror("pthread_join");
            exit(EXIT_FAILURE);
        }
    }

    exit(EXIT_SUCCESS);
}

void cleanup_unregister() {
#ifdef DEBUG
    printf("[Recreate]\tThread %d unregistered (TID=%d, originally %d)\n",
           tls_idx, (pid_t)syscall(SYS_gettid), tls_tid);
#endif
    pthread_exit(NULL);
}

void child(pid_t tracer_pid) {
    recreate();
    if (kill(tracer_pid, SIGUSR1) == -1) {
        perror("Failed to send SIGUSR1");
        exit(EXIT_FAILURE);
    }
}

int recreate_tracer_wait(sigset_t *set, int *sig) {
    if (sigwait(set, sig)) {
        perror("sigwait");
        return -1;
    }

#ifdef DEBUG
    printf("[Recreate]\tReceived SIGUSR1 from child.\n");
#endif
    return 0;
}

int cleanup_tracer(pid_t child_pid) {
    int status;
    if (waitpid(child_pid, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }
    return 0;
}

void tracer() {
    pid_t pid = getpid();
    sigset_t set;
    int sig;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);

    struct user_regs_struct saved_regs[NUM_THREADS];
    if (snapshot(saved_regs)) {
        perror("snapshot");
        exit(EXIT_FAILURE);
    }

    while (1) {
        int child_pid = fork();
        if (child_pid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        }

        if (child_pid == 0) {
            break;
        }

        recreate_tracer_wait(&set, &sig);

        if (restore(child_pid, saved_regs)) {
            perror("restore");
            exit(EXIT_FAILURE);
        }

        if (cleanup_tracer(child_pid)) {
            perror("cleanup");
            exit(EXIT_FAILURE);
        }
    }
}

int patch() {
    unsigned char patch0[11];
    memset(patch0, 0x90, sizeof(patch0));
    unsigned char patch1[32];
    memset(patch1, 0x90, sizeof(patch1));
    unsigned char patch2[5] = {0xE9, 0x63, 0x01, 0x00, 0x00};

    patch_entry_t patches[] = {
        {"48 C7 82 80 08 00 00 ? ? ? ?", 0, patch0,
         sizeof(
             patch0)},  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/arena.c#L213
        {"48 8B 0D ? ? ? ? 48 C7 80 80 08 00 00 00 00 ? ?", 0, patch1,
         sizeof(
             patch1)},  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/arena.c#L221-L223
        {"49 8B 85 ? ? ? ? 66 0F EF C0", 0, patch2,
         sizeof(
             patch2)},  // https://elixir.bootlin.com/glibc/glibc-2.39/source/posix/fork.c#L106
    };
    size_t patch_count = sizeof(patches) / sizeof(patches[0]);

    return apply_patches("libc", 1, patches, patch_count);
}

void parent() {
    setup_wait();

    if (patch()) {
        perror("patch");
        exit(EXIT_FAILURE);
    }

    int tracer_pid = fork();
    if (tracer_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (tracer_pid) {
        while (1) {
            pause();
        }
    }

    tracer_pid = getpid();
    tracer();

    child(tracer_pid);
}
