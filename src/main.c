#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "forkall.h"

_Thread_local pid_t thread_id = -1;

void seed_rng() {
    unsigned int seed;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        exit(EXIT_FAILURE);
    }

    if (read(fd, &seed, sizeof(seed)) != sizeof(seed)) {
        exit(EXIT_FAILURE);
    }

    close(fd);
    srand(seed);
}

void print(const char *msg) {
    pid_t tid = (pid_t)syscall(SYS_gettid);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("[%ld.%03ld] [A %d / O %d]\t%s\n", tv.tv_sec, tv.tv_usec / 1000, tid,
           thread_id, msg);
}

// Sleep for a random amount of time to simulate work
void work(int min_sleep, int max_sleep, int is_setup) {
    int sleep_time = rand() % (max_sleep - min_sleep + 1) + min_sleep;
    char msg[128];
    snprintf(msg, sizeof(msg), "[%s]\tsleeping for %d seconds",
             is_setup ? "Stp" : "Wrk", sleep_time);
    print(msg);
    sleep(sleep_time);
    snprintf(msg, sizeof(msg), "[%s]\twoke up", is_setup ? "Stp" : "Wrk");
    print(msg);
}

void *routine(void *arg) {
    thread_id = (pid_t)syscall(SYS_gettid);
    seed_rng();
    work(0, 5, 1);         // Some expensive setup
    setup_register();      // Section A
    work(0, 2, 0);         // Some cheaper work
    cleanup_unregister();  // Section B
    print("finished");
    return NULL;
}

int main(int argc, char *argv[]) {
    thread_id = (pid_t)syscall(SYS_gettid);
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, routine, NULL);
    }

    seed_rng();
    work(0, 5, 1);  // Some expensive setup
    parent();       // Section A
    work(0, 2, 0);  // Some cheaper work
    cleanup();      // Section B
    print("finished");

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
