#include "sigpatch.h"

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "config.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    uintptr_t start;
    uintptr_t end;
    char perms[5];            // e.g. "r-xp"
    char pathname[PATH_MAX];  // may be empty
} mem_range_t;

mem_range_t *get_memory_ranges(const char *name_regex, int require_exec,
                               size_t *out_count) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen");
        return NULL;
    }
    mem_range_t *ranges = NULL;
    size_t count = 0;
    char line[1024];
    regex_t regex;
    int use_regex = 0;
    if (name_regex && strlen(name_regex) > 0) {
        if (regcomp(&regex, name_regex, REG_EXTENDED | REG_NOSUB) != 0) {
            fprintf(stderr, "Failed to compile regex\n");
            fclose(fp);
            return NULL;
        }
        use_regex = 1;
    }
    while (fgets(line, sizeof(line), fp)) {
        mem_range_t range;
        /* Example line format:
           7f7f86000000-7f7f86200000 r-xp 00000000 fc:01 123456
           /usr/lib/libc.so.6 */
        char perms[5], dev[6], pathname[PATH_MAX];
        unsigned long start, end, offset, inode;
        int fields = sscanf(line, "%lx-%lx %4s %lx %5s %lu %s", &start, &end,
                            perms, &offset, dev, &inode, pathname);
        if (fields < 6) continue;  // Some lines may not have a pathname
        range.start = start;
        range.end = end;
        strncpy(range.perms, perms, 4);
        range.perms[4] = '\0';
        if (fields == 7)
            strncpy(range.pathname, pathname, PATH_MAX - 1);
        else
            range.pathname[0] = '\0';
        if (require_exec && (strchr(range.perms, 'x') == NULL)) continue;
        if (use_regex && strlen(range.pathname) > 0) {
            if (regexec(&regex, range.pathname, 0, NULL, 0) != 0) continue;
        }
        mem_range_t *new_ranges =
            realloc(ranges, (count + 1) * sizeof(mem_range_t));
        if (!new_ranges) {
            perror("realloc");
            free(ranges);
            if (use_regex) regfree(&regex);
            fclose(fp);
            return NULL;
        }
        ranges = new_ranges;
        ranges[count++] = range;
    }
    if (use_regex) regfree(&regex);
    fclose(fp);
    *out_count = count;
    return ranges;
}

int parse_pattern(const char *pattern_str, unsigned char **out_pattern,
                  char **out_mask, size_t *out_len) {
    if (!pattern_str || !out_pattern || !out_mask || !out_len) return -1;
    char *dup = strdup(pattern_str);
    if (!dup) return -1;
    size_t count = 0;
    char *tok = strtok(dup, " ");
    while (tok) {
        count++;
        tok = strtok(NULL, " ");
    }
    free(dup);
    unsigned char *pattern = malloc(count);
    char *mask = malloc(count + 1);
    if (!pattern || !mask) {
        free(pattern);
        free(mask);
        return -1;
    }
    dup = strdup(pattern_str);
    tok = strtok(dup, " ");
    size_t i = 0;
    while (tok) {
        if (tok[0] == '?') {
            pattern[i] = 0;
            mask[i] = '?';
        } else {
            pattern[i] = (unsigned char)strtoul(tok, NULL, 16);
            mask[i] = 'x';
        }
        ++i;
        tok = strtok(NULL, " ");
    }
    mask[count] = '\0';
    free(dup);
    *out_pattern = pattern;
    *out_mask = mask;
    *out_len = count;
    return 0;
}

uintptr_t *signature_scan(const unsigned char *pattern, const char *mask,
                          size_t pat_len, mem_range_t *ranges,
                          size_t range_count, size_t *match_count) {
    if (!pattern || !mask || pat_len == 0 || !ranges || range_count == 0 ||
        !match_count)
        return NULL;
    uintptr_t *matches = NULL;
    size_t count = 0;
    for (size_t r = 0; r < range_count; r++) {
        size_t region_size = ranges[r].end - ranges[r].start;
        if (region_size < pat_len) continue;
        unsigned char *base = (unsigned char *)ranges[r].start;
        for (size_t i = 0; i <= region_size - pat_len; ++i) {
            int found = 1;
            for (size_t j = 0; j < pat_len; j++) {
                if (mask[j] == 'x' && base[i + j] != pattern[j]) {
                    found = 0;
                    break;
                }
            }
            if (found) {
                uintptr_t addr = ranges[r].start + i;
                uintptr_t *tmp =
                    realloc(matches, (count + 1) * sizeof(uintptr_t));
                if (!tmp) {
                    free(matches);
                    return NULL;
                }
                matches = tmp;
                matches[count++] = addr;
            }
        }
    }
    *match_count = count;
    return matches;
}

int patch_bytes(uintptr_t address, const unsigned char *patch,
                size_t patch_len) {
    if (!patch || patch_len == 0) return -1;
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 0) return -1;
    uintptr_t page_start = address & ~(pagesize - 1);
    uintptr_t end_addr = address + patch_len;
    size_t len = end_addr - page_start;
    if (mprotect((void *)page_start, len, PROT_READ | PROT_WRITE | PROT_EXEC) !=
        0) {
        perror("mprotect");
        return -1;
    }
    memcpy((void *)address, patch, patch_len);

    __builtin___clear_cache((char *)address, (char *)(address + patch_len));
    return 0;
}

static int apply_patch_list(patch_entry_t *patches, size_t patch_count,
                            mem_range_t *ranges, size_t range_count) {
    for (size_t j = 0; j < patch_count; j++) {
        patch_entry_t *entry = &patches[j];
        unsigned char *pattern = NULL;
        char *mask = NULL;
        size_t pat_len = 0;

        if (parse_pattern(entry->pattern_str, &pattern, &mask, &pat_len) != 0) {
            fprintf(stderr, "Failed to parse pattern: %s\n",
                    entry->pattern_str);
            return 1;
        }

#ifdef DEBUG
        printf("Parsed pattern (%zu bytes):\n", pat_len);
        for (size_t i = 0; i < pat_len; ++i) {
            if (mask[i] == 'x')
                printf("%02X ", pattern[i]);
            else
                printf("? ");
        }
        printf("\n");
#endif

        size_t match_count = 0;
        uintptr_t *matches = signature_scan(pattern, mask, pat_len, ranges,
                                            range_count, &match_count);
        if (!matches) {
            printf("No matches found for pattern: %s\n", entry->pattern_str);
        } else {
#ifdef DEBUG
            printf("Found %zu match(es) for pattern: %s\n", match_count,
                   entry->pattern_str);
            for (size_t i = 0; i < match_count; ++i) {
                printf("  Match at address: 0x%lx\n", matches[i]);
            }
#endif
            for (size_t i = 0; i < match_count; ++i) {
                /* Apply the patch at (match address + patch_offset) */
                uintptr_t target_addr = matches[i] + entry->patch_offset;
                int ret = patch_bytes(target_addr, entry->patch_bytes,
                                      entry->patch_length);
#ifdef DEBUG
                if (ret == 0)
                    printf("Patched %zu byte(s) at 0x%lx\n",
                           entry->patch_length, target_addr);
                else
                    printf("Failed to patch at 0x%lx\n", target_addr);
#endif
            }
            free(matches);
        }
        free(pattern);
        free(mask);
    }
    return 0;
}

int apply_patches(const char *name_regex, int require_exec,
                  patch_entry_t *patches, size_t patch_count) {
    size_t range_count = 0;
    mem_range_t *ranges =
        get_memory_ranges(name_regex, require_exec, &range_count);
    if (!ranges) {
        fprintf(stderr, "Failed to get memory ranges\n");
        return 1;
    }
#ifdef DEBUG
    printf("Found %zu executable range(s) matching \"%s\":\n", range_count,
           name_regex);
    for (size_t i = 0; i < range_count; ++i) {
        printf("0x%lx-0x%lx %s %s\n", ranges[i].start, ranges[i].end,
               ranges[i].perms, ranges[i].pathname);
    }
#endif

    int ret = apply_patch_list(patches, patch_count, ranges, range_count);
    free(ranges);
    return ret;
}
