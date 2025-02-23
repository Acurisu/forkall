#ifndef SIGPATCH_H
#define SIGPATCH_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *pattern_str;
    int patch_offset;
    unsigned char *patch_bytes;
    size_t patch_length;
} patch_entry_t;

int apply_patches(const char *name_regex, int require_exec,
                  patch_entry_t *patches, size_t patch_count);

#endif  // SIGPATCH_H
