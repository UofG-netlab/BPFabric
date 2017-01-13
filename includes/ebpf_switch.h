#ifndef __EBPF_SWITCH_H
#define __EBPF_SWITCH_H

#include "ebpf_consts.h"
#include "ebpf_functions.h"

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

#endif
