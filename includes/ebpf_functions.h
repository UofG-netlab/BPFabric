#ifndef __EBPF_SWITCH_FUNCTIONS_H
#define __EBPF_SWITCH_FUNCTIONS_H

static int (*bpf_map_lookup_elem)(void *map, void *key, void *value) = (void *)1;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, unsigned long long flags) = (void *)2;
static int (*bpf_map_delete_elem)(void *map, void *key) = (void *)3;
static int (*bpf_mirror)(unsigned long long out_port, void *buf, int len) = (void *)30;
static int (*bpf_notify)(int id, void *data, int len) = (void *)31;
static int (*bpf_debug)(unsigned long long arg) = (void *)32;

#endif
