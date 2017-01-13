#ifndef __EBPF_ARRAYMAP_H
#define __EBPF_ARRAYMAP_H

#include "bpfmap.h"

struct bpf_map *array_map_alloc(union bpf_attr *attr);
void array_map_free(struct bpf_map *map);
void *array_map_lookup_elem(struct bpf_map *map, void *key);
int array_map_get_next_key(struct bpf_map *map, void *key, void *next_key);
int array_map_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int array_map_delete_elem(struct bpf_map *map, void *key);

#endif
