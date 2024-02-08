#ifndef __EBPF_LPM_TRIE_H
#define __EBPF_LPM_TRIE_H

#include "bpfmap.h"
#include <stdint.h>

struct bpf_map *trie_alloc(union bpf_attr *attr);
void *trie_lookup_elem(struct bpf_map *map, void *key);
int trie_update_elem(struct bpf_map *map, void *key, void *value, uint64_t map_flags);
int trie_delete_elem(struct bpf_map *map, void *key);
void trie_free(struct bpf_map *map);
int trie_get_next_key(struct bpf_map *map, void *key, void *next_key);

struct bpf_lpm_trie_key
{
    uint32_t prefixlen; /* up to 32 for AF_INET, 128 for AF_INET6 */
    uint8_t data[0];    /* Arbitrary size */
};

#endif
