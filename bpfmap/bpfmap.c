#include <sys/queue.h>
#include <string.h>

#include "bpfmap.h"
#include "arraymap.h"
#include "hashtab.h"
#include "lpm_trie.h"

#define MAX_MAPS 128

struct bpf_map *bpf_maps[MAX_MAPS] = {0};

const struct bpf_map_ops bpf_map_types[] = {
    [BPF_MAP_TYPE_HASH] = {
        .map_alloc = htab_map_alloc,
        .map_free = htab_map_free,
        .map_get_next_key = htab_map_get_next_key,
        .map_lookup_elem = htab_map_lookup_elem,
        .map_update_elem = htab_map_update_elem,
        .map_delete_elem = htab_map_delete_elem,
    },
    [BPF_MAP_TYPE_ARRAY] = {
        .map_alloc = array_map_alloc,
        .map_free = array_map_free,
        .map_get_next_key = array_map_get_next_key,
        .map_lookup_elem = array_map_lookup_elem,
        .map_update_elem = array_map_update_elem,
        .map_delete_elem = array_map_delete_elem,
    },
    [BPF_MAP_TYPE_LPM_TRIE] = {
        .map_alloc = trie_alloc,
        .map_free = trie_free,
        .map_get_next_key = trie_get_next_key,
        .map_lookup_elem = trie_lookup_elem,
        .map_update_elem = trie_update_elem,
        .map_delete_elem = trie_delete_elem,
    }};

int bpf_create_map(enum bpf_map_type map_type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, uint64_t flags)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));

    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = flags;

    //
    const struct bpf_map_ops *map_type_ops = &bpf_map_types[map_type];
    struct bpf_map *map;

    map = map_type_ops->map_alloc(&attr);
    if (map == NULL)
    {
        return -1;
    }

    map->ops = map_type_ops;

    // find a free idx for this map
    int map_idx = -1;
    for (int i = 0; i < MAX_MAPS; i++)
    {
        if (bpf_maps[i] == NULL)
        {
            map_idx = i;
            bpf_maps[map_idx] = map;
            break;
        }
    }

    return map_idx;
}

void bpf_free_map(int map)
{
    struct bpf_map *m = bpf_maps[map];
    m->ops->map_free(m);
    bpf_maps[map] = NULL;
}

int bpf_update_elem(int map, void *key, void *value, unsigned long long flags)
{
    struct bpf_map *m = bpf_maps[map];
    return m->ops->map_update_elem(m, key, value, flags);
}

int bpf_lookup_elem(int map, void *key, void *value)
{
    void **v = value;
    *v = NULL;

    struct bpf_map *m = bpf_maps[map];
    *v = m->ops->map_lookup_elem(m, key);
    if (*v == NULL)
    {
        return -1;
    }

    return 0;
}

int bpf_delete_elem(int map, void *key)
{
    struct bpf_map *m = bpf_maps[map];
    return m->ops->map_delete_elem(m, key);
}

int bpf_get_next_key(int map, void *key, void *next_key)
{
    struct bpf_map *m = bpf_maps[map];
    return m->ops->map_get_next_key(m, key, next_key);
}
