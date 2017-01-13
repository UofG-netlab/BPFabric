#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "arraymap.h"

struct bpf_map *array_map_alloc(union bpf_attr *attr)
{
    struct bpf_array *array;
    uint64_t array_size;
    uint32_t elem_size;

    /* check sanity of attributes */
    if (attr->max_entries == 0 || attr->key_size != 4 ||
        attr->value_size == 0 || attr->map_flags) {
        errno = EINVAL;
        return NULL;
    }

    elem_size = round_up(attr->value_size, 8);

    /* allocate all map elements and zero-initialize them */
    array = calloc(attr->max_entries * elem_size, sizeof(*array));
    if (!array) {
        errno = ENOMEM;
        return NULL;
    }

    /* copy mandatory map attributes */
    array->map.map_type = attr->map_type;
    array->map.key_size = attr->key_size;
    array->map.value_size = attr->value_size;
    array->map.max_entries = attr->max_entries;
    array->elem_size = elem_size;

    return &array->map;
}

void array_map_free(struct bpf_map *map)
{
    struct bpf_array *array = container_of(map, struct bpf_array, map);

    free(array);
}

void *array_map_lookup_elem(struct bpf_map *map, void *key)
{
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint32_t index = *(uint32_t *)key;

    if (index >= array->map.max_entries)
        return NULL;

    return array->value + array->elem_size * index;
}

int array_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint32_t index = *(uint32_t *)key;
    uint32_t *next = (uint32_t *)next_key;

    if (index >= array->map.max_entries) {
        *next = 0;
        return 0;
    }

    if (index == array->map.max_entries - 1) {
        errno = ENOENT;
        return -1;
    }

    *next = index + 1;
    return 0;
}

int array_map_update_elem(struct bpf_map *map, void *key, void *value,
                 uint64_t map_flags)
{
    struct bpf_array *array = container_of(map, struct bpf_array, map);
    uint32_t index = *(uint32_t *)key;

    if (map_flags > BPF_EXIST) {
        /* unknown flags */
        errno = EINVAL;
        return -1;
    }

    if (index >= array->map.max_entries) {
        /* all elements were pre-allocated, cannot insert a new one */
        errno = E2BIG;
        return -1;
    }

    if (map_flags == BPF_NOEXIST) {
        /* all elements already exist */
        errno = EEXIST;
        return -1;
    }

    memcpy(array->value + array->elem_size * index,
           value, map->value_size);

    return 0;
}

int array_map_delete_elem(struct bpf_map *map, void *key)
{
    errno = EINVAL;
    return -1;
}
