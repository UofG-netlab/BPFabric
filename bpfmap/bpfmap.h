#ifndef __EBPF_BPFMAP_H
#define __EBPF_BPFMAP_H

#include <stdint.h>

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY         0 /* create new element or update existing */
#define BPF_NOEXIST     1 /* create new element if it didn't exist */
#define BPF_EXIST       2 /* update existing element */

#define BPF_F_NO_PREALLOC       (1U << 0)

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
};

union bpf_attr {
    struct { /* anonymous struct used by BPF_MAP_CREATE command */
        uint32_t    map_type;    /* one of enum bpf_map_type */
        uint32_t    key_size;    /* size of key in bytes */
        uint32_t    value_size;    /* size of value in bytes */
        uint32_t    max_entries;    /* max number of entries in a map */
        uint32_t    map_flags;    /* prealloc or not */
    };

    struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
        uint32_t        map_fd;
        uint64_t    key;
        union {
            uint64_t value;
            uint64_t next_key;
        };
        uint64_t        flags;
    };
} __attribute__((aligned(8)));

struct bpf_map_ops {
    struct bpf_map *(*map_alloc)(union bpf_attr *attr);
    void (*map_release)(struct bpf_map *map);
    void (*map_free)(struct bpf_map *map);
    int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);

    void *(*map_lookup_elem)(struct bpf_map *map, void *key);
    int (*map_update_elem)(struct bpf_map *map, void *key, void *value, uint64_t flags);
    int (*map_delete_elem)(struct bpf_map *map, void *key);
};

struct bpf_map {
    // atomic_t refcnt;
    enum bpf_map_type map_type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    uint32_t pages;
    // struct user_struct *user;
    const struct bpf_map_ops *ops;
    // struct work_struct work;
    // atomic_t usercnt;
};


struct bpf_array {
    struct bpf_map map;
    uint32_t elem_size;

    union {
        char value[0] __attribute__((aligned(8)));
        void *ptrs[0] __attribute__((aligned(8)));
    };
};

int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries);
int bpf_update_elem(int map, void *key, void *value, unsigned long long flags);
int bpf_lookup_elem(int map, void *key, void *value);
int bpf_delete_elem(int map, void *key);
int bpf_get_next_key(int map, void *key, void *next_key);

#endif
