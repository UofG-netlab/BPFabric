#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "bpfmap.h"

int main(int argc, char *argv[]) {
    //bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries)

    int map = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(uint32_t), sizeof(uint32_t), 20);

    // int bpf_update_elem(int map, void *key, void *value, unsigned long long flags);
    // int bpf_lookup_elem(int map, void *key, void *value);
    // int bpf_delete_elem(int map, void *key);
    // int bpf_get_next_key(int map, void *key, void *next_key);

    uint32_t key = 0xdeadbeef;
    uint32_t value = 0x11223344;
    uint32_t *item;

    if (bpf_update_elem(map, &key, &value, 0) != 0) {
        printf("error inserting element\n");
    }

    if (bpf_lookup_elem(map, &key, &item) != 0) {
        printf("error lookup up element\n");
    }

    value = 0x22334455;
    if (bpf_update_elem(map, &key, &value, 0) != 0) {
        printf("error updating table\n");
    }

    if (bpf_lookup_elem(map, &key, &item) != 0) {
        printf("error looking up updated element\n");
    }

    if (bpf_delete_elem(map, &key) != 0) {
        printf("error deleting element\n");
    }

    if (bpf_lookup_elem(map, &key, &item) == 0) {
        printf("should return an error the element was deleted\n");
    }

    if (item != NULL) {
        printf("non existing element should return null\n");
    }
}
