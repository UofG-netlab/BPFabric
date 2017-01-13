#include <stdlib.h>
#include <stdio.h>
#include "arraymap.h"

struct ewma_stats {
    uint64_t volume;
    uint64_t packets;
    uint64_t prediction;
    uint32_t lasttime;
    uint32_t count;
};

int main() {
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(struct ewma_stats),
        .max_entries = 20,
        .map_flags = 0,
    };

    // static struct bpf_map *array_map_alloc(union bpf_attr *attr);
    struct bpf_map *array_map;
    array_map = array_map_alloc(&attr);

    if (array_map == NULL) {
        printf("Error creating the array map\n");
        return EXIT_FAILURE;
    }

    uint32_t key1 = 0;
    struct ewma_stats *stats;

    stats = array_map_lookup_elem(array_map, &key1);
    printf("%lu\n", stats->packets);

    stats->packets++;

    stats = array_map_lookup_elem(array_map, &key1);
    printf("%lu\n", stats->packets);

    uint32_t key2 = 1;
    stats = array_map_lookup_elem(array_map, &key2);
    printf("%lu\n", stats->packets);

    return EXIT_SUCCESS;
}
