#include <stdlib.h>
#include <stdio.h>
#include "hashtab.h"
#include <errno.h>

struct objvalue {
    int32_t count;
    int32_t size;
    int16_t test;
};

int main(int argc, char *argv[]) {
    printf("testing hashmap\n");

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(uint32_t),
        .max_entries = 20,
        .map_flags = 0,
    };

    struct bpf_map *map = htab_map_alloc(&attr);

    if (map == NULL) {
        printf("Invalid parameters for creating the map\n");
        return EXIT_FAILURE;
    }

    printf("map created successfully\n");

    uint32_t key = 0xaabbccdd;
    uint32_t value = 0xdeadbeef;
    void *elem = NULL;

    /* Lookup for a non existing element */
    elem = htab_map_lookup_elem(map, &key);
    if (elem != NULL) {
        printf("Error: found element that shouldn't exist\n");
    }

    /* Insert a new element */
    if (htab_map_update_elem(map, &key, &value, 0) == -1) {
        printf("Error: unable to insert entry in the hastable\n");
    }

    /* Lookup for existing element */
    elem = htab_map_lookup_elem(map, &key);
    if (elem == NULL) {
        printf("Error: unable to get element previously inserted\n");
    }

    if (*(uint32_t *)elem != value) {
        printf("Error: lookup value is not the same as inserted\n");
        printf("Got %x expected %x\n", *(uint32_t *)elem, value);
    }

    /* Update the element */
    value = 0x11223344;
    if (htab_map_update_elem(map, &key, &value, 0) == -1) {
        printf("Error: unable to update entry in the hastable\n");
    }

    if (*(uint32_t *)elem != value) {
        printf("Error: lookup value is not the same as update\n");
        printf("Got %x expected %x\n", *(uint32_t *)elem, value);
    }


    /* Insert a second item */
    uint32_t key2 = 0x12345678;
    uint32_t value2 = 0xbeefbeef;
    if (htab_map_update_elem(map, &key2, &value2, 0) == -1) {
        printf("Error: unable to insert entry in the hastable\n");
    }

    /* Lookup second item was inserted */
    elem = htab_map_lookup_elem(map, &key2);
    if (elem == NULL) {
        printf("Error: unable to get element previously inserted\n");
    }

    if (*(uint32_t *)elem != value2) {
        printf("Error: lookup value is not the same as inserted\n");
        printf("Got %x expected %x\n", *(uint32_t *)elem, value2);
    }


    /* Iterate over the table */
    uint32_t next_key = 0;
    int count = 0;
    for (int ret = htab_map_get_next_key(map, &next_key, &next_key); ret != -1; ret = htab_map_get_next_key(map, &next_key, &next_key)) {
        printf("next key is %x\n", next_key);
        count++;
    }

    if (count != 2) {
        printf("Error: expected 2 items in the hashtable got %d\n", count);
    }

    // check we can start iterating from a known key
    printf("current key is %x\n", key);
    htab_map_get_next_key(map, &key, &next_key);
    if (next_key != key2) {
        printf("Error: expected next key to be %x got %x\n", key2, next_key);
    }

    if (htab_map_get_next_key(map, &next_key, &next_key) != -1) {
        printf("Error: expected end of iteration\n");
    }


    /* Remove the entry */
    if (htab_map_delete_elem(map, &key) != 0) {
        printf("Error: unable to remove the entry\n");
    }

    /* Lookup to see if the element was properly removed */
    elem = htab_map_lookup_elem(map, &key);
    if (elem != NULL) {
        printf("Error: found element that shouldn't exist\n");
    }

    /* Remove an already removed entry */
    if (htab_map_delete_elem(map, &key) != -1) {
        printf("Error: managed to removed an already removed entry\n");
    }


    /* test with a map storing objects */
    union bpf_attr objattr = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(uint32_t),
        .value_size = sizeof(struct objvalue),
        .max_entries = 20,
        .map_flags = 0,
    };

    struct bpf_map *objmap = htab_map_alloc(&objattr);

    if (map == NULL) {
        printf("Invalid parameters for creating the map\n");
        return EXIT_FAILURE;
    }

    uint32_t objkey = 0x11223344;
    struct objvalue objval = {
        .count = 0,
        .size = 0,
        .test = 0,
    };

    if (htab_map_update_elem(objmap, &objkey, &objval, 0) == -1) {
        printf("Error: unable to insert entry in the hastable\n");
    }

    elem = htab_map_lookup_elem(objmap, &objkey);
    if (elem == NULL) {
        printf("Error: unable to find object in map\n");
    }

    if (((struct objvalue *)elem)->count != 0) {
        printf("Error: expected count to be 0\n");
    }

    ((struct objvalue *)elem)->count++;

    elem = htab_map_lookup_elem(objmap, &objkey);

    if (((struct objvalue *)elem)->count != 1) {
        printf("Error: expected count to be 0, got %d\n", ((struct objvalue *)elem)->count);
    }

    return EXIT_SUCCESS;
}
