#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "ebpf_switch.h"

struct countentry {
    int bytes;
    int packets;
};

struct bpf_map_def SEC("maps") trafficcount = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(struct countentry),
    .max_entries = 256,
};

uint64_t prog(void *pkt)
{
    struct metadatahdr *metadatahdr = pkt;
    struct ethhdr *eth = pkt + sizeof(struct metadatahdr);

    unsigned char *src = eth->h_source;

    struct countentry *item;
    struct countentry newitem;
    if (bpf_map_lookup_elem(&trafficcount, src, &item) == -1) { // No entry was found
        item = &newitem;

        item->bytes = 0;
        item->packets = 0;
    }

    item->packets++;
    bpf_map_update_elem(&trafficcount, src, &item, 0);

    return FLOOD;
}
char _license[] SEC("license") = "GPL";
