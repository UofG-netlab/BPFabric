// Example based on Brendan Gregg's code available at http://www.brendangregg.com/blog/2015-05-15/ebpf-one-small-step.html

#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") traffichist = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 24,
};

uint64_t prog(struct packet *pkt)
{
    // Packet distribution
    uint32_t index = pkt->metadata.length / 64;
    uint64_t *value;

    bpf_map_lookup_elem(&traffichist, &index, &value);
    (*value)++;

    return NEXT;
}
char _license[] SEC("license") = "GPL";
