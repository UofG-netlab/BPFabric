#include <linux/if_ether.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6,
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{
    uint32_t *port;

    // If the packet src mac is unknown, tell the controller
    if (bpf_map_lookup_elem(&inports, pkt->eth.h_source, &port) == -1) {
        return CONTROLLER;
    }

    // Lookup the output port
    if (bpf_map_lookup_elem(&inports, pkt->eth.h_dest, &port) == -1) {
        // If no entry was found send to the controller
        return CONTROLLER;
    }

    return *port;
}
char _license[] SEC("license") = "GPL";
