#include <linux/if_ether.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt, unsigned len)
{
    uint32_t *original_port;

    // If the packet is from the IDPS ingress (port 0) drop it. There shouldn't be traffic coming from this port
    if (pkt->metadata.in_port == 0)
    {
        return DROP;
    }

    // If the packet is from the IDPS egress, rewrite the in_port and forward to the next stage
    if (pkt->metadata.in_port == 1 && bpf_map_lookup_elem(&inports, pkt->eth.h_source, &original_port) != -1)
    {
        pkt->metadata.in_port = *original_port;
        return NEXT;
    }

    // Otherwise learn the original port for this MAC address
    bpf_map_update_elem(&inports, pkt->eth.h_source, &pkt->metadata.in_port, 0);

    // Send all the traffic to the IDPS
    return PORT + 0;
}
char _license[] SEC("license") = "GPL";
