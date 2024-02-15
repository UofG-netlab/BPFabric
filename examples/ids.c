#include <linux/if_ether.h>
#include "ebpf_switch.h"

uint64_t prog(struct packet *pkt, unsigned len)
{
    // If the packet is from the IDS (port 0) drop it
    if (pkt->metadata.in_port == 0)
    {
        return DROP;
    }

    // Otherwise mirror all the traffic to the IDS
    bpf_mirror(0, pkt, len);

    return NEXT;
}
char _license[] SEC("license") = "GPL";
