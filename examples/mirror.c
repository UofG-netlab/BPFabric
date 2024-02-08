#include <linux/if_ether.h>
#include "ebpf_switch.h"

uint64_t prog(struct packet *pkt)
{
    if (pkt->metadata.in_port == 1)
    {
        bpf_mirror(2, pkt, 100);
    }

    return NEXT;
}
char _license[] SEC("license") = "GPL";
