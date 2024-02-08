#ifndef __EBPF_SWITCH_PACKET_H
#define __EBPF_SWITCH_PACKET_H

#include <linux/if_ether.h>
#include <stdint.h>

struct metadatahdr
{ // limited to the size available between the TPACKET_V2 header and the tp_mac payload
    uint32_t in_port;
    uint32_t sec;
    uint32_t nsec;
    uint16_t length;
} __attribute__((packed));

struct packet
{
    struct metadatahdr metadata;
    struct ethhdr eth;
};

#endif
