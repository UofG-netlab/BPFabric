#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ebpf_switch.h"

struct tcpflowtuple
{
    uint32_t src;
    uint32_t dst;
    uint16_t srcport;
    uint16_t dstport;
};

struct tstamp
{
    uint32_t sec;
    uint32_t nsec;
};

struct tcplatency
{
    struct tstamp syn;
    struct tstamp synack;
    struct tstamp ack;
};

struct bpf_map_def SEC("maps") latency = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct tcpflowtuple), // key is SRC:DST:SRCPORT:DSTPORT tuple
    .value_size = sizeof(struct tcplatency), // key is sec:nsec
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{
    // Check if the ethernet frame contains an ipv4 payload
    if (pkt->eth.h_proto == 0x0008)
    {
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);

        // Check if the ip packet contains a TCP payload
        if (ipv4->ip_p == 6)
        {
            struct tcphdr *tcp = (struct tcphdr *)(((uint32_t *)ipv4) + ipv4->ip_hl);

            //
            if ((tcp->th_flags & (TH_ACK | TH_SYN)) == TH_SYN)
            {
                // TCP SYN
                struct tcpflowtuple tuple = {
                    .src = ipv4->ip_src.s_addr,
                    .dst = ipv4->ip_dst.s_addr,
                    .srcport = tcp->th_sport,
                    .dstport = tcp->th_dport};

                struct tcplatency lat = {
                    .syn = {.sec = pkt->metadata.sec, .nsec = pkt->metadata.nsec},
                    .synack = 0,
                    .ack = 0};

                bpf_map_update_elem(&latency, &tuple, &lat, 0);
            }
            else if ((tcp->th_flags & (TH_ACK | TH_SYN)) == (TH_SYN | TH_ACK))
            {
                // TCP SYN|ACK
                struct tcpflowtuple tuple = {
                    .dst = ipv4->ip_src.s_addr,
                    .src = ipv4->ip_dst.s_addr,
                    .dstport = tcp->th_sport,
                    .srcport = tcp->th_dport};
                struct tcplatency *lat;

                if (bpf_map_lookup_elem(&latency, &tuple, &lat) != -1)
                {
                    lat->synack.sec = pkt->metadata.sec;
                    lat->synack.nsec = pkt->metadata.nsec;
                }
            }
            else if ((tcp->th_flags & TH_ACK) == TH_ACK)
            {
                // TCP ACK
                struct tcpflowtuple tuple = {
                    .src = ipv4->ip_src.s_addr,
                    .dst = ipv4->ip_dst.s_addr,
                    .srcport = tcp->th_sport,
                    .dstport = tcp->th_dport};
                struct tcplatency *lat;

                if (bpf_map_lookup_elem(&latency, &tuple, &lat) != -1)
                {
                    lat->ack.sec = pkt->metadata.sec;
                    lat->ack.nsec = pkt->metadata.nsec;

                    bpf_notify(1, ((uint8_t *)lat) - sizeof(struct tcpflowtuple) - 4, sizeof(struct tcplatency) + sizeof(struct tcpflowtuple) + 4);
                    bpf_map_delete_elem(&latency, &tuple);
                }
            }
        }
    }

    return NEXT;
}
char _license[] SEC("license") = "GPL";
