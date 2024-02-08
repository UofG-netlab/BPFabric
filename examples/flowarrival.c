#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ebpf_switch.h"

struct arrival_stats
{
    uint32_t lasttime;
    uint32_t arrival;
    uint32_t departure;
};

struct bpf_map_def SEC("maps") flowarrival = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct arrival_stats),
    .max_entries = 1,
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

            if (tcp->th_flags & (TH_SYN | TH_FIN))
            {
                struct arrival_stats *astats;
                unsigned int key = 0;
                bpf_map_lookup_elem(&flowarrival, &key, &astats);

                //
                if (tcp->th_flags & TH_SYN)
                {
                    astats->arrival += 1;
                }

                else if (tcp->th_flags & TH_FIN)
                {
                    astats->departure += 1;
                }

                else if (tcp->th_flags & TH_RST)
                {
                    astats->departure += 1;
                }

                if (pkt->metadata.sec - astats->lasttime > 5)
                {
                    bpf_notify(0, astats, sizeof(struct arrival_stats));
                    astats->lasttime = pkt->metadata.sec;
                    astats->arrival = 0;
                    astats->departure = 0;
                }
            }
        }
    }

    return NEXT;
}
char _license[] SEC("license") = "GPL";
