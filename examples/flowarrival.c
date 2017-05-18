#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ebpf_switch.h"

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

struct arrival_stats {
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
    if (pkt->eth.h_proto == 0x0008) {
        struct ip *ipv4 = (struct ip *)(((uint8_t *)&pkt->eth) + ETH_HLEN);

        // Check if the ip packet contains a TCP payload
        if (ipv4->ip_p == 6) {
            struct tcphdr *tcp = (struct tcphdr *)(((uint32_t *)ipv4) + ipv4->ip_hl);

            if (tcp->th_flags & (TH_SYN | TH_FIN)) {
                struct arrival_stats *astats;
                unsigned int key = 0;
                bpf_map_lookup_elem(&flowarrival, &key, &astats);

                // 
                if (tcp->th_flags & TH_SYN) {
                    astats->arrival += 1;
                }

                else if (tcp->th_flags & TH_FIN) {
                    astats->departure += 1;
                }

                else if (tcp->th_flags & TH_RST) {
                    astats->departure += 1;
                }

                if (pkt->metadata.sec - astats->lasttime > 5) {
                    bpf_notify(0, astats, sizeof(struct arrival_stats));
                    astats->lasttime = pkt->metadata.sec;
                    astats->arrival = 0;
                    astats->departure = 0;
                }
            }
        }
    }


    /* learning switch behaviour */
    uint32_t *out_port;
    // if the source is not a broadcast or multicast
    if ((pkt->eth.h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&inports, pkt->eth.h_source, &pkt->metadata.in_port, 0);
    }

    // Flood if the destination is broadcast or multicast
    if (pkt->eth.h_dest[0] & 1) {
        return FLOOD;
    }

    // Lookup the output port
    if (bpf_map_lookup_elem(&inports, pkt->eth.h_dest, &out_port) == -1) {
        // If no entry was found flood
        return FLOOD;
    }

    return *out_port;
}
char _license[] SEC("license") = "GPL";
