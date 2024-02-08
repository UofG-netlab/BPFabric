#include <linux/if_ether.h>
#include "ebpf_switch.h"

struct ipv4_lpm_key
{
    uint32_t prefixlen;
    uint32_t data;
};

struct bpf_map_def SEC("maps") lpm = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct ipv4_lpm_key),
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
    .map_flags = BPF_F_NO_PREALLOC,
};

uint64_t prog(struct packet *pkt)
{
    struct ipv4_lpm_key key = {.prefixlen = 32, .data = 3232235777};

    if (pkt->metadata.in_port == 0)
    {
        uint32_t value = 5;
        bpf_map_update_elem(&lpm, &key, &value, 0);
    }
    else
    {
        uint32_t *value;

        if (bpf_map_lookup_elem(&lpm, &key, &value) == 0)
        {
            bpf_debug(*value);
        }
    }

    return NEXT;
}
char _license[] SEC("license") = "GPL";
