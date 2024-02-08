#include "ebpf_switch.h"

#define EWMA_DELTA 5 // in seconds

struct ewma_stats
{
    uint64_t volume;
    uint64_t packets;
    uint64_t prediction;
    uint32_t lasttime;
    uint32_t count;
};

struct bpf_map_def SEC("maps") ewma = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(struct ewma_stats),
    .max_entries = 24};

uint64_t prog(struct packet *pkt)
{
    struct ewma_stats *ewma_stat;

    bpf_map_lookup_elem(&ewma, &pkt->metadata.in_port, &ewma_stat);

    ewma_stat->volume += pkt->metadata.length;
    ewma_stat->packets++;

    if (pkt->metadata.sec - ewma_stat->lasttime > EWMA_DELTA)
    {
        // could use nsec to be more accurate
        // compute the new prediction, prediction = alpha * volume + (1.0-alpha)*prediction
        ewma_stat->prediction = (ewma_stat->volume + (ewma_stat->prediction << 3) - ewma_stat->prediction) >> 3;

        bpf_notify(pkt->metadata.in_port, ewma_stat, sizeof(struct ewma_stats));

        //
        ewma_stat->lasttime = pkt->metadata.sec;
        ewma_stat->packets = 0;
        ewma_stat->volume = 0;
        ewma_stat->count++;
    }

    return NEXT + 1;
}
char _license[] SEC("license") = "GPL";
