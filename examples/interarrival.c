#include "ebpf_switch.h"

#define NBUCKETS 64

struct statekeeper {
    uint64_t lasttime;
    uint64_t counter;
    uint64_t overflow;
};

// Use to keep the current state
struct bpf_map_def SEC("maps") state = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct statekeeper),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") interarrival = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = NBUCKETS,
};

struct bpf_map_def SEC("maps") inports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 6, // MAC address is the key
    .value_size = sizeof(uint32_t),
    .max_entries = 256,
};

uint64_t prog(struct packet *pkt)
{
    uint32_t zero = 0;

    // Retrieve the current state
    struct statekeeper *st;
    bpf_map_lookup_elem(&state, &zero, &st);

    //
    uint64_t currenttime = ((uint64_t)pkt->metadata.sec << 32) | pkt->metadata.nsec;
    uint64_t delta = currenttime - st->lasttime;

    uint32_t idx = delta>>24; // 24 ~ 16msec | 20 ~1msec | 18 0.250 msec
    if (idx < NBUCKETS) {
        uint64_t *counter;
        bpf_map_lookup_elem(&interarrival, &idx, &counter);
        (*counter)++;
    } else {
        st->overflow++;
    }

    st->lasttime = currenttime;
    st->counter++;

    if (st->counter % 64 == 0) {
        uint64_t *first;
        bpf_map_lookup_elem(&interarrival, &zero, &first);
        bpf_notify(0, first, NBUCKETS*sizeof(uint64_t));
    }

    // Learning Switch
    uint32_t *out_port;

    // if the source is not a broadcast or multicast
    if ((pkt->eth.h_source[0] & 1) == 0) {
        // Update the port associated with the packet
        bpf_map_update_elem(&inports, pkt->eth.h_source, &pkt->metadata.in_port, 0);
    }

    // Flood of the destination is broadcast or multicast
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
