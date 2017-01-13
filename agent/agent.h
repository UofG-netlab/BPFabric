#ifndef AGENT_H
#define AGENT_H

typedef void (*tx_packet_fn)(void *buf, int len, uint64_t out_port, int flags);

struct agent_options {
    uint64_t dpid;
    char* controller;
};

int agent_start(ubpf_jit_fn *ubpf_fn, tx_packet_fn tx_fn, struct agent_options *opts);
int agent_packetin(void *pkt, int len);
int agent_stop(void);

#endif
