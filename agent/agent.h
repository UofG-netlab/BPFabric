#ifndef AGENT_H
#define AGENT_H

typedef void (*tx_packet_fn)(void *buf, int len, uint64_t out_port, int flags);

struct agent_options
{
    uint64_t dpid;
    char *controller;
};

int agent_start(tx_packet_fn tx_fn, struct agent_options *opts);
int agent_packetin(void *pkt, size_t len);
int agent_stop(void);

uint64_t pipeline_exec(void *pkt, size_t len);

#endif
