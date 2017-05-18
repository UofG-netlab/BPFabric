#include <linux/if_ether.h>
#include "ebpf_switch.h"

uint64_t prog(struct packet *pkt)
{
  if (pkt->metadata.in_port == 0) {
    return 1;
  }

  return 0;
}
char _license[] SEC("license") = "GPL";
