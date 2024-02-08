#ifndef __EBPF_SWITCH_CONSTS_H
#define __EBPF_SWITCH_CONSTS_H

/** Send the packet to a specific port */
#define PORT 0x00ULL

/** Flood the packet to all other ports */
#define FLOOD (0x01ULL << 32)

/** Send the packet to the controller */
#define CONTROLLER (0x02ULL << 32)

/** Drop the packet */
#define DROP (0x03ULL << 32)

/** Send the packet to the next pipeline stage */
#define NEXT (0x04ULL << 32)

#define OPCODE_MASK (0xffffffffULL << 32)

#define VALUE_MASK 0xffffffff

#endif
