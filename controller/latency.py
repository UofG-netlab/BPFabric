#!/usr/bin/env python
import struct
import socket

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


out = file('latency.dat', 'w')

class SimpleSwitchApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}

        with open('../examples/latency.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        #print pkt.data.encode('hex')
        src, dst, srcport, dstport, syn_sec, syn_nsec, synack_sec, synack_nsec, ack_sec, ack_nsec = struct.unpack('<IIHHxxxxIIIIII', pkt.data)

        syn = syn_sec * 10**9 + syn_nsec
        synack = synack_sec * 10**9 + synack_nsec
        ack = ack_sec * 10**9 + ack_nsec

#        print syn_sec, syn_nsec, synack_sec, synack_nsec, ack_sec, ack_nsec
#        print int2ip(src), srcport, int2ip(dst), dstport, (ack-synack)/10**3, (synack-syn)/10**6, (ack-syn)/10**6
#        print
        out.write('{} {} {} {} {}\n'.format(srcport, dstport, (ack-synack)/10**6, (synack-syn)/10**6, (ack-syn)/10**6))


if __name__ == '__main__':
    SimpleSwitchApplication().run()
