#!/usr/bin/env python
import struct
import socket

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

class SimpleSwitchApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}

        with open('../examples/flowarrival.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        t, arrival, departure = struct.unpack('<III', pkt.data)
        print t, arrival, departure


if __name__ == '__main__':
    SimpleSwitchApplication().run()
