#!/usr/bin/env python

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

class LearningSwitchApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        self.mac_to_port = {}

        with open('../examples/learningswitch.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(name="learningswitch", index=0, elf=f.read()))

if __name__ == '__main__':
    LearningSwitchApplication().run()
