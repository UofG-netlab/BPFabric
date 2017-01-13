#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import time
import matplotlib
import threading

from matplotlib import pyplot as plt
import numpy as np

plt.ion()

plt.title('EWMA')
plt.xlabel('time (s)')
plt.draw()
plt.show()


class InterArrivalApplication(eBPFCoreApplication):
    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open('../examples/interarrival.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        print pkt.data.encode('hex')

        num_bins = len(pkt.data) / 8
        x = range(num_bins)
        x_labels = [ '{} - {}'.format((i*2**24)/1000, ((i+1)*2**24-1)/1000) for i in x ]

        data = [ struct.unpack_from('Q', pkt.data, i)[0] for i in range(0, len(pkt.data), 8) ]

        plt.cla()
        plt.clf()

        plt.bar(x, data, align='center')
        plt.xticks(x, x_labels, rotation=70)

        plt.draw()
        plt.pause(0.01)
if __name__ == '__main__':
    InterArrivalApplication().run()
