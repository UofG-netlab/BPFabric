#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import time
import matplotlib
import threading

from matplotlib import pyplot as plt


plt.ion()

plt.title('EWMA')
plt.xlabel('time (s)')
plt.draw()
plt.show()

class QueryThread(threading.Thread):
    def __init__(self, event, connection):
        threading.Thread.__init__(self)
        self.stopped = event
        self.connection = connection

    def run(self):
        while not self.stopped.wait(5):
            self.connection.send(TableListRequest(table_name='traffichist'))


class TrafficHistApplication(eBPFCoreApplication):
    ewmaStruct = struct.Struct('QQQII')

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open('../examples/traffichist.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))

        self.queryThreadStopEvent = threading.Event()
        self.queryThread = QueryThread(self.queryThreadStopEvent, connection)
        self.queryThread.daemon = True
        self.queryThread.start()

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        plt.cla()
        plt.clf()

        num_bins = len(pkt.items) / 8
        x = range(num_bins)
        x_labels = [ '{} - {}'.format(i*64, (i+1)*64-1) for i in x ]
        data = [ struct.unpack_from('Q', pkt.items, i * pkt.entry.value_size)[0] for i in range(num_bins) ]

        plt.bar(x, data, align='center')
        plt.xticks(x, x_labels, rotation=70)

        print data
        plt.draw()
        plt.pause(0.01)

if __name__ == '__main__':
    TrafficHistApplication().run()
