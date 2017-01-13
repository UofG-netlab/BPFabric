#!/usr/bin/env python
import struct

from core import eBPFCoreApplication, set_event_handler
from core.packets import *

import time
import collections
import matplotlib
# matplotlib.use('TkAgg')

from matplotlib import pyplot as plt

mng = plt.get_current_fig_manager()
mng.window.attributes('-fullscreen', True)
plt.ion()

PLOT_SAMPLES = 100
PORT_COUNT = 8

class PortData(object):
    def __init__(self, idx):
        self.idx = idx
        self.volume = [0]*PLOT_SAMPLES
        self.prediction = [0]*PLOT_SAMPLES
        self.time = [0]*PLOT_SAMPLES

        #
        plt.subplot(PORT_COUNT/2, 2, self.idx+1) # need to add 1 as 0 in matplotlib is reserved
        self.volume_line,     = plt.plot(self.time, self.volume)
        self.prediction_line, = plt.plot(self.time, self.prediction)

    def add_points(self, time, volume, prediction):
        self.time.pop(0)
        self.volume.pop(0)
        self.prediction.pop(0)

        self.time.append(time)
        self.volume.append(volume)
        self.prediction.append(prediction)

        ymax = max(max(self.volume), max(self.prediction))
        xmin = min(self.time)
        xmax = max(self.time)

        self.volume_line.set_xdata(self.time)
        self.volume_line.set_ydata(self.volume)

        self.prediction_line.set_xdata(self.time)
        self.prediction_line.set_ydata(self.prediction)

        plt.subplot(PORT_COUNT/2, 2, self.idx+1)
        plt.ylim([0, ymax])
        plt.xlim([xmin, xmax])


ports_data = [ PortData(i) for i in range(PORT_COUNT) ]
plt.tight_layout()

plt.title('EWMA')
plt.xlabel('time (s)')
plt.draw()
plt.show()

class EWMAApplication(eBPFCoreApplication):
    ewmaStruct = struct.Struct('QQQII')

    @set_event_handler(Header.HELLO)
    def hello(self, connection, pkt):
        with open('../examples/ewma.o', 'rb') as f:
            print("Installing the eBPF ELF")
            connection.send(InstallRequest(elf=f.read()))
            self.start_time = time.time()

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):

        print pkt.data.encode('hex')
        volume, packets, prediction, lasttime, count = EWMAApplication.ewmaStruct.unpack(pkt.data)
        print '[{}] [{}] volume: {} prediction: {} packets: {}'.format(connection.dpid, pkt.id, volume, prediction, packets)

        port_data = ports_data[pkt.id]
        port_data.add_points(time.time() - self.start_time, volume, prediction)

        plt.draw()
        plt.pause(0.01)

if __name__ == '__main__':
    EWMAApplication().run()
