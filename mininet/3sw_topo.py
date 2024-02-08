#!/usr/bin/env python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI

from eBPFSwitch import eBPFSwitch, eBPFHost

class ThreeSwitchTopo(Topo):
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        coreSwitch = self.addSwitch('s1', switch_path="../softswitch/softswitch")
        aggSwitch1 = self.addSwitch('s2', switch_path="../softswitch/softswitch")
        aggSwitch2 = self.addSwitch('s3', switch_path="../softswitch/softswitch")

        self.addLink(aggSwitch1, coreSwitch)
        self.addLink(aggSwitch2, coreSwitch)

        for i, sw in enumerate([aggSwitch1, aggSwitch2]):
            # Add 2 hosts per switch
            for h in range(1, 3):
                host = self.addHost(f'h_{i}_{h}',
                                    ip = f'10.0.{i}.{h}/8',
                                    mac = '00:04:00:00:00:%02x'.format(h))

                self.addLink(host, sw)

def main():
    topo = ThreeSwitchTopo()
    net = Mininet(topo = topo, host = eBPFHost, switch = eBPFSwitch, controller = None)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()
