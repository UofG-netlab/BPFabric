#!/usr/bin/env python

#
# sudo snort -c /usr/local/snort/etc/snort/snort.lua -R ./local.rules -Q -i mid-ingress:mid-egress -A alert_fast --daq afpacket --daq-batch-size 1
#

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.util import quietRun
import subprocess

from eBPFSwitch import eBPFSwitch, eBPFHost

# an eBPFSwitch that has two veth pairs automatically allocated on port 0 and 1
class MiddleboxSwitch(eBPFSwitch):
    def start(self, controllers):
        print("Starting eBPF switch", self.name)

        self.pairs = [('switch-egress', 'mid-ingress'), ('switch-ingress', 'mid-egress')]

        for (port1, port2) in self.pairs:
            quietRun(f'ip link add name {port1} type veth peer name {port2}')
            quietRun(f'ip link set dev {port1} up')
            quietRun(f'ip link set dev {port2} up')

        args = [self.switch_path]

        args.extend(['-p', '-i', '--dpid', str(self.dpid), 'switch-egress', 'switch-ingress'])

        for port, intf in self.intfs.items():
            if not intf.IP():
                args.append(intf.name)

        self.proc = subprocess.Popen(args)

    def stop(self):
        for (port1, _) in self.pairs:
            quietRun(f'ip link del {port1}')

        print('stopping')
        self.proc.kill()


class IDPSSingleSwitchTopo(Topo):
    def __init__(self, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1', switch_path="../softswitch/softswitch")

        for h in range(1, 3):
            host = self.addHost(f'h{h}',
                                ip = f"10.0.0.{h}/8",
                                mac = '00:04:00:00:00:%02x'.format(h))

            self.addLink(host, switch)

def main():
    topo = IDPSSingleSwitchTopo()
    net = Mininet(topo = topo, host = eBPFHost, switch = MiddleboxSwitch, controller = None)

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    main()
