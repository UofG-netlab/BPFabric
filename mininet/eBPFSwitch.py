from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.util import errRun
import subprocess

from time import sleep

class eBPFHost(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)
        self.setDefaultRoute('dev eth0') #Is that really the best way to do it?

        return r

class eBPFSwitch(Switch):
    dpid = 1

    def __init__(self, name, switch_path=None, dpid=None, **kwargs):
        Switch.__init__(self, name, **kwargs)

        if not switch_path:
            raise ValueError("switch_path must be defined")

        self.switch_path = switch_path

        if dpid:
            self.dpid = dpid
            eBPFSwitch.dpid = max(eBPFSwitch.dpid, dpid)
        else:
            self.dpid = eBPFSwitch.dpid
            eBPFSwitch.dpid += 1

    @classmethod
    def setup(cls):
        pass

    def start(self, controllers):
        print "Starting eBPF switch", self.name

        args = [self.switch_path]

        args.extend(['--dpid', str(self.dpid)])

        for port, intf in self.intfs.items():
            if not intf.IP():
                args.append(intf.name)

        print ' '.join(args) + ' &'

        self.proc = subprocess.Popen(args)

    def stop(self):
        print 'stopping'
        self.proc.kill()
