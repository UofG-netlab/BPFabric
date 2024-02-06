from mininet.node import Switch, Host
import subprocess


class eBPFHost(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        # Disable offloading
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload {} {} off".format(self.defaultIntf(), off)
            self.cmd(cmd)
        self.setDefaultRoute('dev {}'.format(self.defaultIntf())) #Is that really the best way to do it?

        return r

class eBPFSwitch(Switch):
    dpid = 1

    def __init__(self, name, switch_path='softswitch', dpid=None, **kwargs):
        Switch.__init__(self, name, **kwargs)

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
        print("Starting eBPF switch", self.name)

        args = [self.switch_path]

        args.extend(['--dpid', str(self.dpid)])

        for port, intf in self.intfs.items():
            if not intf.IP():
                args.append(intf.name)

        # print(' '.join(args) + ' &')

        self.proc = subprocess.Popen(args)

    def stop(self):
        print('stopping')
        self.proc.kill()
