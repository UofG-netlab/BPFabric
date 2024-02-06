import time

from twisted.internet import reactor

from .events import set_event_handler
from .protocol import eBPFFactory
from .packets import *

class eBPFCoreApplication(object):
    def __init__(self):
        self.connections = {}
        reactor.listenTCP(9000, eBPFFactory(self))

    @set_event_handler('disconnect')
    def connection_closed(self, connection, reason):
        del self.connections[connection.dpid]

    @set_event_handler(Header.HELLO)
    def hello_request(self, connection, pkt):
        print('Connection from switch {:08X}, version {}'.format(pkt.dpid, pkt.version))

        connection.dpid = pkt.dpid
        connection.version = pkt.version
        connection.connected_at = time.time()
        self.connections[connection.dpid] = connection

        # Send HELLO back
        connection.send(Hello(version=1, dpid=0))

    def run(self):
        reactor.run()
