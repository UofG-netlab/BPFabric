from twisted.internet import protocol

from packets import *
from events import _handlers

FLOOD      = 0xfffffffd
CONTROLLER = 0xfffffffe
DROP       = 0xffffffff

class eBPFFactory(protocol.Factory):
    def __init__(self, application):
        self.application = application

    def buildProtocol(self, addr):
        return eBPFProtocol(self, self.application)

class eBPFProtocol(protocol.Protocol):
    _message_type_to_object = {
        Header.HELLO: Hello,
        Header.INSTALL_REQUEST: InstallRequest,
        Header.INSTALL_REPLY: InstallReply,
        Header.TABLES_LIST_REQUEST: TablesListRequest,
        Header.TABLES_LIST_REPLY: TablesListReply,
        Header.TABLE_LIST_REQUEST: TableListRequest,
        Header.TABLE_LIST_REPLY: TableListReply,
        Header.TABLE_ENTRY_GET_REQUEST: TableEntryGetRequest,
        Header.TABLE_ENTRY_GET_REPLY: TableEntryGetReply,
        Header.TABLE_ENTRY_INSERT_REQUEST: TableEntryInsertRequest,
        Header.TABLE_ENTRY_INSERT_REPLY: TableEntryInsertReply,
        Header.TABLE_ENTRY_DELETE_REQUEST: TableEntryDeleteRequest,
        Header.TABLE_ENTRY_DELETE_REPLY: TableEntryDeleteReply,
        Header.PACKET_IN: PacketIn,
        Header.PACKET_OUT: PacketOut,
        Header.NOTIFY: Notify,
    }

    _message_object_to_type = { v: k for k,v in _message_type_to_object.items() }

    HEADER_LENGTH = 10

    def __init__(self, factory, application):
        self.factory = factory
        self.application = application
        self.buffer = ''
        self.header = Header()

    def _read_packets(self):
        """
            Generator to read the incoming packets, yield a tuple with the
            header as the first element and the object representing the packet
            as second element if the message type is known or the raw payload
            otherwise. The generator is stopped if a full packet
            (header and payload) is not available.
        """

        while (not self.header.IsInitialized() and len(self.buffer) >= eBPFProtocol.HEADER_LENGTH) or (self.header.IsInitialized() and len(self.buffer) >= self.header.length):
            if not self.header.IsInitialized() and len(self.buffer) >= eBPFProtocol.HEADER_LENGTH:
                self.header.ParseFromString(self.buffer[:eBPFProtocol.HEADER_LENGTH])
                self.buffer = self.buffer[eBPFProtocol.HEADER_LENGTH:]

            if self.header.IsInitialized() and len(self.buffer) >= self.header.length:
                # read the payload of the packet
                payload = self.buffer[:self.header.length]
                self.buffer = self.buffer[self.header.length:]

                # Deserialize the packet to its associated object
                cls = eBPFProtocol._message_type_to_object.get(self.header.type)
                if cls:
                    inst = cls()
                    inst.ParseFromString(payload)
                    yield (self.header, inst)
                else:
                    # No handler for
                    yield (self.header, payload)

                # Clear the header for the next packet
                self.header.Clear()

    def _run_handlers(self, event, *args):
        """
            Execute all the handlers (if any) for the event type provided.
        """
        for handler in _handlers.get(event, []):
            handler(self.application, self, *args)

    def dataReceived(self, data):
        # append the newly received data to the buffer
        self.buffer += data

        # Iterate over the packets received, call the associated handlers
        for header, packet in self._read_packets():
            self._run_handlers(header.type, packet)

    def connectionLost(self, reason):
        self._run_handlers('disconnect', reason)

    def send(self, pkt):
        """
            Serialize and send a message to a switch.
        """
        payload = pkt.SerializeToString()
        header = Header(type=eBPFProtocol._message_object_to_type[type(pkt)], length=len(payload))
        self.transport.write(header.SerializeToString() + payload)
