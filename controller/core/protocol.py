from collections import namedtuple
import struct
from twisted.internet import protocol

from .packets import *
from .events import _handlers

FLOOD      = 0xfffffffd
CONTROLLER = 0xfffffffe
DROP       = 0xffffffff

PORT = 0x00
FLOOD = 0x01 << 32
CONTROLLER = 0x02 << 32
DROP = 0x03 << 32
NEXT = 0x04 << 32

class eBPFFactory(protocol.Factory):
    def __init__(self, application):
        self.application = application

    def buildProtocol(self, addr):
        return eBPFProtocol(self, self.application)

PacketHeader = namedtuple('PacketHeader', ['type', 'length'])

class eBPFProtocol(protocol.Protocol):
    _message_type_to_object = {
        Header.HELLO: Hello,

        Header.FUNCTION_ADD_REQUEST: FunctionAddRequest,
        Header.FUNCTION_ADD_REPLY: FunctionAddReply,
        Header.FUNCTION_REMOVE_REQUEST: FunctionRemoveRequest,
        Header.FUNCTION_REMOVE_REPLY: FunctionRemoveReply,
        Header.FUNCTION_LIST_REQUEST: FunctionListRequest,
        Header.FUNCTION_LIST_REPLY: FunctionListReply,

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

    HEADER_FMT = '>HH'
    HEADER_LENGTH = struct.calcsize(HEADER_FMT)

    def __init__(self, factory, application):
        self.factory = factory
        self.application = application
        self.buffer = bytearray()
        self.header = None

    def _read_packets(self):
        """
            Generator to read the incoming packets, yield a tuple with the
            header as the first element and the object representing the packet
            as second element if the message type is known or the raw payload
            otherwise. The generator is stopped if a full packet
            (header and payload) is not available.
        """

        while (not self.header and len(self.buffer) >= eBPFProtocol.HEADER_LENGTH) or (self.header and len(self.buffer) >= self.header.length):
            if not self.header and len(self.buffer) >= eBPFProtocol.HEADER_LENGTH:
                self.header = PacketHeader(*struct.unpack(eBPFProtocol.HEADER_FMT, self.buffer[:eBPFProtocol.HEADER_LENGTH]))
                self.buffer = self.buffer[eBPFProtocol.HEADER_LENGTH:]

            if self.header and len(self.buffer) >= self.header.length:
                # read the payload of the packet
                payload = bytes(self.buffer[:self.header.length])
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
                self.header = None

    def _run_handlers(self, event, *args):
        """
            Execute all the handlers (if any) for the event type provided.
        """
        for handler in _handlers.get(event, []):
            handler(self.application, self, *args)

    def dataReceived(self, data):
        # append the newly received data to the buffer
        self.buffer.extend(data)

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
        header = struct.pack('>HH', eBPFProtocol._message_object_to_type[type(pkt)], len(payload))
        self.transport.write(header + payload)
