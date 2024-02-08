import sys
sys.path.insert(1, '../protocol/src/python')

from Header_pb2 import Header
from Hello_pb2 import Hello
from Function_pb2 import FunctionAddRequest, FunctionAddReply, FunctionRemoveRequest, FunctionRemoveReply, FunctionListRequest, FunctionListReply
from Table_pb2 import TablesListRequest, TablesListReply, TableListRequest, \
    TableListReply, TableEntryGetRequest, TableEntryGetReply, \
    TableEntryInsertRequest, TableEntryInsertReply, TableEntryDeleteRequest, \
    TableEntryDeleteReply, TableDefinition
from Packet_pb2 import PacketIn, PacketOut
from Notify_pb2 import Notify
