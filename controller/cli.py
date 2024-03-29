#!/usr/bin/env python
import cmd
import os
import struct

from threading import Thread
from twisted.internet import reactor

from core import eBPFCoreApplication, set_event_handler, FLOOD
from core.packets import *

# The intro message to show at the top when running the program
banner = "-" * 80 + """
    eBPF Switch Controller Command Line Interface - Netlab 2024
    Simon Jouet <simon.jouet@gmail.com> - University of Glasgow
""" + '-' * 80 + '\n'

def tabulate(rows, headers=None):
    if not rows or len(rows) == 0:
        print('<Empty Table>')
        return

    # Find the largest possible value for each column
    columns_width = [ max([ len(str(row[i])) for row in rows ]) for i in range(len(rows[0])) ]

    # If there are headers check if headers is larger than content
    if headers:
        columns_width = [ max(columns_width[i], len(header)) for i, header in enumerate(headers) ]

    # Add two extra spaces to columns_width for prettiness
    columns_width = [ w+2 for w in columns_width ]

    # Generate the row format string and delimiter string
    row_format = '  '.join(['{{:>{}}}'.format(w) for w in columns_width ])
    row_delim  = [ '='*w for w in columns_width ]

    # Print the headers if necessary
    print('')
    if headers:
        print(row_format.format(*headers))

    # Print the rows
    print(row_format.format(*row_delim))
    for row in rows:
        print(row_format.format(*row))
    print(row_format.format(*row_delim))

class SwitchTableCli(cmd.Cmd):
    def __init__(self, connection, function_id, table_name):
        cmd.Cmd.__init__(self)
        self.connection = connection
        self.function_id = function_id
        self.table_name = table_name

    def do_list(self, line):
        self.connection.send(TableListRequest(index=self.function_id, table_name=self.table_name))

    def do_get(self, line):
        self.connection.send(TableEntryGetRequest(index=self.function_id, table_name=self.table_name, key=bytes.fromhex(line)))

    def do_update(self, line):
        args = line.split()
        if len(args) != 2:
            print("update <hex:key> <hex:value>")
            return

        self.connection.send(TableEntryInsertRequest(index=self.function_id, table_name=self.table_name, key=bytes.fromhex(args[0]), value=bytes.fromhex(args[1])))

    def do_delete(self, line):
        self.connection.send(TableEntryDeleteRequest(index=self.function_id, table_name=self.table_name, key=bytes.fromhex(line)))

    def emptyline(self):
         self.do_help(None)

class SwitchTablesCli(cmd.Cmd):
    def __init__(self, connection, function_id: int):
        cmd.Cmd.__init__(self)
        self.connection = connection
        self.function_id = function_id

    def do_list(self, line):
        self.connection.send(TablesListRequest(index=self.function_id))

    def default(self, line: str) -> None:
        args = line.split(maxsplit=1)

        if len(args) == 0:
            cmd.Cmd.default(self, line)
        else:
            try:
                SwitchTableCli(self.connection, self.function_id, args[0]).onecmd(args[1] if len(args) > 1 else '')
            except ValueError:
                cmd.Cmd.default(self, line)

    def emptyline(self):
         self.do_help(None)

class SwitchCLI(cmd.Cmd):
    def __init__(self, connection):
        cmd.Cmd.__init__(self)
        self.connection = connection

    def do_list(self, line: str):
        self.connection.send(FunctionListRequest())

    def do_add(self, line: str) -> None:
        args = line.split()

        # 1 add 0 test ../examples/learningswitch.o
        if len(args) != 3:
            print("invalid")
            return
        
        index, name, path = args

        if not os.path.isfile(path):
            print('Invalid file path')
            return

        with open(path, 'rb') as f:
            elf = f.read()
            self.connection.send(FunctionAddRequest(name=name, index=int(index), elf=elf))

    def do_remove(self, line: str) -> None:
        self.connection.send(FunctionRemoveRequest(index=int(line)))

    def do_table(self, line: str) -> None:
        args = line.split(maxsplit=1)

        if len(args) == 0:
            cmd.Cmd.default(self, line)
        else:
            try:
                function_id = int(args[0], 16)

                SwitchTablesCli(self.connection, function_id).onecmd(args[1] if len(args) > 1 else '')
            except ValueError:
                cmd.Cmd.default(self, line)

    def emptyline(self):
         self.do_help(None)

class MainCLI(cmd.Cmd):
    def __init__(self, application):
        cmd.Cmd.__init__(self)
        self.application = application

    def preloop(self):
        print(banner)
        self.do_help(None)

    def default(self, line):
        args = line.split()

        if len(args) == 0:
            cmd.Cmd.default(self, line)
        else:
            try:
                dpid = int(args[0], 16)

                if dpid in self.application.connections:
                    SwitchCLI(self.application.connections[dpid]).onecmd(' '.join(args[1:]))
                else:
                    print(f'Switch with dpid {dpid} is not connected.')
            except ValueError:
                cmd.Cmd.default(self, line)

    def do_connections(self, line):
        tabulate([ ('{:08X}'.format(k), c.version, c.connected_at) for k,c in self.application.connections.items() ], headers=['dpid', 'version', 'connected at'])

    def emptyline(self):
         pass

    # def do_EOF(self, line):
    #     return True

class eBPFCLIApplication(eBPFCoreApplication):
    """
        Controller application that will start a interactive CLI.
    """
    def run(self):
        Thread(target=reactor.run, kwargs={'installSignalHandlers': 0}).start()

        try:
            MainCLI(self).cmdloop()
        except KeyboardInterrupt:
            print("\nGot keyboard interrupt. Exiting...")
        finally:
            reactor.callFromThread(reactor.stop)

    @set_event_handler(Header.TABLES_LIST_REPLY)
    def tables_list_reply(self, connection, pkt):
        tabulate([ (e.table_name, TableDefinition.TableType.Name(e.table_type), e.key_size, e.value_size, e.max_entries) for e in pkt.entries ], headers=['name', 'type', 'key size', 'value size', 'max entries'])

    @set_event_handler(Header.TABLE_LIST_REPLY)
    def table_list_reply(self, connection, pkt):
        entries = []

        if pkt.entry.table_type in [TableDefinition.HASH, TableDefinition.LPM_TRIE]:
            item_size = pkt.entry.key_size + pkt.entry.value_size
            fmt = "{}s{}s".format(pkt.entry.key_size, pkt.entry.value_size)

            for i in range(pkt.n_items):
                key, value = struct.unpack_from(fmt, pkt.items, i * item_size)
                entries.append((key.hex(), value.hex()))

        elif pkt.entry.table_type == TableDefinition.ARRAY:
            item_size = pkt.entry.value_size
            fmt = "{}s".format(pkt.entry.value_size)

            for i in range(pkt.n_items):
                value = struct.unpack_from(fmt, pkt.items, i * item_size)[0]
                entries.append((i, value.hex()))

        tabulate(entries, headers=["Key", "Value"])

    @set_event_handler(Header.TABLE_ENTRY_GET_REPLY)
    def table_entry_get_reply(self, connection, pkt):
        tabulate([(pkt.key.hex(), pkt.value.hex())], headers=["Key", "Value"])

    @set_event_handler(Header.NOTIFY)
    def notify_event(self, connection, pkt):
        print(f'\n[{connection.dpid}] Received notify event {pkt.id}, data length {pkt.data}')
        print(pkt.data.hex())

    @set_event_handler(Header.PACKET_IN)
    def packet_in(self, connection, pkt):
        print(f"\n[{connection.dpid}] Received packet in {pkt.data.hex()}")

    @set_event_handler(Header.FUNCTION_LIST_REPLY)
    def function_list_reply(self, connection, pkt):
        tabulate([ (e.index or 0, e.name, e.counter or 0) for e in pkt.entries ], headers=['index', 'name', 'counter'])

    @set_event_handler(Header.FUNCTION_ADD_REPLY)
    def function_add_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            print("Cannot add a function at this index")
        elif pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_FUNCTION:
            print("Unable to install this function")
        else:
            print("Function has been installed")

    @set_event_handler(Header.FUNCTION_REMOVE_REPLY)
    def function_remove_reply(self, connection, pkt):
        if pkt.status == FunctionAddReply.FunctionAddStatus.INVALID_STAGE:
            print("Cannot remove a function at this index")
        else:
            print("Function has been removed")

if __name__ == '__main__':
    eBPFCLIApplication().run()
