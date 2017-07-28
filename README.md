# BPFabric - Netlab

## Description
A programmable dataplane using the eBPF instruction set.

## Dependencies
Tested and working with
  * Ubuntu 16.04.1 LTS - kernel 4.4.0-31-generic
  * clang-3.9


## Examples
### Learning Switch
#### Description
Very simple (legacy) learning switch that learn the source mac address and
associated input port. If the port is unknown the packet is flooded.

#### How-To
Run a mininet topology and install the learningswitch.o eBPF elf to the
switches.

```zsh
# Run the mininet topology with three switches and 4 hosts
cd mininet
sudo ./3sw_topo.py
```

```zsh
# Run the interactive controller
cd controller
./cli.py
--------------------------------------------------------------------------------
    eBPF Switch Controller Command Line Interface - Netlab 2016
    Simon Jouet <simon.jouet@glasgow.ac.uk> - University of Glasgow
--------------------------------------------------------------------------------


Documented commands (type help <topic>):
========================================
help

Undocumented commands:
======================
EOF  connections

(Cmd) Connection from switch 00000001, version 1
Connection from switch 00000002, version 1
Connection from switch 00000003, version 1

(Cmd) connections

      dpid    version     connected at
==========  =========  ===============
  00000001          1    1467377575.33
  00000002          1    1467377575.37
  00000003          1     1467377575.4
==========  =========  ===============

(Cmd) 1 install ../examples/learningswitch.o
(Cmd) 2 install ../examples/learningswitch.o
(Cmd) 3 install ../examples/learningswitch.o
```

Try the connectivity in Mininet between the hosts
```zsh
mininet> pingall
*** Ping: testing ping reachability
h1 -> h2 h3 h4
h2 -> h1 h3 h4
h3 -> h1 h2 h4
h4 -> h1 h2 h3
*** Results: 0% dropped (12/12 received)
```

Analyze the tables of the switches to see the ethernet addres to port mapping
```zsh
# List the BPF tables available on switch 1
(Cmd) 1 tables
(Cmd)
     name    type    key size    value size    max entries
=========  ======  ==========  ============  =============
  inports    HASH           6             4            256
=========  ======  ==========  ============  =============

# List the entries in the inports table
(Cmd) 1 table inports list
(Cmd)
           Key       Value
==============  ==========
  000400000000    00000000
  000400000003    01000000
  000400000002    01000000
  000400000001    00000000
==============  ==========
```

### Centralized Learning Switch
#### Description
A simple centralized switch that will delegate the mac address to port mapping
to the controller if the destination is unknown.

#### How-To
Run a mininet topology and run the controller responsible to reply to the
PacketIn events from the switches.

```zsh
# Start the mininet topology
cd mininet
sudo ./3sw_topo.py
```

```zsh
# Start the controller
cd controller
./simpleswitch.py
Connection from switch 00000001, version 1
Installing the eBPF ELF
Connection from switch 00000003, version 1
Installing the eBPF ELF
Connection from switch 00000002, version 1
Installing the eBPF ELF
2 333300000002 ba776cdc9a6b 0x86dd
1 333300000002 ba776cdc9a6b 0x86dd
0 333300000002 ba776cdc9a6b 0x86dd
1 333300000002 000400000000 0x86dd
Inserting entry in switch 2  000400000000 1
[...]
```

## Building BPFabric for OpenWRT routers

More on the wiki at https://github.com/UofG-netlab/BPFabric/wiki/OpenWRT

## Issues
  * Error while compiling the examples `/usr/include/linux/types.h:4:10: fatal error: 'asm/types.h' file not found`
    * `sudo ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm`
    * `sudo apt-get install g++-multilib`

## Debugging
### Disassembling eBPF
```zsh
objcopy -I elf64-little -O binary --only-section=.text program.o program.bin
ubpf/bin/ubpf-disassembler program.bin program.asm
cat program.asm
```

## Authors
  * Simon Jouet (simon.jouet@glasgow.ac.uk)
  * Dimitrios Pezaros (dimitrios.pezaros@glasgow.ac.uk)

## Acknowledgements
  * EPSRC EP/L026015/1: A Situtation-Aware Information Infrastructure
