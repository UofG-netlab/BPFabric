all: bpfmap-src ubpf-src protocol-src agent-src switch dpdkswitch-src examples-src

ubpf-src:
	cd ubpf && $(MAKE)

bpfmap-src:
	cd bpfmap && $(MAKE)

protocol-src:
	cd protocol && $(MAKE)

agent-src:
	cd agent && $(MAKE)

switch: agent-src
	cd softswitch && $(MAKE)

dpdkswitch-src: agent-src
	cd dpdkswitch && $(MAKE)

examples-src:
	cd examples && $(MAKE)

clean:
	cd bpfmap && $(MAKE) clean
	cd ubpf && $(MAKE) clean
	cd agent && $(MAKE) clean
	cd protocol && $(MAKE) clean
	cd softswitch && $(MAKE) clean
	cd examples && $(MAKE) clean
	cd dpdkswitch && $(MAKE) clean
