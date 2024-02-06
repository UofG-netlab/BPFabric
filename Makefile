TARGETS:=switch dpdkswitch-src examples-src

all: $(TARGETS)

bpfmap-src:
	cd bpfmap && $(MAKE)

protocol-src:
	cd protocol && $(MAKE)

ubpf-src: bpfmap-src
	cd ubpf && $(MAKE)

agent-src: protocol-src bpfmap-src ubpf-src
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
