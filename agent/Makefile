agent.o: agent.c
	gcc -c agent.c -I../ubpf/inc -I../protocol/src/c -I../bpfmap
	ar cr agent.a agent.o

clean:
	rm -f agent.o
