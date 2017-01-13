all:
	gcc -g -o softswitch main.c -I../ubpf/inc -I../agent -I../includes ../agent/agent.o ../protocol/src/c/*.pb-c.c ../ubpf/libubpf.a ../bpfmap/libbpfmap.a -lpthread -lprotobuf-c

clean:
	rm -f *.o softswitch
