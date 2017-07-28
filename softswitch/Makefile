CFLAGS += -g -I../ubpf/inc -I../agent -I../includes
LDFLAGS += -L../ubpf -L../bpfmap
LDLIBS += -lpthread -lprotobuf-c -lubpf -lbpfmap

all: softswitch

softswitch: main.c ../agent/agent.o ../protocol/src/c/*.pb-c.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f *.o softswitch
