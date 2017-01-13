all: build-proto-c build-proto-python

build-proto-c: *.proto
	mkdir -p src/c/
	protoc-c --c_out=src/c/ *.proto

	cd src/c/ && gcc -c *.c && ar cr protocol.a *.o

build-proto-python: *.proto
	mkdir -p src/python/
	protoc --python_out=src/python/ *.proto

clean:
	rm -rf src
