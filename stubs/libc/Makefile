CC     = gcc
CFLAGS = -c -fno-stack-protector -fno-builtin -fPIC -fno-asynchronous-unwind-tables
SRC    = src/stubs.c

.PHONY: all clean

all: arm-t32

arm-t32:
	$(CC) $(CFLAGS) $(SRC) -o bin/arm-t32-stubs.o -mthumb
	objdump -d bin/arm-t32-stubs.o

clean:
	rm -rf bin/*.o