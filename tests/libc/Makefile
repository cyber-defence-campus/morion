CC     = gcc
CFLAGS = -Wall -g -marm -O0

memcpy_SRC = src/memcpy/memcpy.c
memcpy_TGT = bin/memcpy

strlen_SRC = src/strlen/strlen.c
strlen_TGT = bin/strlen

.PHONY: all
all: memcpy strlen

memcpy: $(memcpy_SRC)
	$(CC) $(CFLAGS) -o $(memcpy_TGT) $(memcpy_SRC)

strlen: $(strlen_SRC)
	$(CC) $(CFLAGS) -o $(strlen_TGT) $(strlen_SRC)

.PHONY: clean
clean:
	rm -f $(memcpy_TGT) $(strlen_TGT)