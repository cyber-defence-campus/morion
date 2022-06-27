CC     = gcc
CFLAGS = -Wall -g -marm -O0

memcpy_SRC = src/memcpy/memcpy.c
memcpy_TGT = bin/memcpy

strlen_SRC = src/strlen/strlen.c
strlen_TGT = bin/strlen

strtol_SRC = src/strtol/strtol.c
strtol_TGT = bin/strtol

strtoul_SRC = src/strtoul/strtoul.c
strtoul_TGT = bin/strtoul

.PHONY: all
all: memcpy strlen strtol strtoul

memcpy: $(memcpy_SRC)
	$(CC) $(CFLAGS) -o $(memcpy_TGT) $(memcpy_SRC)

strlen: $(strlen_SRC)
	$(CC) $(CFLAGS) -o $(strlen_TGT) $(strlen_SRC)

strtol: $(strtol_SRC)
	$(CC) $(CFLAGS) -o $(strtol_TGT) $(strtol_SRC)

strtoul: $(strtoul_SRC)
	$(CC) $(CFLAGS) -o $(strtoul_TGT) $(strtoul_SRC)

.PHONY: clean
clean:
	rm -f $(memcpy_TGT) $(strlen_TGT) $(strtol_TGT) $(strtoul_TGT)