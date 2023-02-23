CC     = gcc
CFLAGS = -Wall -g -marm -O0

memcmp_SRC = src/memcmp/memcmp.c
memcmp_TGT = bin/memcmp

memcpy_SRC = src/memcpy/memcpy.c
memcpy_TGT = bin/memcpy

strlen_SRC = src/strlen/strlen.c
strlen_TGT = bin/strlen

strtol_SRC = src/strtol/strtol.c
strtol_TGT = bin/strtol

strtoul_SRC = src/strtoul/strtoul.c
strtoul_TGT = bin/strtoul

.PHONY: all
all: memcmp memcpy strlen strtol strtoul

memcmp: $(memcmp_SRC)
	$(CC) $(CFLAGS) -o $(memcmp_TGT) $(memcmp_SRC)

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
	rm -f $(memcmp_TGT) $(memcpy_TGT) $(strlen_TGT) $(strtol_TGT) $(strtoul_TGT)