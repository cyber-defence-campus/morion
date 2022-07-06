CC      = gcc
CFLAGS  = -Wall -marm -O3

strcpy_SRC = src/strcpy.c
strcpy_TGT = bin/strcpy

.PHONY: all
all: strcpy

strcpy: $(strcpy_SRC)
	$(CC) $(CFLAGS) -o $(strcpy_TGT) $(strcpy_SRC)
	strip --strip-unneeded $(strcpy_TGT)

strcpy_stack_canaries: $(strcpy_SRC)
	$(CC) $(CFLAGS) -fstack-protector-all -o $(strcpy_TGT) $(strcpy_SRC)
	strip --strip-unneeded $(strcpy_TGT)

.PHONY: clean
clean:
	rm -f $(strcpy_TGT)