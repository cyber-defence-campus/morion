CC      = gcc
CFLAGS  = -Wall -marm -O3

cf_SRC  = src/cf.c
cf_TGT  = bin/cf

.PHONY: all
all: cf

cf: $(cf_SRC)
	$(CC) $(CFLAGS) -o $(cf_TGT) $(cf_SRC)
	strip --strip-unneeded $(cf_TGT)

.PHONY: clean
clean:
	rm -f $(cf_TGT)