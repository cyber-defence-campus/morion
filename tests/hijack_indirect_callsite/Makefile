CC      = gcc
CFLAGS  = -Wall -marm -O3

icall_SRC = src/icall.c
icall_TGT = bin/icall

.PHONY: all
all: icall

icall: $(icall_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(icall_TGT) $(icall_SRC) -lcrypt
	strip --strip-unneeded $(icall_TGT)
	sudo chown root $(icall_TGT)
	sudo chmod u+s $(icall_TGT)

.PHONY: clean
clean:
	rm -f $(icall_TGT)