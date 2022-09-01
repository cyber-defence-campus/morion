CC      = gcc
CFLAGS  = -Wall -marm -O3

sudo_SRC = src/sudo.c
sudo_TGT = bin/sudo

.PHONY: all
all: sudo

sudo: $(sudo_SRC)
	$(CC) $(CFLAGS) -o $(sudo_TGT) $(sudo_SRC)
	strip --strip-unneeded $(sudo_TGT)
	sudo chown root $(sudo_TGT)
	sudo chmod u+s $(sudo_TGT)

.PHONY: clean
clean:
	rm -f $(sudo_TGT)