target remote :3000
tbreak *0x40059c
continue
trace debug tests/libc/src/memcpy/memcpy.yaml 0xb6ef0a20
