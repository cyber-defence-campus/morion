target remote :3000
tbreak *0x400588
continue
trace debug tests/libc/src/strtoul/strtoul.yaml 0xb6ef0a20