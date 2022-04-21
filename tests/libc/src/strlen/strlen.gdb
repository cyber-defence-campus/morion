target remote :3000
tbreak *0x400554
continue
trace debug tests/libc/src/strlen/strlen.yaml 0xb6ef0a20
#quit
