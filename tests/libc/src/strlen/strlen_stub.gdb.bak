# Setup
set pagination off
set disassembly-flavor intel

# Target
target remote :3000

# Break after calloc
tbreak *0x400554
continue

# Trace binary
morion_trace debug tests/libc/src/strlen/strlen_stub.yaml 0xb6ef0a20