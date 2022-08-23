# Setup
set pagination off
set disassembly-flavor intel

# Target
target remote :3000

# Break before memcpy
tbreak *0x400690
continue

# Trace binary
morion_trace debug tests/libc/src/memcpy/memcpy_model.yaml 0x4006f0