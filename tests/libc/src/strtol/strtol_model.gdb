# Setup
set pagination off
set disassembly-flavor intel

# Target
target remote :3000

# Break before strtol
tbreak *0x400680
continue

# Trace binary
morion_trace debug tests/libc/src/strtol/strtol_model.yaml 0x4006e4