# Setup
set pagination off
set disassembly-flavor intel
set architecture armv7
set arm fallback-mode arm

# Target
target remote localhost:3000

# Break before memcpy
tbreak *0x400690
continue

# Trace binary
morion_trace debug memcpy_model.yaml 0x4006f0