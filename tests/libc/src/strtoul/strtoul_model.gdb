# Setup
set pagination off
set disassembly-flavor intel
set architecture armv7
set arm fallback-mode arm

# Target
target remote localhost:3000

# Break before strtuol
tbreak *0x400680
continue

# Trace binary
morion_trace debug strtoul_model.yaml 0x4006e4