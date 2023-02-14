# Setup
set pagination off
set disassembly-flavor intel
set architecture armv7
set arm fallback-mode arm

# Target
target remote localhost:3000

# Break after calloc
tbreak *0x400588
continue

# Echo s
echo s: \n
i r r0

# Trace binary
morion_trace debug strlen_model.yaml 0xb6eed5a0