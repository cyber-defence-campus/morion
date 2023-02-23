# Setup
set pagination off
set disassembly-flavor intel
set architecture armv7
set arm fallback-mode arm

# Target
target remote localhost:3000

# Break before memcmp
tbreak *0x4006a4
continue

# Echo arguments
echo memcmp arg s1: \n
i r r0
echo memcmp arg s2: \n
i r r1
echo memcmp arg n: \n
i r r2

# Trace binary
morion_trace debug memcmp_model.yaml 0x40075c