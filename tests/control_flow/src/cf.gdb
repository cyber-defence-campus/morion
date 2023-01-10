# Setup
set pagination off
set disassembly-flavor intel
set architecture armv7
set arm fallback-mode arm

# Target
target remote localhost:3000

# Trace function `main`
break *0x400530
continue
morion_trace debug cf.yaml 0xb6eed5a0