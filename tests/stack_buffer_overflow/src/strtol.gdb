# Setup
set pagination off
set disassembly-flavor intel
set arm fallback-mode arm

# Target
#target remote :3000
gef-remote localhost 3000

# Break at main
tbreak *0x400454
continue

# Break before and after strcpy
tbreak *0x40048c
tbreak *0x400490
tbreak *0x400494
continue