# Setup
set pagination off
set disassembly-flavor intel
set architecture armv7
set arm fallback-mode arm

# Target
target remote localhost:3000

# Adresses
set $start_address = 0x00400588
set $stop_address  = 0xb6eed5a0

# Break after calloc
tbreak *$start_address
continue

# Echo arguments
echo \n
echo strlen arg s: \n
i r r0

# Echo addresses
echo \n
echo start_address: \n
print/x $start_address
echo stop_address: \n
print/x $stop_address