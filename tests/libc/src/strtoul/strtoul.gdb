# Setup
set pagination off
set disassembly-flavor intel
set architecture armv7
set arm fallback-mode arm

# Target
target remote localhost:3000

# Adresses
set $start_address = 0x00400680
set $stop_address  = 0x004006e4

# Break before strtuol
tbreak *$start_address
continue

# Echo addresses
echo \n
echo start_address: \n
print/x $start_address
echo stop_address: \n
print/x $stop_address