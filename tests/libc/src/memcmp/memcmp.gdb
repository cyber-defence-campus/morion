# Setup
set pagination off
set disassembly-flavor intel
set architecture armv7
set arm fallback-mode arm

# Target
target remote localhost:3000

# Adresses
set $start_address = 0x004006a4
set $stop_address  = 0x0040075c

# Break before memcmp
tbreak *$start_address
continue

# Echo arguments
echo \n
echo memcmp arg s1: \n
i r r0
echo memcmp arg s2: \n
i r r1
echo memcmp arg n: \n
i r r2

# Echo addresses
echo \n
echo start_address: \n
print/x $start_address
echo stop_address: \n
print/x $stop_address