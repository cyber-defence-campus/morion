# Setup
set pagination off
set disassembly-flavor intel

# Target
target remote :3000

# Break at __libc_start_main
tbreak __libc_start_main
continue

# Break at main
tbreak *0x4005f4
continue

# Echo argv
echo argv[0]:\n
x/s *($r1+0)
echo argv[1]:\n
x/s *($r1+4)
echo argv[2]:\n
x/s *($r1+8)
echo argv[3]:\n
x/s *($r1+12)

# Break
tbreak *0x400648
continue

# Trace binary
morion_trace debug sudo.yaml 0xb6ef0a20