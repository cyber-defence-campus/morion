#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from triton import ARCH, Instruction, MODE, TritonContext


function = {
    0x00400554: b"\x00\x30\xa0\xe1", # mov r3, r0
    0x00400558: b"\x08\x30\x0b\x45", # str r3, [fp, #-8]
    0x0040055c: b"\x08\x00\x1b\xe5", # ldr r0, [fp, #-8]
    0x00400560: b"\x01\xfa\xa0\xe3", # mov pc, 0x1000
    0x00001000: b"\x00\x00\xa0\xe3", # mov  r0, #0x0
    0x00001004: b"\x00\x00\x40\xe3", # movt r0, #0x0
    0x00001008: b"\x64\x25\x00\xe3", # mov  r2, #0x564
    0x0000100c: b"\x40\x20\x40\xe3", # movt r2, #0x40
    0x00001010: b"\x02\xf0\xa0\xe1", # mov pc, r2
    0x00400564: b"\x00\x30\xa0\xe1", # mov r3, r0
    0x00400568: b"\x02\x00\x53\xe3", # cmp r3, #2
    0x0040056c: b"\x01\x00\x00\x1a", # bne #0x400578
    0x00400578: b"\x00\x30\xa0\xe3", # mov r3, #0
    0x0040057c: b"\x03\x00\xa0\xe1", # mov r0, r3
    0x00400580: b"\x04\xd0\x4b\xe2", # sub sp, fp, #4
    0x00400584: b"\x00\x88\xbd\xe8", # pop {fp, pc}
}

ctx = TritonContext(ARCH.ARM32)
ctx.setMode(MODE.ALIGNED_MEMORY, True)
ctx.setThumb(False)

pc = 0x00400554
while pc in function:
    inst = Instruction(pc, function[pc])
    ctx.processing(inst)
    print(inst)
    import IPython; IPython.embed()
    pc = ctx.getConcreteRegisterValue(ctx.registers.pc)
