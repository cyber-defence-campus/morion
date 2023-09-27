#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from morion.symbex.help import SymbexHelper
from triton             import ARCH, CPUSIZE, MemoryAccess, TritonContext

ctx = TritonContext(ARCH.ARM32)

# Determine valid MemoryAccess sizes
print(f"Valid MemoryAccess Sizes:")
for i in range(1, 2049):
    try:
        MemoryAccess(0x3000, i)
        print(f"{i}")
    except:
        pass
print(f"\n")

def print_model(mem_addr, mem_size, value):
    mem_ast = ctx.getMemoryAst(MemoryAccess(mem_addr, mem_size))
    model = sorted(
        list(ctx.getModel(mem_ast == value).items()),
        key=lambda t: t[1].getVariable()
    )
    print(f"Solution for value 0x{value:x}:")
    for sym_var_id, solver_model in model:
        sym_var = ctx.getSymbolicVariable(sym_var_id)
        sym_var_size = sym_var.getBitSize() / 8
        _, _, _, sym_var_info = SymbexHelper.parse_symvar_alias(sym_var.getAlias())
        sym_var_value = solver_model.getValue()
        if sym_var_size == CPUSIZE.BYTE:
            print(f"[{sym_var_id}, {sym_var_info}] 0x{mem_addr:x}: 0x{sym_var_value:02x}")
            mem_addr += CPUSIZE.BYTE
        elif sym_var_size == CPUSIZE.WORD:
            print(f"[{sym_var_id}, {sym_var_info}] 0x{mem_addr:x}: 0x{sym_var_value:04x}")
            mem_addr += CPUSIZE.WORD
        elif sym_var_size == CPUSIZE.DWORD:
            print(f"[{sym_var_id}, {sym_var_info}] 0x{mem_addr:x}: 0x{sym_var_value:08x}")
            mem_addr += CPUSIZE.DWORD
        elif sym_var_size == CPUSIZE.QWORD:
            print(f"[{sym_var_id}, {sym_var_info}] 0x{mem_addr:x}: 0x{sym_var_value:016x}")
            mem_addr += CPUSIZE.QWORD
    print(f"\n")

# Single-Byte Symbolic Variables
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x1000, info="mem1_0"))
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x1001, info="mem1_1"))
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x1002, info="mem1_2"))
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x1003, info="mem1_3"))
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x1004, info="mem1_4"))
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x1005, info="mem1_5"))
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x1006, info="mem1_6"))
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x1007, info="mem1_7"))

# Multi-Byte Symbolic Variables
ctx.symbolizeMemory(MemoryAccess(0x1000, CPUSIZE.BYTE), SymbexHelper.create_symvar_alias(mem_addr=0x2000, info="mem2__"))

# Evaluate different models
print_model(0x1000, CPUSIZE.QWORD, 0x4041424344454647)
print_model(0x2000, CPUSIZE.QWORD, 0x4041424344454647)
print_model(0x1000, CPUSIZE.DWORD, 0x40414243)
print_model(0x2000, CPUSIZE.DWORD, 0x40414243)