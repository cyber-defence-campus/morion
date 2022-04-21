#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from keystone                 import *
from morion.log               import Logger
from morion.tracing.gdb.trace import GdbHelper
from typing                   import List, Tuple


class SimulationFunction:
    """
    Base class for simulations functions.
    """

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        self.name = name
        self.entry_addr = entry_addr
        self.leave_addr = leave_addr
        self.logger = logger
        return

    def _arm_assemble(self, code_lines: List[str], is_entry: bool, comment: str = None) -> List[Tuple[int, bytes, str, str]]:
        inst_trace = []
        # Configure architecture and mode
        arch  = KS_ARCH_ARM
        mode  = KS_MODE_THUMB if GdbHelper.get_thumb_state() else KS_MODE_ARM
        mode += KS_MODE_BIG_ENDIAN if GdbHelper.get_byteorder() == "big" else KS_MODE_LITTLE_ENDIAN
        # Initialize Keystone assembler
        ks = Ks(arch, mode)
        # Assemble code
        addr = 0x1000
        pc = GdbHelper.get_register_value("pc")
        if is_entry:
            code_line = f"mov pc, 0x{addr:x}"
            encoding, _ = ks.asm(code_line, as_bytes=True)
            inst_trace.append((pc, encoding, code_line, comment))
        else:
            code_lines.extend(self._arm_mov_to_reg("r2", pc))
            code_lines.extend([f"mov pc, r2"])
        for code_line in code_lines:
            encoding, _ = ks.asm(code_line, as_bytes=True)
            inst_trace.append((addr, encoding, code_line, comment))
            addr += len(encoding)
        return inst_trace

    def _arm_mov_to_reg(self, reg_name: str, value: int) -> List[str]:
        value_b = int(f"{value:08x}"[4:], base=16)
        value_t = int(f"{value:08x}"[:4], base=16)
        return [
            f"mov  {reg_name:s}, #0x{value_b:x}",
            f"movt {reg_name:s}, #0x{value_t:x}"
        ]

##    def on_concex_entry(self, symbex: "SymbolicExecutor") -> List[Tuple[int, bytes, str]]:
##        """On entry hook during the concrete execution phase (1).
##
##        At this point, the hooked function has not yet been executed concretely.
##        The concrete arguments of the function are available.
##
##        The function is expected to return a list of assembly instructions in
##        the form of address, opcode, comment tuples.
##
##        Within this function, only registers/memory in the context of the
##        concrete execution should be accessed (not from symbolic execution).
##        """
##        try:
##            arch = SymHelper.get_architecture()
##            if arch in ["armv6", "armv7"]:
##                code = [
##                    # Add assembly instructions here
##                ]
##                return self._arm_assemble(code, is_entry=True, comment=f"{self.name:s}@on_concex_entry")
##            else:
##                raise Exception(f"Architecture '{arch:s}' not supported.")
##        except Exception as exc:
##            symbex.logger.error(f"{self.name:s}@on_concex_entry failed: {exc}")
##        return []

##    def on_concex_leave(self, symbex: "SymbolicExecutor") -> List[Tuple[int, bytes, str]]:
##        """On leave hook during the concrete execution phase (1).
##
##        At this point, the hooked function has been executed concretely. The
##        concrete return value of the function is available.
##            
##        The function is expected to return a list of assembly instructions in
##        the form of address, opcode, comment tuples.
##
##        Within this function, only registers/memory in the context of the
##        concrete execution should be accessed (not from symbolic execution).
##        """
##        try:
##            arch = SymHelper.get_architecture()
##            if arch in ["armv6", "armv7"]:
##                code = [
##                    # Add assembly instructions here
##                ]
##                return self._arm_assemble(code, is_entry=False, comment=f"{self.name:s}@on_concex_leave")
##            else:
##                raise Exception(f"Architecture '{arch:s}' not supported.")
##        except Exception as exc:
##            symbex.logger.error(f"{self.name:s}@on_concex_leave failed: {exc}")
##        return []

    

    
