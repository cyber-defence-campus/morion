#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from keystone                 import *
from morion.log               import Logger
from morion.tracing.gdb.trace import GdbHelper
from typing                   import List, Tuple


class FunctionHook:
    """
    Base class for simulations functions.
    """

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        self._name = name
        self._entry_addr = entry_addr
        self._leave_addr = leave_addr
        self._logger = logger
        self.synopsis = ""
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
        pc = GdbHelper.get_register_value("pc")
        if is_entry:
            self._hook_addr = 0x1000
            code_line = f"mov pc, 0x{self._hook_addr:x}"
            encoding, _ = ks.asm(code_line, as_bytes=True)
            inst_trace.append((pc, encoding, code_line, comment))
        else:
            code_lines.extend(self._arm_mov_to_reg("r2", pc))
            code_lines.extend([f"mov pc, r2"])
        for code_line in code_lines:
            encoding, _ = ks.asm(code_line, as_bytes=True)
            inst_trace.append((self._hook_addr, encoding, code_line, comment))
            self._hook_addr += len(encoding)
        return inst_trace

    def _arm_mov_to_reg(self, reg_name: str, value: int) -> List[str]:
        value_b = int(f"{value:08x}"[4:], base=16)
        value_t = int(f"{value:08x}"[:4], base=16)
        return [
            f"mov  {reg_name:s}, #0x{value_b:x}",
            f"movt {reg_name:s}, #0x{value_t:x}"
        ]

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        """On entry hook during concrete execution.

        At this point, the hooked function has not yet been executed concretely.
        The concrete arguments of the function are available.

        The function is expected to return a list of assembly instructions in
        the form of address, opcode, disassembly, comment tuples.

        Within this function, only registers/memory in the context of the
        concrete execution should be accessed (not from symbolic execution).
        """
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Inject assembly
                code = []
                return self._arm_assemble(code, is_entry=True, comment=f"{self._name:s} (on_entry)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            symbex.logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        """On leave hook during concrete execution.

        At this point, the hooked function has been executed concretely. The
        concrete return value of the function is available.
            
        The function is expected to return a list of assembly instructions in
        the form of address, opcode, disassembly, comment tuples.

        Within this function, only registers/memory in the context of the
        concrete execution should be accessed (not from symbolic execution).
        """
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Inject assembly
                code = []
                return self._arm_assemble(code, is_entry=False, comment=f"{self._name:s} (on_leave)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as exc:
            symbex.logger.error(f"{self._name:s} (on_leave) failed: {str(e):s}")
        return []

    

    
