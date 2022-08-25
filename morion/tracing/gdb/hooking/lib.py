#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from keystone                 import *
from morion.log               import Logger
from morion.tracing.gdb.trace import GdbHelper
from typing                   import List, Tuple


class base_hook:
    """
    Base class for simulations functions.
    """

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, logger: Logger = Logger()) -> None:
        self._name = name
        self._entry_addr = entry_addr
        self._leave_addr = leave_addr
        self._target_addr = target_addr
        self._logger = logger
        self.synopsis = "base_hook"
        return

    def _arm_assemble(self, code_addr: int, code_lines: List[str], is_thumb: bool, comment: str = None) -> List[Tuple[int, bytes, str, str]]:
        inst_trace = []
        # Initialize Keystone assembler
        arch  = KS_ARCH_ARM
        mode  = KS_MODE_THUMB if is_thumb else KS_MODE_ARM
        mode += KS_MODE_BIG_ENDIAN if GdbHelper.get_byteorder() == "big" else KS_MODE_LITTLE_ENDIAN
        ks = Ks(arch, mode)
        # Assemble code
        for code_line in code_lines:
            encoding, _ = ks.asm(code_line, as_bytes=True)
            inst_trace.append((code_addr, encoding, code_line, comment))
            code_addr += len(encoding)
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
                # Inject branch to Thumb state stub code
                pc = GdbHelper.get_register_value("pc")
                pc_rel_target = f"#{hex(self._target_addr - pc + 1):s}"
                code = [
                    f"blx {pc_rel_target:s}"
                ]
                is_thumb = GdbHelper.get_thumb_state()
                return self._arm_assemble(pc, code, is_thumb, f"{self._name:s} (on_entry)")
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
                # Inject Thumb state stub code
                code = [
                    "bx lr"
                ]
                return self._arm_assemble(self._target_addr, code, True, f"{self._name:s} (on_leave)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as exc:
            symbex.logger.error(f"{self._name:s} (on_leave) failed: {str(e):s}")
        return []


class generic_hook(base_hook):
    """
    Base class for simulations functions.
    """

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, logger)
        self.synopsis = "generic_hook"
        return
