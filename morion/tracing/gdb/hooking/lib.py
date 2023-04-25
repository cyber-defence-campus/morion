#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from keystone                 import *
from morion.log               import Logger
from morion.tracing.gdb.trace import GdbHelper
from typing                   import List, Tuple


class inst_hook:
    """
    Base class for hooking instruction sequences.
    """

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        self._name = name
        self._entry_addr = entry_addr
        self._leave_addr = leave_addr
        self._target_addr_bgn = target_addr
        self._target_addr_end = target_addr
        self._mode = mode
        self._logger = logger
        self.synopsis = "inst_hook"
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
        self._target_addr_end = code_addr
        return inst_trace

    def _arm_mov_to_reg(self, reg_name: str, value: int) -> List[str]:
        value_b = int(f"{value:08x}"[4:], base=16)
        value_t = int(f"{value:08x}"[:4], base=16)
        return [
            f"mov  {reg_name:s}, #0x{value_b:x}",
            f"movt {reg_name:s}, #0x{value_t:x}"
        ]

    def _arm_mov_to_mem(self, mem_addr: int, value: int) -> List[str]:
        code_r0 = self._arm_mov_to_reg("r0", mem_addr)
        code_r1 = self._arm_mov_to_reg("r1", value)
        return code_r0 + code_r1 + [
            f"str r1, [r0]"
        ]

    def on_entry(self, code: List[str] = []) -> List[Tuple[int, bytes, str, str]]:
        """On entry hook during concrete execution.

        At this point, the hooked function has not yet been executed concretely.
        The concrete arguments of the function are available.

        The function is expected to return a list of assembly instructions in
        the form of address, opcode, disassembly and comment tuples.

        Within this function, only registers/memory in the context of the
        concrete execution should be accessed (not from symbolic execution).
        """
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                is_thumb = GdbHelper.get_thumb_state()
                # Inject branch to stub code
                pc_rel_target = f"#{hex(self._target_addr_bgn - self._entry_addr):s}"
                ass_branch = self._arm_assemble(
                    code_addr = self._entry_addr,
                    code_lines = [f"b {pc_rel_target:s}"],
                    is_thumb = is_thumb,
                    comment = f"{self._name:s} (on=entry, mode={self._mode:s})"
                )
                # Inject stub code
                ass_code = self._arm_assemble(
                    code_addr = self._target_addr_bgn,
                    code_lines = code,
                    is_thumb = is_thumb,
                    comment = f"{self._name:s} (on=entry, mode={self._mode:s})"
                )
                return ass_branch + ass_code
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return []

    def on_leave(self, code: List[str] = []) -> List[Tuple[int, bytes, str, str]]:
        """On leave hook during concrete execution.

        At this point, the hooked function has been executed concretely. The
        concrete return value of the function is available.
            
        The function is expected to return a list of assembly instructions in
        the form of address, opcode, disassembly and comment tuples.

        Within this function, only registers/memory in the context of the
        concrete execution should be accessed (not from symbolic execution).
        """
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                is_thumb = GdbHelper.get_thumb_state()
                # Inject stub code
                ass_code = self._arm_assemble(
                    code_addr = self._target_addr_end,
                    code_lines = code,
                    is_thumb = is_thumb,
                    comment = f"{self._name:s} (on=leave, mode={self._mode:s})"
                )
                # Inject branch to caller
                pc_rel_target = f"#{hex(self._leave_addr - self._target_addr_end):s}"
                ass_branch = self._arm_assemble(
                    code_addr = self._target_addr_end,
                    code_lines = [f"b {pc_rel_target:s}"],
                    is_thumb = is_thumb,
                    comment = f"{self._name:s} (on=leave, mode={self._mode:s})"
                )
                return ass_code + ass_branch
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class func_hook(inst_hook):
    """
    Base class for hooking functions (sets return value).
    """

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        self._name = name
        self._entry_addr = entry_addr
        self._leave_addr = leave_addr
        self._target_addr_bgn = target_addr
        self._target_addr_end = target_addr
        self._mode = mode
        self._logger = logger
        self.synopsis = "func_hook"
        return
    
    def on_leave(self, code: List[str] = []) -> List[Tuple[int, bytes, str, str]]:
        """On leave hook during concrete execution.

        At this point, the hooked function has been executed concretely. The
        concrete return value of the function is available.
            
        The function is expected to return a list of assembly instructions in
        the form of address, opcode, disassembly and comment tuples.

        Within this function, only registers/memory in the context of the
        concrete execution should be accessed (not from symbolic execution).
        """
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:                
                # Move result to return registers
                r0_val = GdbHelper.get_register_value("r0")
                r1_val = GdbHelper.get_register_value("r1")
                code = []
                code.extend(self._arm_mov_to_reg("r0", r0_val))
                code.extend(self._arm_mov_to_reg("r1", r1_val))
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []