#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from morion.log                     import Logger
from morion.tracing.gdb.hooking.lib import base_hook
from morion.tracing.gdb.trace       import GdbHelper
from typing                         import List, Tuple


class strlen(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "size_t strlen(const char *s);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                s = GdbHelper.get_register_value("r0")
                s_val = GdbHelper.get_memory_string(s)
                self._logger.debug(f"\ts   = 0x{s:08x}")
                self._logger.debug(f"\t*s  = '{s_val:s}'")
                return super().on_entry()
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                length = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tret = {length:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", length)
                code.append("bx lr")
                return self._arm_assemble(self._target_addr, code, is_thumb=True, comment=f"{self._name:s} (on=leave, mode={self._mode:s})")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []
