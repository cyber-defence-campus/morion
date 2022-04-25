#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from morion.log                     import Logger
from morion.tracing.gdb.hooking.lib import FunctionHook
from morion.tracing.gdb.trace       import GdbHelper
from typing                         import List, Tuple


class strlen(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "size_t strlen(const char *s);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                s = GdbHelper.get_register_value("r0")
                s_val = GdbHelper.get_memory_string(s)
                self._logger.debug(f"\ts=0x{s:x} ('{s_val:s}')")
                return self._arm_assemble([], is_entry=True, comment=f"{self._name:s} (on_entry)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                length = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tret={length:d}")
                code = self._arm_mov_to_reg("r0", length)
                return self._arm_assemble(code, is_entry=False, comment=f"{self._name:s} (on_leave)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return []
