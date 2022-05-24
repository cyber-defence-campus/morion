#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from morion.log                     import Logger
from morion.tracing.gdb.hooking.lib import FunctionHook
from morion.tracing.gdb.trace       import GdbHelper
from typing                         import List, Tuple


class memcpy(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "void *memcpy(void *restrict dest, const void *restrict src, size_t n);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                dest = GdbHelper.get_register_value("r0")
                src = GdbHelper.get_register_value("r1")
                n = GdbHelper.get_register_value("r2")
                self._logger.debug(f"\tdest=0x{dest:x}")
                self._logger.debug(f"\tsrc =0x{src:x}")
                self._logger.debug(f"\tn   =0x{n:d}")
                # Inject assembly
                code = []
                for i in range(0, n):
                    src_byte = GdbHelper.get_memory_value(src+i, 1)
                    code.extend(self._arm_mov_to_reg("r0", src_byte))
                    code.extend(self._arm_mov_to_reg("r1", dest+i))
                    code.extend(["strb r0, [r1]"])
                return self._arm_assemble(code, is_entry=True, comment=f"{self._name:s} (on_entry)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return []


class printf(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "int printf(const char *restrict format, ...);"
        return


class putchar(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "int putchar(int c);"
        return
    

class strtoul(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "unsigned long strtoul(const char *restrict nptr, char **restrict endptr, int base);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # TODO: Make other classes similar to this one!
                # Log arguments
                self.nptr = GdbHelper.get_register_value("r0")
                nptr_val = GdbHelper.get_memory_string(self.nptr)
                self.endptr = GdbHelper.get_register_value("r1")
                self.base = GdbHelper.get_register_value("r2")
                self._logger.debug(f"\tnptr     = 0x{self.nptr:08x}")
                self._logger.debug(f"\t*nptr    = '{nptr_val:s}'")
                self._logger.debug(f"\tendptr   = 0x{self.endptr:08x}")
                self._logger.debug(f"\tbase     = {self.base:d}")
                # Inject assembly
                code = []
                return self._arm_assemble(code, is_entry=True, comment=f"{self._name:s} (on_entry)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # TODO: Make other classes similar to this one!
                # Log arguments
                endptr_val = GdbHelper.get_memory_string(GdbHelper.get_memory_value(self.endptr))
                ret = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\t**endptr = '{endptr_val:s}'")
                self._logger.debug(f"\tret      = {ret:d}")
                # TODO: endptr: _arm_mov_to_mem
                # Inject assembly
                code = self._arm_mov_to_reg("r0", ret)
                return self._arm_assemble(code, is_entry=False, comment=f"{self._name:s} (on_leave)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return []

    
class strlen(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "size_t strlen(const char *s);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                s = GdbHelper.get_register_value("r0")
                s_val = GdbHelper.get_memory_string(s)
                self._logger.debug(f"\ts=0x{s:x} ('{s_val:s}')")
                # Inject assembly
                code = []
                return self._arm_assemble(code, is_entry=True, comment=f"{self._name:s} (on_entry)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                length = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tret={length:d}")
                # Inject assembly
                code = self._arm_mov_to_reg("r0", length)
                return self._arm_assemble(code, is_entry=False, comment=f"{self._name:s} (on_leave)")
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return []
