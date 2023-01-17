#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from morion.log                     import Logger
from morion.tracing.gdb.hooking.lib import base_hook
from morion.tracing.gdb.trace       import GdbHelper
from typing                         import List, Tuple


class memcpy(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "void *memcpy(void *restrict dest, const void *restrict src, size_t n);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.dest = GdbHelper.get_register_value("r0")
                self.src  = GdbHelper.get_register_value("r1")
                self.n    = GdbHelper.get_register_value("r2")
                self._logger.debug(f"\tdest = 0x{self.dest:08x}")
                self._logger.debug(f"\tsrc  = 0x{self.src:08x}")
                self._logger.debug(f"\tn    = {self.n:d}")
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
                result = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tresult = 0x{result:08x}")
                # Move result to return register r0
                code = self._arm_mov_to_reg("r0", result)
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class printf(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "int printf(const char *restrict format, ...);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.format = GdbHelper.get_register_value("r0")
                self.format_ = GdbHelper.get_memory_string(self.format)
                self._logger.debug(f"\t format = 0x{self.format:08x}")
                self._logger.debug(f"\t*format = '{self.format_:s}'")
                return super().on_entry()
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                result = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", result)
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class putchar(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "int putchar(int c);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.c = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tc = 0x{self.c:02x}")
                return super().on_entry()
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                result = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", result)
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class puts(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "int puts(const char *s);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
               # Log arguments
                self.s = GdbHelper.get_register_value("r0")
                self.s_ = GdbHelper.get_memory_string(self.s)
                self._logger.debug(f"\t s  = 0x{self.s:08x}")
                self._logger.debug(f"\t*s  = '{self.s_:s}'")
                return super().on_entry()
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                result = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", result)
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class strncmp(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "int strncmp(const char *s1, const char *s2, size_t n);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.s1 = GdbHelper.get_register_value("r0")
                self.s1_ = GdbHelper.get_memory_string(self.s1)
                self.s2 = GdbHelper.get_register_value("r1")
                self.s2_ = GdbHelper.get_memory_string(self.s2)
                self.n = GdbHelper.get_register_value("r2")
                self._logger.debug(f"\t s1 = 0x{self.s1:08x}")
                self._logger.debug(f"\t*s1 = '{self.s1_:s}'")
                self._logger.debug(f"\t s2 = 0x{self.s2:08x}")
                self._logger.debug(f"\t*s2 = '{self.s2_:s}'")
                self._logger.debug(f"\t  n = {self.n:d}")
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
                result = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", result)
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


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
                self.s = GdbHelper.get_register_value("r0")
                self.s_ = GdbHelper.get_memory_string(self.s)
                self._logger.debug(f"\t s  = 0x{self.s:08x}")
                self._logger.debug(f"\t*s  = '{self.s_:s}'")
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
                self._logger.debug(f"\tresult = {length:d}")
                # Move result to return register r0
                code = self._arm_mov_to_reg("r0", length)
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class strtol(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "long strtol(const char *restrict nptr, char **restrict endptr, int base);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.nptr   = GdbHelper.get_register_value("r0")
                self.nptr_  = GdbHelper.get_memory_string(self.nptr)
                self.endptr = GdbHelper.get_register_value("r1")
                self.base   = GdbHelper.get_register_value("r2")
                self._logger.debug(f"\t nptr   = 0x{self.nptr:08x}")
                self._logger.debug(f"\t*nptr   = '{self.nptr_:s}'")
                self._logger.debug(f"\t endptr = 0x{self.endptr:08x}")
                self._logger.debug(f"\t base   = {self.base:d}")
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
                endptr_ = GdbHelper.get_memory_value(self.endptr)
                endptr__ = GdbHelper.get_memory_string(endptr_)
                result   = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\t *endptr = 0x{endptr_:08x}")
                self._logger.debug(f"\t**endptr = '{endptr__:s}'")
                self._logger.debug(f"\t  result = {result:d}")
                # Move *endptr to memory endptr
                code_endptr = self._arm_mov_to_mem(self.endptr, endptr_)
                # Move result to return register r0
                code_result  = self._arm_mov_to_reg("r0", result)
                return super().on_leave(code_endptr + code_result)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class strtoul(strtol):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "unsigned long strtoul(const char *restrict nptr, char **restrict endptr, int base);"
        return