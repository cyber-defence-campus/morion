#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import re
from   morion.help                    import Converter
from   morion.log                     import Logger
from   morion.tracing.gdb.hooking.lib import inst_hook
from   morion.tracing.gdb.trace       import GdbHelper
from   typing                         import List, Tuple


class fgets(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "char *fgets(char *restrict s, int n, FILE *restrict stream);"
        return
    
    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.s = GdbHelper.get_register_value("r0")
                self.n = Converter.uint_to_int(GdbHelper.get_register_value("r1"))
                self.stream = GdbHelper.get_register_value("r2")
                self._logger.debug(f"\t s      = 0x{self.s:08x}")
                self._logger.debug(f"\t n      = {self.n:d}")
                self._logger.debug(f"\t stream = 0x{self.stream:08x}")
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
                s = GdbHelper.get_register_value("r0")
                s_ = GdbHelper.get_memory_string(s)
                self._logger.debug(f"\t s = 0x{s:08x}")
                self._logger.debug(f"\t*s = '{s_:s}'")
                # Move s[i]
                code_cpy = []
                if len(s_) > 0:
                    for i in range(len(s_)+1):
                        mem_val = GdbHelper.get_memory_value(s+i, 1)
                        code_cpy.extend(self._arm_mov_to_mem(s+i, mem_val, 1))
                # Move result to return register r0
                code_result = self._arm_mov_to_reg("r0", s)
                return super().on_leave(code_cpy + code_result)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class free(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "void free(void *ptr);"
        return
    
    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.ptr = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tptr = 0x{self.ptr:08x}")
                return super().on_entry()
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return []
    

class malloc(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "void *malloc(size_t size);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.size = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tsize = {self.size:d}")
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
    

class memcmp(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "int memcmp(const void *s1, const void *s2, size_t n);"
        return
    
    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.s1 = GdbHelper.get_register_value("r0")
                self.s2 = GdbHelper.get_register_value("r1")
                self.n  = GdbHelper.get_register_value("r2")
                self._logger.debug(f"\ts1 = 0x{self.s1:08x}")
                self._logger.debug(f"\ts2 = 0x{self.s2:08x}")
                self._logger.debug(f"\t n = {self.n:d}")
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
                result = Converter.uint_to_int(GdbHelper.get_register_value("r0"))
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code = self._arm_mov_to_reg("r0", Converter.int_to_uint(result))
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class memcpy(inst_hook):

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
                # Move src[i] to dest[i]
                code_cpy = []
                for i in range(self.n):
                    mem_val = GdbHelper.get_memory_value(self.src+i, 1)
                    code_cpy.extend(self._arm_mov_to_mem(self.dest+i, mem_val, 1))
                # Move result to return register r0
                code_result = self._arm_mov_to_reg("r0", result)
                return super().on_leave(code_cpy + code_result)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class printf(inst_hook):

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
                result = Converter.uint_to_int(GdbHelper.get_register_value("r0"))
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", Converter.int_to_uint(result))
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class putchar(inst_hook):

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
                result = Converter.uint_to_int(GdbHelper.get_register_value("r0"))
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", Converter.int_to_uint(result))
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class puts(inst_hook):

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
                self._logger.debug(f"\t s = 0x{self.s:08x}")
                self._logger.debug(f"\t*s = '{self.s_:s}'")
                return super().on_entry()
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return []

    def on_leave(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                result = Converter.uint_to_int(GdbHelper.get_register_value("r0"))
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", Converter.int_to_uint(result))
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class sscanf(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "int sscanf(const char *restrict s, const char *restrict format, ...);"
        return

    def on_entry(self) -> List[Tuple[int, bytes, str, str]]:
        try:
            arch = GdbHelper.get_architecture()
            if arch in ["armv6", "armv7"]:
                # Log arguments
                self.s = GdbHelper.get_register_value("r0")
                self.s_ = GdbHelper.get_memory_string(self.s)
                self.format = GdbHelper.get_register_value("r1")
                self.format_ = GdbHelper.get_memory_string(self.format)
                self._logger.debug(f"\t s      = 0x{self.s:08x}")
                self._logger.debug(f"\t*s      = '{self.s_:s}'")
                self._logger.debug(f"\t format = 0x{self.format:08x}")
                self._logger.debug(f"\t*format = '{self.format_:s}'")
                # Parse conversion specifiers
                format_pattern = r"""
                (%|%([1-9][0-9]*)\$)                    # 1/2: (Numbered) argument specification
                (\*)?                                   # 3  : Assignment-suppressing character
                ([1-9][0-9]*)?                          # 4  : Maximum field width
                (m)?                                    # 5  : Assignment-allocation character
                (hh|h|ll|l|j|z|t|L)?                    # 6  : Length modifier
                (d|i|o|u|x|a|e|f|g|s|\[|c|p|n|C|S|\%)   # 7  : Conversion specifier
                """
                self.conversions = [m for m in re.finditer(format_pattern, self.format_, flags=re.VERBOSE)]
                # Store input arguments
                self.args = []
                num_args = len(self.conversions)
                # Get first two arguments from registers
                if num_args >= 1:
                    arg1 = GdbHelper.get_register_value("r2")
                    self.args.append(arg1)
                    self._logger.debug(f"\t arg1   = 0x{arg1:08x}")
                if num_args >= 2:
                    arg2 = GdbHelper.get_register_value("r3")
                    self.args.append(arg2)
                    self._logger.debug(f"\t arg2   = 0x{arg2:08x}")
                # Get remaining arguments from stack
                if num_args >= 3:
                    stack_ptr = GdbHelper.get_register_value("sp")
                    for i in range(num_args-2):
                        argi = GdbHelper.get_memory_value(stack_ptr+i*4, 4)
                        self.args.append(argi)
                        self._logger.debug(f"\t arg{i+3:d}   = 0x{argi:08x}")
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
                cnt_assign = Converter.uint_to_int(GdbHelper.get_register_value("r0"))
                self._logger.debug(f"\tresult = {cnt_assign:d}")
                
                # Helper function to determine byte-length of an argument
                def get_arg_length(
                        ass_sup_chr: str,
                        max_fld_wth: str,
                        ass_all_chr: str,
                        lth_mod: str,
                        con_spe: str
                    ) -> int:
                    length = -1

                    if ass_sup_chr == '*':
                        length = 0
                    elif lth_mod == 'hh':
                        if con_spe in ['d', 'i', 'o', 'u', 'x', 'X', 'n']:
                            length = 1
                    elif lth_mod == 'h':
                        if con_spe in ['d', 'i', 'o', 'u', 'x', 'X', 'n']:
                            length = 2
                    elif lth_mod == 'l':
                        if (ass_all_chr == 'm' or
                            con_spe in ['d', 'i', 'o', 'u', 'x', 'X', 'n'] or
                            con_spe in ['c', 's', '[']):
                            length = 4
                        elif con_spe in ['a', 'A', 'e', 'E', 'f', 'F', 'g', 'G']:
                            length = 8
                    elif lth_mod == 'll':
                        if con_spe in ['d', 'i', 'o', 'u', 'x', 'X', 'n']:
                            length = 8
                    elif lth_mod == 'j':
                        if con_spe in ['d', 'i', 'o', 'u', 'x', 'X', 'n']:
                            length = 8
                    elif lth_mod == 'z':
                        if con_spe in ['d', 'i', 'o', 'u', 'x', 'X', 'n']:
                            length = 4
                    elif lth_mod == 't':
                        if con_spe in ['d', 'i', 'o', 'u', 'x', 'X', 'n']:
                            length = 4
                    elif lth_mod == 'L':
                        if con_spe in ['a', 'A', 'e', 'E', 'f', 'F', 'g', 'G']:
                            length = 8

                    if max_fld_wth is not None:
                        length = min(length, int(max_fld_wth))
                    return length

                # Move arguments
                code_inputs = []
                for ci, conversion in enumerate(self.conversions[0:max(0, cnt_assign)]):
                    # Parse conversion
                    num_arg = conversion.group(2)        # 2: Numbered argument specification
                    ass_sup_chr = conversion.group(3)    # 3: Assignment-suppressing character
                    max_fld_wth = conversion.group(4)    # 4: Maximum field width
                    ass_all_chr = conversion.group(5)    # 5: Assignment-allocation character
                    lth_mod = conversion.group(6)        # 6: Length modifier
                    con_spe = conversion.group(7)        # 7: Conversion specifier
                    # Argument specification
                    if num_arg is None:
                        arg_ptr = self.args[ci]
                    # Numbered argument specification
                    elif num_arg <= cnt_assign:
                        arg_ptr = self.args[num_arg-1]
                    # Argument length
                    arg_len = get_arg_length(ass_sup_chr, max_fld_wth, ass_all_chr, lth_mod, con_spe)
                    # Move argument
                    if arg_len < 0:
                        arg_len = len(GdbHelper.get_memory_string(arg_ptr))+1
                    for i in range(arg_len):
                        arg_val = GdbHelper.get_memory_value(arg_ptr+i, 1)
                        code_inputs.extend(self._arm_mov_to_mem(arg_ptr+i, arg_val, 1))

                # Move result to return register r0
                code_result = self._arm_mov_to_reg("r0", Converter.int_to_uint(cnt_assign))
                return super().on_leave(code_inputs + code_result)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class strcmp(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, target_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, target_addr, mode, logger)
        self.synopsis = "int strcmp(const char *s1, const char *s2);"
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
                self._logger.debug(f"\t s1 = 0x{self.s1:08x}")
                self._logger.debug(f"\t*s1 = '{self.s1_:s}'")
                self._logger.debug(f"\t s2 = 0x{self.s2:08x}")
                self._logger.debug(f"\t*s2 = '{self.s2_:s}'")
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
                result = Converter.uint_to_int(GdbHelper.get_register_value("r0"))
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", Converter.int_to_uint(result))
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []
    

class strncmp(inst_hook):

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
                result = Converter.uint_to_int(GdbHelper.get_register_value("r0"))
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code  = self._arm_mov_to_reg("r0", Converter.int_to_uint(result))
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class strlen(inst_hook):

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
                result = GdbHelper.get_register_value("r0")
                self._logger.debug(f"\tresult = {result:d}")
                # Move result to return register r0
                code = self._arm_mov_to_reg("r0", result)
                return super().on_leave(code)
            raise Exception(f"Architecture '{arch:s}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return []


class strtol(inst_hook):

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
                self.base   = Converter.uint_to_int(GdbHelper.get_register_value("r2"))
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
                endptr_ = GdbHelper.get_memory_value(self.endptr, 4)
                endptr__ = GdbHelper.get_memory_string(endptr_)
                result   = Converter.ulong_to_long(GdbHelper.get_register_value("r0"))
                self._logger.debug(f"\t *endptr = 0x{endptr_:08x}")
                self._logger.debug(f"\t**endptr = '{endptr__:s}'")
                self._logger.debug(f"\t  result = {result:d}")
                # Move *endptr to memory endptr
                code_endptr = self._arm_mov_to_mem(self.endptr, endptr_)
                # Move result to return register r0
                code_result  = self._arm_mov_to_reg("r0", Converter.long_to_ulong(result))
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