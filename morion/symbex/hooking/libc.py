#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from   morion.help                 import Converter
from   morion.log                  import Logger
from   morion.symbex.tools.execute import Executor
from   morion.symbex.help          import SymbexHelper
from   morion.symbex.hooking.lib   import inst_hook
from   triton                      import ARCH, CPUSIZE, MemoryAccess, TritonContext
import re


class fgets(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "char *fgets(char *restrict s, int n, FILE *restrict stream);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                self.s = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.n = Converter.uint_to_int(ctx.getConcreteRegisterValue(ctx.registers.r1))
                self.stream = ctx.getConcreteRegisterValue(ctx.registers.r2)
                self._logger.debug(f"\t s = 0x{self.s:08x}")
                self._logger.debug(f"\t n = {self.n:d}")
                self._logger.debug(f"\t stream = 0x{self.stream:08x}")
                # TODO: Taint mode
                if self._mode == "taint":
                    self._logger.warning("Taint mode not yet implemented.")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                s = ctx.getConcreteRegisterValue(ctx.registers.r0)
                s_ = Executor.get_memory_string(ctx, s)
                self._logger.debug(f"\t s = 0x{s:08x}")
                self._logger.debug(f"\t*s = '{s_:s}'")
                # TODO: Taint mode
                if self._mode == "taint":
                    self._logger.warning("Taint mode not yet implemented.")
                # Model mode
                elif self._mode == "model":
                    cut = self.n-1 > 3
                    if len(s_) > 0:
                        for i in range(self.n-1):
                            mem = MemoryAccess(s+i, CPUSIZE.BYTE)
                            ctx.symbolizeMemory(mem, SymbexHelper.create_symvar_alias(mem_addr=s+i, info=f"MODEL:fgets@libc:s+{i:d}"))
                            if not cut or i == 0:
                                self._logger.debug(f"\t0x{s+i:08x}=$$")
                            elif i == self.n-2:
                                self._logger.debug(f"\t...")
                                self._logger.debug(f"\t0x{s+i:08x}=$$")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return


class memcmp(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "int memcmp(const void *s1, const void *s2, size_t n);"
        return
    
    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                self.s1  = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.s2  = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.n   = ctx.getConcreteRegisterValue(ctx.registers.r2)
                self._logger.debug(f"\ts1     = 0x{self.s1:08x}")
                self._logger.debug(f"\ts2     = 0x{self.s2:08x}")
                self._logger.debug(f"\t n     = {self.n:d}")
                # Taint mode
                if self._mode == "taint":
                    self._taint = False
                    if (ctx.isRegisterSymbolized(ctx.registers.r0) or
                        ctx.isRegisterSymbolized(ctx.registers.r1) or
                        ctx.isRegisterSymbolized(ctx.registers.r2)):
                        self._taint = True
                        return
                    for i in range(self.n):
                        mem_s1 = MemoryAccess(self.s1+i, CPUSIZE.BYTE)
                        mem_s2 = MemoryAccess(self.s2+i, CPUSIZE.BYTE)
                        if (ctx.isMemorySymbolized(mem_s1) or
                            ctx.isMemorySymbolized(mem_s2)):
                            self._taint = True
                            return
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return
    
    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                result = Converter.uint_to_int(ctx.getConcreteRegisterValue(ctx.registers.r0))
                self._logger.debug(f"\tresult = {result:d}")
                # Taint mode
                if self._mode == "taint":
                    if self._taint:
                        ctx.concretizeRegister(ctx.registers.r0)
                        ctx.symbolizeRegister(ctx.registers.r0, SymbexHelper.create_symvar_alias(reg_name="r0", info="TAINT:memcmp@libc"))
                        self._logger.debug(f"\tresult = [TAINTED]")
                # Model mode
                elif self._mode == "model":
                    # AST context
                    ast = ctx.getAstContext()

                    # Subtraction index 0
                    ast_s1_0  = ctx.getMemoryAst(MemoryAccess(self.s1, CPUSIZE.BYTE))
                    ast_s1_0  = ast.zx(CPUSIZE.DWORD_BIT-CPUSIZE.BYTE_BIT, ast_s1_0)
                    ast_s2_0  = ctx.getMemoryAst(MemoryAccess(self.s2, CPUSIZE.BYTE))
                    ast_s2_0  = ast.zx(CPUSIZE.DWORD_BIT-CPUSIZE.BYTE_BIT, ast_s2_0)
                    ast_sub_0 = ast.bvsub(ast_s1_0, ast_s2_0)

                    # Summation indexes [1, n-1]
                    ast_sum_n = ast.bv(0, CPUSIZE.DWORD_BIT)
                    for i in range(1, self.n):
                        # Subtraction
                        ast_s1_i = ctx.getMemoryAst(MemoryAccess(self.s1 + i, CPUSIZE.BYTE))
                        ast_s1_i = ast.zx(CPUSIZE.DWORD_BIT-CPUSIZE.BYTE_BIT, ast_s1_i)
                        ast_s2_i = ctx.getMemoryAst(MemoryAccess(self.s2 + i, CPUSIZE.BYTE))
                        ast_s2_i = ast.zx(CPUSIZE.DWORD_BIT-CPUSIZE.BYTE_BIT, ast_s2_i)
                        ast_sub_i = ast.bvsub(ast_s1_i, ast_s2_i)
                        # If-Then-Else
                        ast_eq = [ast.equal(ast.bvtrue(), ast.bvtrue())]
                        for k in range(0, i):
                            ast_s1_k = ctx.getMemoryAst(MemoryAccess(self.s1 + k, CPUSIZE.BYTE))
                            ast_s2_k = ctx.getMemoryAst(MemoryAccess(self.s2 + k, CPUSIZE.BYTE))
                            ast_eq.append(ast.equal(ast_s1_k, ast_s2_k))
                        ast_ite_i = ast.ite(
                            ast.land(ast_eq),
                            ast.bv(1, CPUSIZE.DWORD_BIT),
                            ast.bv(0, CPUSIZE.DWORD_BIT)
                        )
                        # Multiplication
                        ast_mul_i = ast.bvmul(ast_sub_i, ast_ite_i)
                        ast_sum_n = ast.bvadd(ast_sum_n, ast_mul_i)

                    # Handle n == 0
                    ast_memcmp = ast.ite(
                        ast.equal(
                            ast.bv(self.n, CPUSIZE.DWORD_BIT),
                            ast.bv(0, CPUSIZE.DWORD_BIT)
                        ),
                        ast.bv(0, CPUSIZE.DWORD_BIT),
                        # Addition indexes [0, n-1]
                        ast.bvadd(ast_sub_0, ast_sum_n)
                    )

                    # Assign symbolic result to return register
                    exp_memcmp = ctx.newSymbolicExpression(ast_memcmp)
                    ctx.assignSymbolicExpressionToRegister(exp_memcmp, ctx.registers.r0)
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return
    

class memcpy(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "void *memcpy(void *restrict dest, const void *restrict src, size_t n);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                self.dest = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.src  = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.n    = ctx.getConcreteRegisterValue(ctx.registers.r2)
                self._logger.debug(f"\tdest = 0x{self.dest:08x}")
                self._logger.debug(f"\tsrc  = 0x{self.src:08x}")
                self._logger.debug(f"\tn    = {self.n:d}")
                # Taint mode
                if self._mode == "taint":
                    self._taint_dest   = False
                    self._taint_result = False
                    if ctx.isRegisterSymbolized(ctx.registers.r0):
                        self._taint_result = True
                    if ctx.isRegisterSymbolized(ctx.registers.r1) or ctx.isRegisterSymbolized(ctx.registers.r2):
                        self._taint_dest = True
                    else:
                        for i in range(self.n):
                            mem = MemoryAccess(self.src+i, CPUSIZE.BYTE)
                            if ctx.isMemorySymbolized(mem):
                                self._taint_dest = True
                                break
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                result = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self._logger.debug(f"\tresult      = 0x{result:08x}")
                # Taint mode
                if self._mode == "taint":
                    if self._taint_dest:
                        for i in range(self.n):
                            mem_addr = self.dest+i
                            mem = MemoryAccess(mem_addr, CPUSIZE.BYTE)
                            ctx.concretizeMemory(mem)
                            ctx.symbolizeMemory(mem, SymbexHelper.create_symvar_alias(mem_addr=mem_addr, info=f"TAINT:memcpy@libc:dest+{i:d}"))
                            self._logger.debug(f"\tdest[{i:d}] = TAINT:memcpy@libc")
                    if self._taint_result:
                        ctx.concretizeRegister(ctx.registers.r0)
                        ctx.symbolizeRegister(ctx.registers.r0, SymbexHelper.create_symvar_alias(reg_name="r0", info="TAINT:memcpy@libc"))
                        self._logger.debug(f"\tresult      = [TAINTED]")
                # Model mode
                elif self._mode == "model":
                    for i in range(0, self.n):
                        sym_exp = ctx.getSymbolicMemory(self.src+i)
                        if sym_exp:
                            ctx.assignSymbolicExpressionToMemory(
                                sym_exp, MemoryAccess(self.dest+i, CPUSIZE.BYTE))
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return


class puts(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "int puts(const char *s);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                self.s = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.s_ = Executor.get_memory_string(ctx, self.s)
                self._logger.debug(f"\t s = 0x{self.s:08x}")
                self._logger.debug(f"\t*s = '{self.s_:s}'")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return


class sscanf(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "int sscanf(const char *restrict str, const char *restrict format, ...);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                self.str = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.str_ = Executor.get_memory_string(ctx, self.str)
                self.format = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.format_ = Executor.get_memory_string(ctx, self.format)
                self._logger.debug(f"\t s      = 0x{self.str:08x}")
                self._logger.debug(f"\t*s      = '{self.str_:s}'")
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
                    arg1 = ctx.getConcreteRegisterValue(ctx.registers.r2)
                    self.args.append(arg1)
                    self._logger.debug(f"\t arg1   = 0x{arg1:08x}")
                if num_args >= 2:
                    arg2 = ctx.getConcreteRegisterValue(ctx.registers.r3)
                    self.args.append(arg2)
                    self._logger.debug(f"\t arg2   = 0x{arg2:08x}")
                # Get remaining arguments from stack
                if num_args >= 3:
                    stack_ptr = ctx.getConcreteRegisterValue(ctx.registers.sp)
                    for i in range(num_args-2):
                        argi = ctx.getConcreteMemoryValue(MemoryAccess(stack_ptr+i*4, 4))
                        self.args.append(argi)
                        self._logger.debug(f"\t arg{i+3:d}   = 0x{argi:08x}")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                cnt_assign = Converter.uint_to_int(ctx.getConcreteRegisterValue(ctx.registers.r0))
                self._logger.debug(f"\tresult = {cnt_assign:d}")
                # TODO: Taint mode
                if self._mode == "taint":
                    self._logger.warning("Taint mode not yet implemented.")
                # Model mode
                elif self._mode == "model":
                    s = self.str
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
                        # Assignment suppressing
                        if ass_sup_chr == '*':
                            continue
                        # Conversion specifier s (currently no support for length modifier l)
                        if con_spe == 's' and lth_mod != 'l':
                            # Parse string
                            inp_str = Executor.get_memory_string(ctx, s)
                            m = re.search(r"([^\s]+)", inp_str)
                            if m is None or len(m.groups()) != 1:
                                self._logger.warning(f"Failed to apply conversion specifier 's' to '{inp_str:s}'")
                                continue
                            arg_str = m.group(1)
                            arg_off = m.start()
                            # Assignment allocation
                            if ass_all_chr == 'm':
                                arg_ptr = ctx.getConcreteMemoryValue(MemoryAccess(arg_ptr, CPUSIZE.DWORD))
                            # Move symbolic bytes
                            cut = len(arg_str) > 3
                            for i in range(len(arg_str)):
                                sym_exp = ctx.getSymbolicMemory(s+arg_off+i)
                                if sym_exp:
                                    ctx.assignSymbolicExpressionToMemory(
                                        sym_exp, MemoryAccess(arg_ptr+i, CPUSIZE.BYTE)
                                    )
                                    if not cut or i == 0:
                                        self._logger.debug(f"0x{arg_ptr+i:08x}=$$")
                                    elif i == len(arg_str)-1:
                                        self._logger.debug(f"\t...")
                                        self._logger.debug(f"0x{arg_ptr+i:08x}=$$")
                            s += m.end()
                        # TODO: Support other conversions
                        else:
                            self._logger.warning(f"Unsupported conversion.")
                # Model mode (V2)
                elif self._mode == "model_v2":
                    # Concrete str
                    str_ = Executor.get_memory_string(ctx, self.str)
                    # Required ASTs
                    ast = ctx.getAstContext()
                    ast_space = ast.bv(ord(" "), CPUSIZE.BYTE_BIT)
                    ast_cnt_chars = ast.bv(0, CPUSIZE.DWORD_BIT)
                    ast_cnt_ass = ast.bv(0, CPUSIZE.DWORD_BIT)
                    # Iterate conversions
                    for c, conversion in enumerate(self.conversions[0:max(0, cnt_assign)]):
                        # Parse conversion
                        num_arg = conversion.group(2)        # 2: Numbered argument specification
                        ass_sup_chr = conversion.group(3)    # 3: Assignment-suppressing character
                        max_fld_wth = conversion.group(4)    # 4: Maximum field width
                        ass_all_chr = conversion.group(5)    # 5: Assignment-allocation character
                        lth_mod = conversion.group(6)        # 6: Length modifier
                        con_spe = conversion.group(7)        # 7: Conversion specifier
                        # Argument specification
                        if num_arg is None:
                            arg_ptr = self.args[c]
                        # Numbered argument specification
                        elif num_arg <= cnt_assign:
                            arg_ptr = self.args[num_arg-1]
                        # Assignment suppressing
                        if ass_sup_chr == '*':
                            continue
                        # Conversion specifier s (currently no support for length modifier l)
                        if con_spe == 's' and lth_mod != 'l':
                            # Assignment allocation
                            if ass_all_chr == 'm':
                                arg_ptr = ctx.getConcreteMemoryValue(MemoryAccess(arg_ptr, CPUSIZE.DWORD))
                            # Store ASTs of str to an array
                            ast_str = ast.array(CPUSIZE.DWORD_BIT)
                            for i in range(len(str_)):
                                # AST of str[i]
                                ast_str_i = ctx.getMemoryAst(MemoryAccess(self.str+i, CPUSIZE.BYTE))
                                # Store AST of str[i] into an array
                                ast_str = ast.store(ast_str, i, ast_str_i)
                            self._logger.debug(f"\tConvSpec {c:d}: str stored to array")
                            # Copy nonspace characters of the c-th conversion specifier to the c-th argument
                            ast_cnt_spaces = ast.bv(0, CPUSIZE.DWORD_BIT)
                            ast_cnt_nonspaces = ast.bv(0, CPUSIZE.DWORD_BIT)
                            for i in range(len(str_)):
                                # AST of str[i]
                                ast_str_i = ctx.getMemoryAst(MemoryAccess(self.str+i, CPUSIZE.BYTE))
                                # Count space characters of the c-th conversion specifier
                                ast_cnt_spaces = ast.bvadd(
                                    ast_cnt_spaces,
                                    ast.ite(
                                        # Ensure a subsequent series of space characters
                                        ast.land([
                                            i == ast_cnt_chars + ast_cnt_spaces,
                                            ast_str_i == ast_space
                                        ]),
                                        ast.bv(1, CPUSIZE.DWORD_BIT),
                                        ast.bv(0, CPUSIZE.DWORD_BIT)
                                    )
                                )
                                # Count nonspace characters of the c-th conversion specifier
                                ast_cnt_nonspaces = ast.bvadd(
                                    ast_cnt_nonspaces,
                                    ast.ite(
                                        # Ensure a subsequent series of nonspace characters
                                        ast.land([
                                            i == ast_cnt_chars + ast_cnt_spaces + ast_cnt_nonspaces,
                                            ast_str_i != ast_space
                                        ]),
                                        ast.bv(1, CPUSIZE.DWORD_BIT),
                                        ast.bv(0, CPUSIZE.DWORD_BIT)
                                    )
                                )
                                # Eventually copy nonspace characters to the corresponding argument
                                ast_arg = ast.array(CPUSIZE.DWORD_BIT)
                                ast_arg_idx = ast.bv(0, CPUSIZE.DWORD_BIT)
                                ast_str_idx = ast.bvadd(ast_cnt_chars, ast_cnt_spaces)
                                for j in range(len(str_)):
                                    ast_arg = ast.store(ast_arg, ast_arg_idx, ast.ite(
                                        # Ensure only characters of the c-th conversion specifier are copied
                                        ast_str_idx < ast_cnt_chars + ast_cnt_spaces + ast_cnt_nonspaces,
                                        ast.select(ast_str, ast_str_idx),   # Do copy
                                        ast.select(ast_arg, ast_arg_idx)    # Do not copy
                                    ))
                                    ast_arg_idx = ast.bvadd(
                                        ast_arg_idx,
                                        ast.ite(
                                            ast_str_idx < ast_cnt_chars + ast_cnt_spaces +ast_cnt_nonspaces,
                                            ast.bv(1, CPUSIZE.DWORD_BIT),
                                            ast.bv(0, CPUSIZE.DWORD_BIT)
                                        )
                                    )
                                    ast_str_idx = ast.bvadd(
                                        ast_str_idx,
                                        ast.bv(1, CPUSIZE.DWORD_BIT)
                                    )
                                for j in range(len(str_)):
                                    ast_arg_j = ast.select(ast_arg, j)
                                    alias = SymbexHelper.create_symvar_alias(
                                        mem_addr=arg_ptr+j,
                                        info=f"MODEL:sscanf@libc:arg{c:d}+{j:d}"
                                    )
                                    sym_exp = ctx.newSymbolicExpression(ast_arg_j, alias)
                                    if sym_exp:
                                        ctx.assignSymbolicExpressionToMemory(
                                            sym_exp, MemoryAccess(arg_ptr+j, CPUSIZE.BYTE)
                                        )
                            # Count number of assignments
                            ast_cnt_ass = ast.bvadd(
                                ast_cnt_ass,
                                ast.ite(
                                    # Ensure that the c-th conversion specifier contains nonspace characters
                                    0 < ast_cnt_nonspaces,
                                    ast.bv(1, CPUSIZE.DWORD_BIT),
                                    ast.bv(0, CPUSIZE.DWORD_BIT)
                                )
                            )
                            # Increment by the number of space and nonspace characters of the c-th conversion specifier s
                            ast_cnt_chars = ast.bvadd(
                                ast_cnt_chars,
                                ast.bvadd(
                                    ast_cnt_spaces,
                                    ast_cnt_nonspaces
                                )
                            )
                        else:
                            self._logger.warning(f"Unsupported conversion.")
                    # Assign symbolic return value
                    ctx.assignSymbolicExpressionToRegister(
                        ctx.newSymbolicExpression(ast_cnt_ass),
                        ctx.registers.r0
                    )
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return

    def old_on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                cnt_assign = Converter.uint_to_int(ctx.getConcreteRegisterValue(ctx.registers.r0))
                self._logger.debug(f"\tresult = {cnt_assign:d}")
                # TODO: Taint mode
                if self._mode == "taint":
                    self._logger.warning("Taint mode not yet implemented.")
                # Model mode
                elif self._mode == "model":
                    s = self.s
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
                        # Assignment suppressing
                        if ass_sup_chr == '*':
                            continue
                        # Conversion specifier s (currently no support for length modifier l)
                        if con_spe == 's' and lth_mod != 'l':
                            # Parse string
                            inp_str = Executor.get_memory_string(ctx, s)
                            m = re.search(r"([^\s]+)", inp_str)
                            if m is None or len(m.groups()) != 1:
                                self._logger.warning(f"Failed to apply conversion specifier 's' to '{inp_str:s}'")
                                continue
                            arg_str = m.group(1)
                            arg_off = m.start()
                            # Assignment allocation
                            if ass_all_chr == 'm':
                                arg_ptr = ctx.getConcreteMemoryValue(MemoryAccess(arg_ptr, CPUSIZE.DWORD))
                            # Move symbolic bytes
                            cut = len(arg_str) > 3
                            for i in range(len(arg_str)):
                                sym_exp = ctx.getSymbolicMemory(s+arg_off+i)
                                if sym_exp:
                                    ctx.assignSymbolicExpressionToMemory(
                                        sym_exp, MemoryAccess(arg_ptr+i, CPUSIZE.BYTE)
                                    )
                                    if not cut or i == 0:
                                        self._logger.debug(f"0x{arg_ptr+i:08x}=$$")
                                    elif i == len(arg_str)-1:
                                        self._logger.debug(f"\t...")
                                        self._logger.debug(f"0x{arg_ptr+i:08x}=$$")
                            s += m.end()
                        # TODO: Support other conversions
                        else:
                            self._logger.warning(f"Unsupported conversion.")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return
    

class strlen(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "size_t strlen(const char *s);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                self.s = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.s_ = Executor.get_memory_string(ctx, self.s)
                self._logger.debug(f"\t s = 0x{self.s:08x}")
                self._logger.debug(f"\t*s = '{self.s_:s}'")
                # Taint mode
                if self._mode == "taint":
                    self._taint = False
                    if ctx.isRegisterSymbolized(ctx.registers.r0):
                        self._taint = True
                        return
                    for i in range(len(self.s_)):
                        mem = MemoryAccess(self.s+i, CPUSIZE.BYTE)
                        if ctx.isMemorySymbolized(mem):
                            self._taint = True
                            return
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                length = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self._logger.debug(f"\tresult = {length:d}")
                # Taint mode
                if self._mode == "taint":
                    if self._taint:
                        ctx.concretizeRegister(ctx.registers.r0)
                        ctx.symbolizeRegister(ctx.registers.r0, SymbexHelper.create_symvar_alias(reg_name="r0", info="TAINT:strlen@libc"))
                        self._logger.debug(f"\tresult = [TAINTED]")
                # Model mode
                elif self._mode == "model":
                    ast = ctx.getAstContext()
                    ast_sum = ast.bv(0, CPUSIZE.DWORD_BIT)
                    for i in range(0, length+1):
                        ast_and = ast.equal(ast.bvtrue(), ast.bvtrue())
                        for k in range(0, i+1):
                            mem = MemoryAccess(self.s+k, CPUSIZE.BYTE)
                            mem_ast = ctx.getMemoryAst(mem)
                            ast_and = ast.land([ast_and, mem_ast != 0x0])
                        ast_ite = ast.ite(ast_and, ast.bv(1, CPUSIZE.DWORD_BIT), ast.bv(0, CPUSIZE.DWORD_BIT))
                        ast_sum = ast.bvadd(ast_sum, ast_ite)
                    sym_exp = ctx.newSymbolicExpression(ast_sum)
                    ctx.assignSymbolicExpressionToRegister(sym_exp, ctx.registers.r0)
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return


class strtol(inst_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "long strtol(const char *restrict nptr, char **restrict endptr, int base);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                self.nptr = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.nptr_ = Executor.get_memory_string(ctx, self.nptr)
                self.endptr = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.base = Converter.uint_to_int(ctx.getConcreteRegisterValue(ctx.registers.r2))
                self._logger.debug(f"\t  nptr   = 0x{self.nptr:08x}")
                self._logger.debug(f"\t *nptr   = '{self.nptr_:s}'")
                self._logger.debug(f"\t  endptr = 0x{self.endptr:08x}")
                self._logger.debug(f"\t  base   = {self.base:d}")
                # Taint mode
                if self._mode == "taint":
                    self._taint = False
                    if ctx.isRegisterSymbolized(ctx.registers.r0):
                        self._taint = True
                        return
                    for i in range(len(self.nptr_)):
                        mem = MemoryAccess(self.nptr+i, CPUSIZE.BYTE)
                        if ctx.isMemorySymbolized(mem):
                                self._taint = True
                                return
                    if ctx.isRegisterSymbolized(ctx.registers.r2):
                        self._taint = True
                        return
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                endptr_ = ctx.getConcreteMemoryValue(MemoryAccess(self.endptr, CPUSIZE.DWORD))
                endptr__ = Executor.get_memory_string(ctx, endptr_)
                result = Converter.ulong_to_long(ctx.getConcreteRegisterValue(ctx.registers.r0))
                self._logger.debug(f"\t *endptr = 0x{endptr_:08x}")
                self._logger.debug(f"\t**endptr = '{endptr__:s}'")
                self._logger.debug(f"\t  result = {result:d}")
                # Taint mode
                if self._mode == "taint":
                    if self._taint:
                        if self.endptr:
                            mem = MemoryAccess(self.endptr, CPUSIZE.DWORD)
                            ctx.concretizeMemory(mem)
                            ctx.symbolizeMemory(mem, SymbexHelper.create_symvar_alias(mem_addr=self.endptr, info="TAINT:strtol@libc:endptr"))
                            self._logger.debug(f"\t *endptr = [TAINTED]")
                        ctx.concretizeRegister(ctx.registers.r0)
                        ctx.symbolizeRegister(ctx.registers.r0, SymbexHelper.create_symvar_alias(reg_name="r0", info="TAINT:strtol@libc"))
                        self._logger.debug(f"\t  result = [TAINTED]")
                # Model mode
                elif self._mode == "model":
                    # Parse string (match spaces, sign, prefix and value)
                    match = re.fullmatch(r'(\s*)([+-]?)(0x|0X)?(.*)', self.nptr_)
                    spaces, sign, prefix, value = match.groups()

                    # Determine base ([2, 36] or 0)
                    base = self.base
                    if not (base >= 2 and base <= 36 or base == 0):
                        self._logger.warning(f"strtol: Base {base:d} is invalid.")
                        return
                    if base == 0:
                        if prefix:
                            base = 16
                        elif value.startswith("0"):
                            base = 8
                        else:
                            base = 10

                    # ASTs of relevant ASCII characters
                    ast = ctx.getAstContext()
                    ast_0 = ast.bv(ord("0"), CPUSIZE.BYTE_BIT)
                    ast_9 = ast.bv(ord("9"), CPUSIZE.BYTE_BIT)
                    ast_a = ast.bv(ord("a"), CPUSIZE.BYTE_BIT)
                    ast_A = ast.bv(ord("A"), CPUSIZE.BYTE_BIT)
                    ast_x = ast.bv(ord("x"), CPUSIZE.BYTE_BIT)
                    ast_X = ast.bv(ord("X"), CPUSIZE.BYTE_BIT)
                    ast_space = ast.bv(ord(" "), CPUSIZE.BYTE_BIT)
                    ast_plus = ast.bv(ord("+"), CPUSIZE.BYTE_BIT)
                    ast_minus = ast.bv(ord("-"), CPUSIZE.BYTE_BIT)

                    # Count characters ([spaces][sign][prefix][valid symbols][invalid symbols]nullbyte)
                    ast_space_cnt = ast.bv(0, CPUSIZE.DWORD_BIT)
                    ast_sign_cnt = ast.bv(0, CPUSIZE.DWORD_BIT)
                    ast_sign = ast.bv(+1, CPUSIZE.DWORD_BIT)
                    ast_prefix_cnt = ast.bv(0, CPUSIZE.DWORD_BIT)
                    ast_valid_symbols_cnt = ast.bv(0, CPUSIZE.DWORD_BIT)
                    for k in range(0, len(self.nptr_)):
                        # Get ASTs of characters k and k+1
                        ast_ck = ctx.getMemoryAst(MemoryAccess(self.nptr + k, CPUSIZE.BYTE))
                        ast_ck1 = ctx.getMemoryAst(MemoryAccess(self.nptr + k + 1, CPUSIZE.BYTE))
                        
                        # Count leading space characters
                        ast_space_cnt = ast.bvadd(
                            ast_space_cnt,
                            ast.ite(
                                ast.land([
                                    k == ast_space_cnt,                                                     # Ensure spaces are leading
                                    ast_ck == ast_space
                                ]),
                                ast.bv(1, CPUSIZE.DWORD_BIT),
                                ast.bv(0, CPUSIZE.DWORD_BIT)
                            )
                        )
                        
                        # Count sign character
                        ast_sign_cnt = ast.bvadd(
                            ast_sign_cnt,
                            ast.ite(
                                ast.land([
                                    k == ast_space_cnt,                                                     # Ensure sign follows spaces
                                    ast.lor([ast_ck == ast_plus, ast_ck == ast_minus])
                                ]),
                                ast.bv(1, CPUSIZE.DWORD_BIT),
                                ast.bv(0, CPUSIZE.DWORD_BIT)
                            )
                        )
                        
                        # Determine sign
                        ast_sign = ast.ite(
                            ast.land([
                                k == ast_space_cnt,
                                ast_ck == ast_minus
                            ]),
                            ast.bv(-1, CPUSIZE.DWORD_BIT),
                            ast_sign
                        )
                        
                        #  Count prefix characters
                        ast_prefix_cnt = ast.bvadd(
                            ast_prefix_cnt,
                            ast.ite(
                                ast.land([
                                    k == ast_space_cnt + ast_sign_cnt,                                      # Ensure prefix follows the sign
                                    ast_ck == ast_0,
                                    ast.lor([ast_ck1 == ast_x, ast_ck1 == ast_X])
                                ]),
                                ast.bv(2, CPUSIZE.DWORD_BIT),
                                ast.bv(0, CPUSIZE.DWORD_BIT)
                            )
                        )
                        
                        # Count valid symbol characters
                        ast_valid_symbols_cnt = ast.bvadd(
                            ast_valid_symbols_cnt,
                            ast.ite(
                                k == ast_space_cnt + ast_sign_cnt + ast_prefix_cnt + ast_valid_symbols_cnt, # Ensure valid symbols follow prefix
                                ast.ite(
                                    ast.land([ast_ck >= ast_0, ast_ck <= ast_9, ast_ck < ast_0 + base]),    # If c is a valid digit for the given base
                                    ast.bv(1, CPUSIZE.DWORD_BIT),
                                    ast.ite(
                                        ast.land([ast_ck >= ast_a, ast_ck < ast_a + base - 10]),            # If c is a valid lower-case letter for the given base
                                        ast.bv(1, CPUSIZE.DWORD_BIT),
                                        ast.ite(
                                            ast.land([ast_ck >= ast_A, ast_ck < ast_A + base - 10]),        # If c is a valid upper-case letter for the given base
                                            ast.bv(1, CPUSIZE.DWORD_BIT),
                                            ast.bv(0, CPUSIZE.DWORD_BIT)
                                        )
                                    )
                                ),
                                ast.bv(0, CPUSIZE.DWORD_BIT)
                            )
                        )

                    # Calculate (signed) sum
                    ast_sum = ast.bv(0, CPUSIZE.DWORD_BIT)
                    ast_factor = ast.bv(1, CPUSIZE.DWORD_BIT)                                       # TODO: ast_factor might overflow when having too many valid symbols
                    for k in reversed(range(0, len(self.nptr_))):
                        # Get AST of character k
                        ast_ck = ctx.getMemoryAst(MemoryAccess(self.nptr + k, CPUSIZE.BYTE))

                        # Transform character to digit
                        ast_ak = ast.ite(
                            ast.land([ast_ck >= ast_0, ast_ck <= ast_9, ast_ck < ast_0 + base]),    # If c is a valid digit for the given base
                            ast_ck - ast_0,
                            ast.ite(
                                ast.land([ast_ck >= ast_a, ast_ck < ast_a + base - 10]),            # If c is a valid lower-case letter for the given base
                                ast_ck - ast_a + 10,
                                ast.ite(
                                    ast.land([ast_ck >= ast_A, ast_ck < ast_A + base - 10]),        # If c is a valid upper-case letter for the given base
                                    ast_ck - ast_A + 10,
                                    ast_0
                                )
                            )
                        )
                        ast_ak = ast.concat([ast.bv(0, CPUSIZE.DWORD_BIT-CPUSIZE.BYTE_BIT), ast_ak])

                        # Calculate (signed) sum
                        ast_sum = ast.bvadd(
                            ast_sum,
                            ast.ite(
                                ast.land([
                                    k >= ast_space_cnt + ast_sign_cnt + ast_prefix_cnt,
                                    k <  ast_space_cnt + ast_sign_cnt + ast_prefix_cnt + ast_valid_symbols_cnt
                                ]),
                                ast_ak * ast_factor * ast_sign,
                                ast.bv(0, CPUSIZE.DWORD_BIT)
                            )
                        )

                        # Calculate factor (base^k)
                        ast_factor = ast.bvmul(
                            ast_factor,
                            ast.ite(
                                ast.land([
                                    k >= ast_space_cnt + ast_sign_cnt + ast_prefix_cnt,
                                    k <  ast_space_cnt + ast_sign_cnt + ast_prefix_cnt + ast_valid_symbols_cnt
                                ]),
                                ast.bv(base, CPUSIZE.DWORD_BIT),
                                ast.bv(1, CPUSIZE.DWORD_BIT)
                            )
                        )
                        
                    # Debug output
                    self._logger.debug(f"---")
                    self._logger.debug(f"\tBase                  : {base:d}")
                    space_cnt = ctx.evaluateAstViaSolver(ast_space_cnt)
                    self._logger.debug(f"\tNo. Space Chars       : {space_cnt:d}")
                    sign_cnt = ctx.evaluateAstViaSolver(ast_sign_cnt)
                    self._logger.debug(f"\tNo. Sign Chars        : {sign_cnt:d}")
                    prefix_cnt = ctx.evaluateAstViaSolver(ast_prefix_cnt)
                    self._logger.debug(f"\tNo. Prefix Chars      : {prefix_cnt:d}")
                    valid_symbols_cnt = ctx.evaluateAstViaSolver(ast_valid_symbols_cnt)
                    self._logger.debug(f"\tNo. Valid Symbol Chars: {valid_symbols_cnt:d}")
                    result = ctx.evaluateAstViaSolver(ast_sum)
                    self._logger.debug(f"\tResult                : {result:d}")
                    self._logger.debug(f"---")

                    # Assign symbolic result to return register
                    sym_exp = ctx.newSymbolicExpression(ast_sum)
                    ctx.assignSymbolicExpressionToRegister(sym_exp, ctx.registers.r0)
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return


class strtoul(strtol):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "unsigned long strtoul(const char *restrict nptr, char **restrict endptr, int base);"
        return