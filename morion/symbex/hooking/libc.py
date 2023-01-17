#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from    morion.log                import Logger
from    morion.symbex.execute     import Helper
from    morion.symbex.hooking.lib import base_hook
from    triton                    import ARCH, CPUSIZE, MemoryAccess, TritonContext
import re


class memcpy(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "void *memcpy(void *restrict dest, const void *restrict src, size_t n);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                self.dest = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.src  = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.n    = ctx.getConcreteRegisterValue(ctx.registers.r2)
                self._logger.debug(f"\tdest = 0x{self.dest:08x}")
                self._logger.debug(f"\tsrc  = 0x{self.src:08x}")
                self._logger.debug(f"\tn    = {self.n:d}")
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
                self._logger.debug(f"\tresult = 0x{result:08x}")
                # TODO: Taint mode
                if self._mode == "taint":
                    self._logger.warning(f"{self._name:s}: Taint mode not implemented.")
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


class puts(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "int puts(const char *s);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                self.s = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.s_ = Helper.get_memory_string(ctx, self.s)
                self._logger.debug(f"\t s = 0x{self.s:08x}")
                self._logger.debug(f"\t*s = '{self.s_:s}'")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return


class strlen(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "size_t strlen(const char *s);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                self.s = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.s_ = Helper.get_memory_string(ctx, self.s)
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
                        ctx.symbolizeRegister(ctx.registers.r0, "r0 [TAINT:strlen]")
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


class strtol(base_hook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, mode, logger)
        self.synopsis = "long strtol(const char *restrict nptr, char **restrict endptr, int base);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                self.nptr = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.nptr_ = Helper.get_memory_string(ctx, self.nptr)
                self.endptr = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.base = ctx.getConcreteRegisterValue(ctx.registers.r2)
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
                endptr__ = Helper.get_memory_string(ctx, endptr_)
                result = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self._logger.debug(f"\t *endptr = 0x{endptr_:08x}")
                self._logger.debug(f"\t**endptr = '{endptr__:s}'")
                self._logger.debug(f"\t  result = {result:d}")
                # Taint mode
                if self._mode == "taint":
                    if self._taint:
                        if self.endptr:
                            mem = MemoryAccess(self.endptr, CPUSIZE.DWORD)
                            ctx.concretizeMemory(mem)
                            ctx.symbolizeMemory(mem, f"0x{self.endptr:x} [TAINT:strtol]")
                            self._logger.debug(f"\t *endptr = [TAINTED]")
                        ctx.concretizeRegister(ctx.registers.r0)
                        ctx.symbolizeRegister(ctx.registers.r0, "r0 [TAINT:strtol]")
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

                    # ASTs or relevant ASCII characters
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
                    ast_factor = ast.bv(1, CPUSIZE.DWORD_BIT)   # TODO: ast_factor might overflow when having too many valid symbols
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