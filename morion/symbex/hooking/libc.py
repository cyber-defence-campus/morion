#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from   morion.log                import Logger
from   morion.symbex.execute     import Helper
from   morion.symbex.hooking.lib import FunctionHook
from   triton                    import ARCH, CPUSIZE, MemoryAccess, TritonContext
import re
import string


class memcpy(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "void *memcpy(void *restrict dest, const void *restrict src, size_t n);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Store and log arguments
                self.dest = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self.src = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.n = ctx.getConcreteRegisterValue(ctx.registers.r2)
                self._logger.debug(f"\tdest=0x{self.dest:x}")
                self._logger.debug(f"\tsrc =0x{self.src:x}")
                self._logger.debug(f"\tn   ={self.n:d}")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Copy symbolic expressions
                for i in range(0, self.n):
                    sym_exp = ctx.getSymbolicMemory(self.src+i)
                    if sym_exp:
                        ctx.assignSymbolicExpressionToMemory(
                            sym_exp, MemoryAccess(self.dest+i, CPUSIZE.BYTE))
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_leave) failed: {str(e):s}")
        return


class printf(FunctionHook):
    
    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "int printf(const char *restrict format, ...);"
        return


class strtoul(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "unsigned long strtoul(const char *restrict nptr, char **restrict endptr, int base);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # TODO: Make other classes similar to this one!
                self.nptr = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self._nptr = Helper.get_memory_string(ctx, self.nptr)
                self.endptr = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.base = ctx.getConcreteRegisterValue(ctx.registers.r2)
                self._logger.debug(f"\tnptr     = 0x{self.nptr:08x}")
                self._logger.debug(f"\t*nptr    = '{self._nptr:s}'")
                self._logger.debug(f"\tendptr   = 0x{self.endptr:08x}")
                self._logger.debug(f"\tbase     = {self.base:d}")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Concrete result
                _endptr = ctx.getConcreteMemoryValue(MemoryAccess(self.endptr, CPUSIZE.DWORD))
                __endptr = Helper.get_memory_string(ctx, _endptr)
                ret = ctx.getConcreteRegisterValue(ctx.registers.r0)

                # Parse string (match spaces, sign, prefix and value)
                match = re.fullmatch(r'(\s*)([+-]?)(0x|0X)?(.*)', self._nptr)
                spaces, sign, prefix, value = match.groups()

                # Determine base ([2, 36] or 0)
                base = self.base
                if not (base >= 2 and base <= 36 or base == 0):
                    self._logger.warning(f"strtoul: Base {base:d} is invalid.")
                    return
                if base == 0:
                    if prefix:
                        base = 16
                    elif value.startswith("0"):
                        base = 8
                    else:
                        base = 10
                
                self._logger.debug(f"\t*endptr  = 0x{_endptr:08x}")
                self._logger.debug(f"\t**endptr = '{__endptr:s}'")
                self._logger.debug(f"\tbase     = {base:d}")
                self._logger.debug(f"\tret      = {ret:d}")

                # Symbolic result
                ast = ctx.getAstContext()
                ast_0 = ast.bv(ord("0"), CPUSIZE.BYTE_BIT)
                ast_9 = ast.bv(ord("9"), CPUSIZE.BYTE_BIT)
                ast_a = ast.bv(ord("a"), CPUSIZE.BYTE_BIT)
                ast_A = ast.bv(ord("A"), CPUSIZE.BYTE_BIT)
                ast_sum = ast.bv(0, CPUSIZE.DWORD_BIT)
                # Iterate valid characters
                for i in range(0, len(self._nptr)):
                    ast_ck = ctx.getMemoryAst(MemoryAccess(self.nptr + i, CPUSIZE.BYTE))
                    ast_ak = ast.ite(
                        ast.land([ast_ck >= ast_0, ast_ck <= ast_9, ast_ck < ast_0 + base]),    # If c is a valid digit for the given base
                        ast_ck - ast_0,
                        ast.ite(
                            ast.land([ast_ck >= ast_a, ast_ck < ast_a + base - 10]),            # If c is a valid lower-case letter for the given base
                            ast_ck - ast_a + 10,
                            ast.ite(
                                ast.land([ast_ck >= ast_A, ast_ck < ast_A + base - 10]),        # If c is a valid upper-case letter for the given base
                                ast_ck - ast_A + 10,
                                ast.ite(                                                        # Constrain valid symbols
                                    ast_ck < ast_0,
                                    ast_0,
                                    ast_0 + base -1
                                )
                            )
                        )
                    )
                    ast_ak = ast.concat([ast.bv(0, CPUSIZE.DWORD_BIT-CPUSIZE.BYTE_BIT), ast_ak])
                    ast_sum = ast.bvadd(ast_sum, ast_ak * (base ** (len(self._nptr)-1-i)))
                sym_exp = ctx.newSymbolicExpression(ast_sum)
                ctx.assignSymbolicExpressionToRegister(sym_exp, ctx.registers.r0)
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_leave) failed: {str(e):s}")
        return

    
class strlen(FunctionHook):

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        super().__init__(name, entry_addr, leave_addr, logger)
        self.synopsis = "size_t strlen(const char *s);"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                self.s = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self._s = Helper.get_memory_string(ctx, self.s)
                self._logger.debug(f"\ts   = 0x{self.s:08x}")
                self._logger.debug(f"\t*s  = '{self._s:s}'")
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Concrete result
                length = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self._logger.debug(f"\tret = {length:d}")
                # Symbolic result
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
            self._logger.error(f"{self._name:s} (on_leave) failed: {str(e):s}")
        return
