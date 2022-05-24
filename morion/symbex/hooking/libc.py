#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from   morion.log                import Logger
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
                self.endptr = ctx.getConcreteRegisterValue(ctx.registers.r1)
                self.base = ctx.getConcreteRegisterValue(ctx.registers.r2)
                self._logger.debug(f"\tnptr   = 0x{self.nptr:08x}")
                self._logger.debug(f"\tendptr = 0x{self.endptr:08x}")
                self._logger.debug(f"\tbase   = {self.base:d}")
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
                endptr = ctx.getConcreteMemoryValue(MemoryAccess(self.endptr, CPUSIZE.DWORD))
                # TODO: Read string from memory (Make a helper function)
                ret = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self._logger.debug(f"\tret    = {ret:d}")

                # Read string from memory
                mem_addr = self.nptr
                nptr_val = ""
                while True:
                    mem_val = ctx.getConcreteMemoryValue(mem_addr)
                    char = chr(mem_val)
                    if char not in string.printable:
                        char = ""
                    nptr_val += char
                    if not mem_val: break
                    mem_addr += CPUSIZE.BYTE

                # Parse string (match spaces, sign, prefix and value)
                match = re.fullmatch(r'(\s*)([+-]?)(0x|0X)?(.*)', nptr_val)
                spaces, sign, prefix, value = match.groups()

                # TODO: Base ([2, 36] or 0)

                # Base must be between 2 and 36 inclusive or 0
                if not (self.base >= 2 and self.base <= 36 or self.base == 0):
                    self._logger.warning(f"Invalid base: {self.base:d}")
                    return

                # With prefix
                if prefix:
                    # Hexadecimal
                    if self.base == 0 or self.base == 16:
                        pass
                    # Invalid
                    else:
                        self._logger.warning(f"Invalid string: '{nptr_val:s}'")
                # Without prefix
                else:
                    if self.base == 0:
                        # Octal
                        if value.startswith("0"):
                            pass
                        # Decimal
                        else:
                            pass
                    else:
                        # Otherwise
                        pass
                # TODO
                base = 10
                
                # Symbolic result
                ast = ctx.getAstContext()
                ast_0 = ast.bv(ord("0"), CPUSIZE.BYTE_BIT)
                ast_9 = ast.bv(ord("9"), CPUSIZE.BYTE_BIT)
                ast_a = ast.bv(ord("a"), CPUSIZE.BYTE_BIT)
                ast_A = ast.bv(ord("A"), CPUSIZE.BYTE_BIT)
                ast_sum = ast.bv(0, CPUSIZE.DWORD_BIT) # TODO: What size does unsinged long have on ARMv7?
                for i in range(0, len(nptr_val)):
                    ast_ck = ast.bv(ord(nptr_val[i]), CPUSIZE.BYTE_BIT)
                    ast_ak = ast.ite(
                        ast.land([ast_ck >= ast_0, ast_ck <= ast_9, ast_ck < ast_0 + base]),
                        ast_ck - ast_0,
                        ast.ite(
                            ast.land([ast_ck >= ast_a, ast_ck < ast_a + base - 10]),
                            ast_ck - ast_a + 10,
                            ast_ck - ast_A + 10
                        )
                    )
                    ast_ak = ast.concat([ast.bv(0, CPUSIZE.DWORD_BIT-CPUSIZE.BYTE_BIT), ast_ak])
                    ast_sum = ast.bvadd(ast_sum, ast_ak * (base ** i))
                sym_exp = ctx.newSymbolicExpression(ast_sum)
                ctx.assignSymbolicExpressionToRegister(sym_exp, ctx.registers.r0)
                import IPython; IPython.embed(header="strtoul (leave)")
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
                self._logger.debug(f"s=0x{self.s:x}")
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
                self._logger.debug(f"ret={length:d}")
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
