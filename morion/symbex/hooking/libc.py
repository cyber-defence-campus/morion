#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from morion.log                import Logger
from morion.symbex.hooking.lib import FunctionHook
from triton                    import ARCH, CPUSIZE, MemoryAccess, TritonContext


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
                self._logger.debug(f"s=0x{self.s:x}", color="yellow")
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
                self._logger.debug(f"ret={length:d}", color="yellow")
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
