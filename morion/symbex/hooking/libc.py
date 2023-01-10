#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from   morion.log                import Logger
from   morion.symbex.execute     import Helper
from   morion.symbex.hooking.lib import base_hook
from   triton                    import ARCH, CPUSIZE, MemoryAccess, TritonContext


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
                self._s = Helper.get_memory_string(ctx, self.s)
                self._logger.debug(f"\ts   = 0x{self.s:08x}")
                self._logger.debug(f"\t*s  = '{self._s:s}'")
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
                self._s = Helper.get_memory_string(ctx, self.s)
                self._logger.debug(f"\ts   = 0x{self.s:08x}")
                self._logger.debug(f"\t*s  = '{self._s:s}'")
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
                self._logger.debug(f"\tret = {length:d}")
                # TODO: Taint mode
                if self._mode == "taint":
                    self._logger.warning(f"{self._name:s}: Taint mode not implemented.")
                # Model mode
                elif self._mode == "mode":
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