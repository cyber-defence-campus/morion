#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from   morion.log                import Logger
from   morion.symbex.execute     import Helper
from   morion.symbex.hooking.lib import FunctionHook
from   triton                    import ARCH, CPUSIZE, MemoryAccess, TritonContext
import re
import string


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
##                # TODO: Store the number of path constraints
##                self.cnt_path_constraints = len(ctx.getPathConstraints())
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Log arguments
                length = ctx.getConcreteRegisterValue(ctx.registers.r0)
                self._logger.debug(f"\tret = {length:d}")
##                # TODO: Remove path constraints added by strlen
##                for _ in range(len(ctx.getPathConstraints()) - self.cnt_path_constraints):
##                    ctx.popPathConstraint()
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on_leave) failed: {str(e):s}")
        return