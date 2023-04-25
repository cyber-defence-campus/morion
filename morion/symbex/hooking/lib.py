#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from morion.log import Logger
from triton     import ARCH, CPUSIZE, MemoryAccess, TritonContext


class inst_hook:
    """
    Base class for hooking instruction sequences.
    """

    def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
        self._name = name
        self._entry_addr = entry_addr
        self._leave_addr = leave_addr
        self._mode = mode
        self._logger = logger
        self.synopsis = "inst_hook"
        return

    def on_entry(self, ctx: TritonContext) -> None:
        """On entry hook during symbolic execution.

        At this point, the hooked function has not yet been executed
        symbolically.

        Within this function, only registers/memory in the context of the
        symbolic execution should be accessed (not from concrete execution).
        """
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Add logic here
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
        return

    def on_leave(self, ctx: TritonContext) -> None:
        """On leave hook during symbolic execution.

        At this point, the hooked function has been executed symbolically.

        Within this function, only registers/memory in the context of the
        symbolic execution should be accessed (not from concrete execution).
        """
        try:
            arch = ctx.getArchitecture()
            if arch == ARCH.ARM32:
                # Add logic here
                return
            raise Exception(f"Architecture '{arch:d}' not supported.")
        except Exception as e:
            self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
        return

# TODO: Use this to implement taint mode
# class generic_hook(inst_hook):
#     """
#     Assign new symbolic variable(s) to function result(s), in case any of the function arguments is
#     based on a symbolic variable.
#     """

#     def __init__(self, name: str, entry_addr: int, leave_addr: int, mode: str = "skip", logger: Logger = Logger()) -> None:
#         self._name = name
#         self._entry_addr = entry_addr
#         self._leave_addr = leave_addr
#         self._mode = mode
#         self._logger = logger
#         self.synopsis = "generic_hook"
#         self.argc = 0
#         self.retc = 0
#         return

#     def on_entry(self, ctx: TritonContext) -> None:
#         try:
#             arch = ctx.getArchitecture()
#             if arch == ARCH.ARM32:
#                 # Check if any function argument is based on a symbolic variable
#                 self._symbolizeResult = False
#                 if not self._symbolizeResult and self.argc >= 1:
#                     # arg1 --> r0
#                     r0 = ctx.getRegister('r0')
#                     if ctx.isRegisterSymbolized(r0): self._symbolizeResult = True
#                 if not self._symbolizeResult and self.argc >= 2:
#                     # arg2 --> r1
#                     r1 = ctx.getRegister('r1')
#                     if ctx.isRegisterSymbolized(r1): self._symbolizeResult = True
#                 if not self._symbolizeResult and self.argc >= 3:
#                     # arg3 --> r2
#                     r2 = ctx.getRegister('r2')
#                     if ctx.isRegisterSymbolized(r2): self._symbolizeResult = True
#                 if not self._symbolizeResult and self.argc >= 4:
#                     # arg4 --> r3
#                     r3 = ctx.getRegister('r3')
#                     if ctx.isRegisterSymbolized(r3): self._symbolizeResult = True
#                 if not self._symbolizeResult:
#                     # argN --> [sp + (N-5)*4]
#                     sp = ctx.getRegister('sp')
#                     sp_val = ctx.getConcreteRegisterValue(sp)
#                     for i in range(0, self.argc-4):
#                         mem = MemoryAccess(sp_val + i*CPUSIZE.DWORD, CPUSIZE.DWORD)
#                         if ctx.isMemorySymbolized(mem):
#                             self._symbolizeResult = True
#                             break
#                 # Add logic here
#                 return
#             raise Exception(f"Architecture '{arch:d}' not supported.")
#         except Exception as e:
#             self._logger.error(f"{self._name:s} (on=entry, mode={self._mode:s}) failed: {str(e):s}")
#         return

#     def on_leave(self, ctx: TritonContext) -> None:
#         try:
#             arch = ctx.getArchitecture()
#             if arch == ARCH.ARM32:
#                 # Assign new symbolic variables to return registers
#                 if self._symbolizeResult:
#                     ast = ctx.getAstContext()
#                     if self.retc >= 1:
#                         sym_var = ctx.newSymbolicVariable(CPUSIZE.DWORD_BIT, f"r0 ({self.synopsis})")
#                         sym_exp = ctx.newSymbolicExpression(ast.variable(sym_var))
#                         ctx.assignSymbolicExpressionToRegister(sym_exp, ctx.getRegister('r0'))
#                     if self.retc >= 2:
#                         sym_var = ctx.newSymbolicVariable(CPUSIZE.DWORD_BIT, f"r1 ({self.synopsis})")
#                         sym_exp = ctx.newSymbolicExpression(ast.variable(sym_var))
#                         ctx.assignSymbolicExpressionToRegister(sym_exp, ctx.getRegister('r1'))
#                 # Add logic here
#                 return
#             raise Exception(f"Architecture '{arch:d}' not supported.")
#         except Exception as e:
#             self._logger.error(f"{self._name:s} (on=leave, mode={self._mode:s}) failed: {str(e):s}")
#         return
    

    
