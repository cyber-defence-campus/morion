#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from morion.log import Logger
from triton     import ARCH, TritonContext


class FunctionHook:
    """
    Base class for simulations functions.
    """

    def __init__(self, name: str, entry_addr: int, leave_addr: int, logger: Logger = Logger()) -> None:
        self._name = name
        self._entry_addr = entry_addr
        self._leave_addr = leave_addr
        self._logger = logger
        self.synopsis = ""
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
            self._logger.error(f"{self._name:s} (on_entry) failed: {str(e):s}")
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
            self._logger.error(f"{self._name:s} (on_leave) failed: {str(e):s}")
        return

    

    
