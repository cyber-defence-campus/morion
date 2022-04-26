#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
from   morion.log                           import Logger
from   morion.symbex.execute                import Executor
from   morion.symbex.analysis.vulnerability import identify_backward_slice
from   triton                               import MODE


class BackwardSlicer(Executor):

    def _slice_symbolic_expression(self, sym_exp: 'SymbolicExpression') -> None:
        # Calculate backward slice
        backward_slice = self.ctx.sliceExpressions(sym_exp)
        # Log backward slice
        for _, sym_exp in sorted(backward_slice.items()):
            comment = sym_exp.getComment()
            if comment:
                self._logger.info(f"\t{comment:s}", color="magenta")
        return

    def _backward_slice_register(self, reg_name: str) -> bool:
        try:
            reg = self.ctx.getRegister(reg_name)
            # Get symbolic expression assigned to register
            reg_sym_exp = self.ctx.getSymbolicRegister(reg)
            # Calculate backward slice
            self._logger.info(f"Start exploring backward slice for register '{reg_name:s}'...")
            if reg_sym_exp is not None:
                self._slice_symbolic_expression(reg_sym_exp)
            self._logger.info(f"... finished exploring backward slice for register '{reg_name:s}'.")
        except Exception as e:
            self._logger.error(
                f"Failed to create backward slice for register '{reg_name:s}': {str(e):s}")
            return False
        return True

    def _backward_slice_memory(self, mem_addr: int) -> bool:
        try:
            # Get symbolic expression assigned to memory
            mem_sym_exp = self.ctx.getSymbolicMemory(mem_addr)
            # Calculate backward slice
            self._logger.info(f"Start exploring backward slice for memory address '0x{mem_addr:x}'...")
            if mem_sym_exp is not None:
                self._slice_symbolic_expression(mem_sym_exp)
            self._logger.info(f"... finished exploring backward slice for memory address '0x{mem_addr:x}'.")
        except Exception as e:
            self._logger.error(
                f"Failed to create backward slice for memory address '0x{mem_addr:x}': {str(e):s}")
            return False
        return True

    def run(self, reg_name: str, mem_addr: int, stepping: bool = False) -> None:
        # Set symbolic execution mode
        self._only_on_symbolized = self.ctx.isModeEnabled(MODE.ONLY_ON_SYMBOLIZED)
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, False)
        # Add post-processing function
        self._post_processing_functions.append(identify_backward_slice)
        # Run symbolic execution
        super().run(stepping)
        # Calculate backward slice
        if reg_name is not None:
            self._backward_slice_register(reg_name)
        if mem_addr is not None:
            self._backward_slice_memory(mem_addr)
        # Remove post-processing function
        self._post_processing_functions.pop()
        # Restore symbolic execution mode
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, self._only_on_symbolized)
        return
    

def main() -> None:
    # Argument parsing
    description = """
    Calculate backward slices in a binary's program trace.
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("trace_file",
                        help="file containing the trace to be executed symbolically")
    parser.add_argument("--reg_name", default=None,
                        help="register name to use as a slicing source")
    parser.add_argument("--mem_addr", default=None,
                        help="memory address to use as a slicing source")
    parser.add_argument("--log_level",
                        choices=["critical", "error", "warning", "info", "debug"],
                        default="debug",
                        help="log level")
    parser.add_argument("--stepping",
                        action="store_true",
                        help="Open a debug shell after each instruction")
    args = parser.parse_args()

    if (args.reg_name is None) == (args.mem_addr is None):
        print("error: invalid slicing source\n")
        parser.print_help()
        return

    if args.mem_addr is not None:
        try:
            args.mem_addr = int(args.mem_addr, base=0)
        except:
            print("error: invalid 'mem_addr'\n")
            parser.print_help()
            return

    # Symbolic Execution
    se = BackwardSlicer(Logger(args.log_level))
    se.load(args.trace_file)
    se.run(args.reg_name, args.mem_addr, args.stepping)
    se.store(args.trace_file)
    return

if __name__ == "__main__":
    main()
