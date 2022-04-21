#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
import sys
from   morion.log    import Logger
from   morion.record import Recorder
from   triton        import ARCH, AST_REPRESENTATION, MODE, TritonContext


class SymbolicExecutor:

    def __init__(self, logger: Logger = Logger()) -> None:
        self.logger = logger
        self.recorder = Recorder(logger)
        return

    def load(self, trace_file: str) -> None:
        # Load trace file
        self.recorder.load(trace_file)
        # Setup fresh Triton context
        self.ctx = TritonContext()
        self.ctx.setMode(MODE.ALIGNED_MEMORY, True)
        self.ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
        arch = self.recorder._trace["info"].get("arch", None)
        if arch in ["armv6", "armv7"]:
            self.ctx.setArchitecture(ARCH.ARM32)
            thumb = self.recorder._trace["info"].get("thumb", None)
            if not thumb is None:
                self.ctx.setThumb(thumb)
        else:
            self.logger.critical(f"Architecture '{arch:s}' not supported.")
            sys.exit("Unsupported architecture.")
        # Set concrete register values
        self.logger.debug("Concrete Regs:")
        regs = self.recorder._trace.get("states", {}).get("entry", {}).get("regs", {})
        for reg_name, reg_values in regs.items():
            try:
                reg = self.ctx.getRegister(reg_name)
                if not isinstance(reg_values, list): reg_values = [reg_values]
                for reg_value in reg_values:
                    if not isinstance(reg_value, int):
                        reg_value = int(reg_value, base=0)
                    self.ctx.setConcreteRegisterValue(reg, reg_value)
                    self.logger.debug(f"\t{reg_name:s}=0x{reg_value:x}")
            except:
                continue
        # Set concrete memory values
        self.logger.debug("Concrete Mems:")
        mems = self.recorder._trace.get("states", {}).get("entry", {}).get("mems", {})
        for mem_addr, mem_values in mems.items():
            try:
                if not isinstance(mem_addr, int):
                    mem_addr = int(mem_addr, base=0)
                if not isinstance(mem_values, list): mem_values = [mem_values]
                for mem_value in mem_values:
                    if not isinstance(mem_value, int):
                        mem_value = int(mem_value, base=0)
                    self.ctx.setConcreteMemoryValue(mem_addr, mem_value)
                    self.logger.debug(f"\t0x{mem_addr:x}=0x{mem_value:x}")
            except:
                continue
        # TODO: Set symbolic register values
        # TODO: Set symbolic memory values
        return


def main() -> None:
    # Argument parsing
    description = """
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("trace_file",
                        help="file containing the trace to be executed symbolically")
    parser.add_argument("--log_level",
                        choices=["debug", "info", "warning", "error", "critical"],
                        default="debug",
                        help="log level")
    args = parser.parse_args()

    # 
    se = SymbolicExecutor(Logger(args.log_level))
    se.load(args.trace_file)
    return

if __name__ == "__main__":
    main()
