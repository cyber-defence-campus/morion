#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
import sys
from   morion.log    import Logger
from   morion.record import Recorder
from   triton        import ARCH, AST_REPRESENTATION, CPUSIZE, Instruction, MemoryAccess, MODE, TritonContext
from   typing        import List


class Executor:
    """
    Symbolic execution of a program trace.
    """

    def __init__(self, logger: Logger = Logger()) -> None:
        self.logger = logger
        self.recorder = Recorder(logger)
        self.__post_processing_functions = []
        return

    def load(self, trace_file: str) -> None:
        self.logger.info(f"Start loading file '{trace_file:s}'...")
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
        # Set symbolic register values
        self.logger.debug("Symbolic Regs:")
        for reg_name, reg_values in regs.items():
            try:
                reg = self.ctx.getRegister(reg_name)
                if not isinstance(reg_values, list): reg_values = [reg_values]
                if "$" in reg_values:
                    self.ctx.symbolizeRegister(reg, reg_name)
                    self.logger.debug(f"\t{reg_name:s}=$")
            except:
                continue
        # Set symbolic memory values
        self.logger.debug("Symbolic Mems:")
        for mem_addr, mem_values in mems.items():
            try:
                if not isinstance(mem_addr, int):
                    mem_addr = int(mem_addr, base=0)
                if not isinstance(mem_values, list): mem_values = [mem_values]
                if "$" in mem_values:
                    mem = MemoryAccess(mem_addr, CPUSIZE.BYTE)
                    self.ctx.symbolizeMemory(mem, f"0x{mem_addr:x}")
                    self.logger.debug(f"\t0x{mem_addr:x}=$")
            except:
                continue
        self.logger.info(f"... finished loading file '{trace_file:s}'.")
        return

    def __is_controllable(self, ast, val: int, byte_size: int) -> List[bool]:
        byte_mask = []
        val = format(val, "0{:d}x".format(byte_size*2))
        for i in range(0, len(val), 2):
            if val[i:i+1] != "42" and val[i:i+1] != "44":
                val1 = val[0:i] + "42" + val[i+2:]
                val2 = val[0:i] + "44" + val[i+2:]
            else:
                val1 = val[0:i] + "46" + val[i+2:]
                val2 = val[0:i] + "48" + val[i+2:]
            if (self.ctx.isSat(ast == int(val1, base=16)) and
                self.ctx.isSat(ast == int(val2, base=16))):
                byte_mask.append(True)
            else:
                byte_mask.append(False)
        return byte_mask

    def __is_register_symbolic(self, reg_name: str) -> List[bool]:
        reg = self.ctx.getRegister(reg_name)
        reg_size = reg.getSize()
        byte_mask = [False] * reg_size
        # Register AST contains symbolic variables
        if self.ctx.isRegisterSymbolized(reg) and reg_size > 0:
            reg_ast = self.ctx.getRegisterAst(reg)
            reg_val = self.ctx.getConcreteRegisterValue(reg)
            byte_mask = self.__is_controllable(reg_ast, reg_val, reg_size)
        return byte_mask

    def __is_memory_symbolic(self, mem_addr: int, mem_size: int = CPUSIZE.BYTE) -> List[bool]:
        mem = MemoryAccess(mem_addr, mem_size)
        byte_mask = [False] * mem_size
        # Memory AST contains symbolic variables
        if self.ctx.isMemorySymbolized(mem) and mem_size > 0:
            mem_ast = self.ctx.getMemoryAst(mem)
            mem_val = self.ctx.getConcreteMemoryValue(mem)
            byte_mask = self.__is_controllable(mem_ast, mem_val, mem_size)
        return byte_mask

    def __step(self, addr: int, opcode: bytes, disassembly: str, comment: str = None) -> bool:
        try:
            # Create instruction
            inst = Instruction(addr, opcode)

            # Disassemble instruction
            self.ctx.disassembly(inst)

            # Build instruction semantics
            is_supported = self.ctx.buildSemantics(inst)

            # Log instruction
            line = [f"0x{inst.getAddress():08x} {inst.getDisassembly():s}", comment]
            self.logger.debug("".join(item.ljust(36) for item in line))

            # Post-process instruction
            for post_processing_function in self.__post_processing_functions:
                post_processing_function(inst)
        except Exception as e:
            self.logger.error(f"Failed to symbolically execute instruction '0x{addr:x} {disassembly:s}': {str(e):s}")
            return False
        return is_supported

    def run(self) -> None:
        # Symbolic execution
        self.logger.info(f"Start symbolic execution...")
        for addr, opcode, disassembly, comment in self.recorder.get_trace():
            # Decode instruction
            try:
                if not isinstance(addr, int):
                    addr = int(addr, base=0)
                opcode = bytes.fromhex(opcode.replace(" ", ""))
            except Exception as e:
                self.logger.critical(f"Failed to read instruction from trace file: {str(e):s}")
                return

            # TODO: Hooks

            # Symbolic execution
            if not self.__step(addr, opcode, disassembly, comment):
                break
        self.logger.info(f"... finished symbolic execution.")

        # Symbolic state
        self.logger.info("Start analyzing symbolic state...")
        self.logger.debug("Symbolic Regs:")
        for reg_id in sorted(self.ctx.getSymbolicRegisters().keys()):
            reg = self.ctx.getRegister(reg_id)
            reg_name = reg.getName()
            byte_mask = self.__is_register_symbolic(reg_name)
            reg_mask = "".join("$$" if b else "XX" for b in byte_mask)
            if "$" in reg_mask:
                self.logger.debug(f"\t{reg_name:s}={reg_mask:s}")
        self.logger.debug("Symbolic Mems:")
        for mem_addr in sorted(self.ctx.getSymbolicMemory().keys()):
            byte_mask = self.__is_memory_symbolic(mem_addr)
            mem_mask = "".join("$$" if b else "XX" for b in byte_mask)
            if "$" in mem_mask:
                self.logger.debug(f"\t0x{mem_addr:x}={mem_mask:s}")
        self.logger.info("... finished analyzing symbolic state.")

    def store(self, trace_file: str) -> None:
        self.logger.info(f"Start storing file '{trace_file:s}'...")
        self.logger.info(f"... finished storing file '{trace_file:s}'.")
        return


def main() -> None:
    # Argument parsing
    description = """
    Perform symbolic execution on a binary's program trace.
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("trace_file",
                        help="file containing the trace to be executed symbolically")
    parser.add_argument("--log_level",
                        choices=["critical", "error", "warning", "info", "debug"],
                        default="debug",
                        help="log level")
    args = parser.parse_args()

    # Symbolic execution
    se = Executor(Logger(args.log_level))
    se.load(args.trace_file)
    se.run()
    se.store(args.trace_file)
    return

if __name__ == "__main__":
    main()
