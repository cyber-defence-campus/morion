#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
import importlib
import inspect
import os
import pkgutil
import sys
from   morion.log    import Logger
from   morion.map    import AddressMapper
from   morion.record import Recorder
from   morion.symbex import hooking
from   triton        import ARCH, AST_REPRESENTATION, CPUSIZE, Instruction, MemoryAccess, MODE, TritonContext
from   typing        import List


class Executor:
    """
    Symbolic execution of a program trace.
    """

    def __init__(self, logger: Logger = Logger()) -> None:
        self._logger = logger
        self._recorder = Recorder(logger)
        self._addr_mapper = AddressMapper()
        self._post_processing_functions = []
        return

    def load(self, trace_file: str) -> None:
        # Load trace file
        self._logger.info(f"Start loading file '{trace_file:s}'...")
        self._recorder.load(trace_file)
        # Setup fresh Triton context
        self.ctx = TritonContext()
        self.ctx.setMode(MODE.ALIGNED_MEMORY, True)
        self.ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
        arch = self._recorder._trace["info"].get("arch", None)
        if arch in ["armv6", "armv7"]:
            self.ctx.setArchitecture(ARCH.ARM32)
            thumb = self._recorder._trace["info"].get("thumb", None)
            if not thumb is None:
                self.ctx.setThumb(thumb)
        else:
            self._logger.critical(f"Architecture '{arch:s}' not supported.")
            sys.exit("Unsupported architecture.")
        # Set concrete register values
        self._logger.debug("Concrete Regs:")
        regs = self._recorder._trace.get("states", {}).get("entry", {}).get("regs", {})
        for reg_name, reg_values in regs.items():
            try:
                reg = self.ctx.getRegister(reg_name)
                if not isinstance(reg_values, list): reg_values = [reg_values]
                for reg_value in reg_values:
                    if not isinstance(reg_value, int):
                        reg_value = int(reg_value, base=0)
                    self.ctx.setConcreteRegisterValue(reg, reg_value)
                    self._logger.debug(f"\t{reg_name:s}=0x{reg_value:x}")
            except:
                continue
        # Set concrete memory values
        self._logger.debug("Concrete Mems:")
        mems = self._recorder._trace.get("states", {}).get("entry", {}).get("mems", {})
        for mem_addr, mem_values in mems.items():
            try:
                if not isinstance(mem_addr, int):
                    mem_addr = int(mem_addr, base=0)
                if not isinstance(mem_values, list): mem_values = [mem_values]
                for mem_value in mem_values:
                    if not isinstance(mem_value, int):
                        mem_value = int(mem_value, base=0)
                    self.ctx.setConcreteMemoryValue(mem_addr, mem_value)
                    self._logger.debug(f"\t0x{mem_addr:x}=0x{mem_value:x}")
            except:
                continue
        # Set symbolic register values
        self._logger.debug("Symbolic Regs:")
        for reg_name, reg_values in regs.items():
            try:
                reg = self.ctx.getRegister(reg_name)
                if not isinstance(reg_values, list): reg_values = [reg_values]
                if "$" in reg_values:
                    self.ctx.symbolizeRegister(reg, reg_name)
                    self._logger.debug(f"\t{reg_name:s}=$")
            except:
                continue
        # Set symbolic memory values
        self._logger.debug("Symbolic Mems:")
        for mem_addr, mem_values in mems.items():
            try:
                if not isinstance(mem_addr, int):
                    mem_addr = int(mem_addr, base=0)
                if not isinstance(mem_values, list): mem_values = [mem_values]
                if "$" in mem_values:
                    mem = MemoryAccess(mem_addr, CPUSIZE.BYTE)
                    self.ctx.symbolizeMemory(mem, f"0x{mem_addr:x}")
                    self._logger.debug(f"\t0x{mem_addr:x}=$")
            except:
                continue
        # Set hooks
        self._logger.debug("Hooks:")
        hooks = self._recorder._trace.get("hooks", {})
        if hooks is None: hooks = {}
        for lib, funs in hooks.items():
            if funs is None: funs = {}
            for fun, addrs in funs.items():
                if addrs is None: addrs = []
                for addr in addrs:
                    if addr is None: addr = {}
                    try:
                        entry = int(addr["entry"], base=16)
                        leave = int(addr["leave"], base=16)
                    except:
                        logger.warning(f"\tHook: '{lib:s}:{fun:s}' (failed)")
                        continue
                    # Register corresponding hook functions
                    for _, m_name, _ in pkgutil.iter_modules([os.path.dirname(hooking.__file__)]):
                        if m_name != lib: continue
                        module = importlib.import_module(f"morion.symbex.hooking.{m_name:s}")
                        classes = inspect.getmembers(module, predicate=inspect.isclass)
                        for c_name, c in classes:
                            if c_name != fun: continue

                            # Instantiate class
                            ci = c(f"{m_name:s}:{c_name:s}", entry, leave, self._logger)

                            # Register hook at entry address
                            self._addr_mapper.add(addr=entry,
                                                symbol=f"{m_name:s}:{c_name:s} (entry)",
                                                function=ci.on_entry,
                                                return_addr=leave)
                            self._logger.debug(f"\t0x{entry:x} '{m_name:s}:{c_name:s} (entry)'")

                            # Register hook at leave address
                            self._addr_mapper.add(addr=leave,
                                                symbol=f"{m_name:s}:{c_name:s} (leave)",
                                                function=ci.on_leave,
                                                return_addr=None)
                            self._logger.debug(f"\t0x{leave:x} '{m_name:s}:{c_name:s} (leave)'")
        self._logger.info(f"... finished loading file '{trace_file:s}'.")
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
            self._logger.debug("".join(item.ljust(36) for item in line))

            # Post-process instruction
            for post_processing_function in self._post_processing_functions:
                post_processing_function(inst)
        except Exception as e:
            self._logger.error(f"Failed to symbolically execute instruction '0x{addr:x} {disassembly:s}': {str(e):s}")
            return False
        return is_supported

    def run(self) -> None:
        # Symbolic execution
        self._logger.info(f"Start symbolic execution...")
        for addr, opcode, disassembly, comment in self._recorder.get_trace():
            # Decode instruction
            try:
                if not isinstance(addr, int):
                    addr = int(addr, base=0)
                opcode = bytes.fromhex(opcode.replace(" ", ""))
            except Exception as e:
                self._logger.critical(f"Failed to read instruction from trace file: {str(e):s}")
                return

            # Execute hook functions
            hook_funs, hook_return_addr = self._addr_mapper.get_hooks(addr)
            for hook_fun in hook_funs:
                hook_symbols = self._addr_mapper.get_symbols(addr)
                hook_symbols = ", ".join(s for s in hook_symbols if s)
                if hook_return_addr is not None:
                    self._logger.debug(f"--- Hook: '{hook_symbols:s}'", color="yellow")
                    self._logger.debug(f"---       '{hook_fun.__self__.synopsis:s}'", color="yellow")
                hook_fun(self.ctx)
                if hook_return_addr is None:
                    self._logger.debug(f"--- Hook: '{hook_symbols:s}'", color="yellow")

            # Symbolic execution
            if not self.__step(addr, opcode, disassembly, comment):
                break
        self._logger.info(f"... finished symbolic execution.")

        # Symbolic state
        self._logger.info("Start analyzing symbolic state...")
        self._logger.debug("Symbolic Regs:")
        for reg_id in sorted(self.ctx.getSymbolicRegisters().keys()):
            reg = self.ctx.getRegister(reg_id)
            reg_name = reg.getName()
            byte_mask = self.__is_register_symbolic(reg_name)
            reg_mask = "".join("$$" if b else "XX" for b in byte_mask)
            if "$" in reg_mask:
                self._logger.debug(f"\t{reg_name:s}={reg_mask:s}")
        self._logger.debug("Symbolic Mems:")
        for mem_addr in sorted(self.ctx.getSymbolicMemory().keys()):
            byte_mask = self.__is_memory_symbolic(mem_addr)
            mem_mask = "".join("$$" if b else "XX" for b in byte_mask)
            if "$" in mem_mask:
                self._logger.debug(f"\t0x{mem_addr:x}={mem_mask:s}")
        self._logger.info("... finished analyzing symbolic state.")

    def store(self, trace_file: str) -> None:
        self._logger.info(f"Start storing file '{trace_file:s}'...")
        self._logger.info(f"... finished storing file '{trace_file:s}'.")
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
