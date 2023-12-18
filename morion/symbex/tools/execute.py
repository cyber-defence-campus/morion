#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
import importlib
import inspect
import os
import pkgutil
import re
import string
import sys
from   morion.interact                      import Shell
from   morion.log                           import Logger
from   morion.map                           import AddressMapper
from   morion.record                        import Recorder
from   morion.symbex                        import hooking
from   morion.symbex.analysis.vulnerability import VulnerabilityAnalysis
from   morion.symbex.help                   import SymbexHelper
from   triton                               import ARCH, AST_REPRESENTATION, CPUSIZE, EXCEPTION, Instruction
from   triton                               import MemoryAccess, MODE, TritonContext
from   typing                               import List

class Executor:
    """
    Symbolic execution of a program trace.
    """

    def __init__(self, logger: Logger = Logger()) -> None:
        self._logger = logger
        self._recorder = Recorder(logger)
        self._addr_mapper = AddressMapper()
        self._pre_processing_functions = []
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
        # Setup registers
        self._logger.debug("Regs:")
        regs = self._recorder._trace.get("states", {}).get("entry", {}).get("regs", {}).copy()
        for reg_name, reg_values in regs.items():
            reg_alias = SymbexHelper.parse_register_name(reg_name, self.ctx)
            if reg_name != reg_alias:
                rs = self._recorder._trace.get("states", {}).get("entry", {}).get("regs", {})
                r = rs.get(reg_name, {})
                del rs[reg_name]
                reg_name = reg_alias
                rs[reg_name] = r
            if not isinstance(reg_values, list): reg_values = [reg_values]
            # Access register
            try:
                reg = self.ctx.getRegister(reg_name)
            except:
                self._logger.warning(f"Failed to access register with name '{reg_name:s}'")
                continue
            # Set concrete register values
            for reg_value in reg_values:
                try:
                    reg_value = str(reg_value)
                    reg_value = int(reg_value, base=0)
                    self.ctx.setConcreteRegisterValue(reg, reg_value)
                    self._logger.debug(f"\t{reg_name:s}=0x{reg_value:x}")
                except Exception as e:
                    if not "$$" in reg_value:
                        self._logger.warning(f"Failed to set register '{reg_name}': {str(e):s}")
            # Make register symbolic
            if any("$$" in str(reg_value) for reg_value in reg_values):
                try:
                    reg_size = reg.getSize()
                    self.ctx.symbolizeRegister(reg, SymbexHelper.create_symvar_alias(reg_name=reg_name))
                    self._logger.debug(f"\t{reg_name:s}={'$$'*reg_size}")
                except Exception as e:
                    self._logger.warning(f"Failed to symbolize register '{reg_name:s}': {str(e):s}")
        # Setup memory
        self._logger.debug("Mems:")
        mems = self._recorder._trace.get("states", {}).get("entry", {}).get("mems", {}).copy()
        for mem_addr, mem_values in mems.items():
            mem_addr = str(mem_addr)
            if not isinstance(mem_values, list): mem_values = [mem_values]
            # Parse memory address
            try:
                mem_addr = SymbexHelper.parse_memory_address(mem_addr, self.ctx)
            except Exception as e:
                self._logger.warning(f"Failed to parse memory address '{mem_addr:s}': {str(e):s}")
                continue
            # Set concrete memory values
            for mem_value in mem_values:
                try:
                    mem_value = str(mem_value)
                    mem_value = int(mem_value, base=0)
                    mem_value_chr = chr(mem_value) if 33 <= mem_value <= 126 else ' '
                    self.ctx.setConcreteMemoryValue(mem_addr, mem_value)
                    self._logger.debug(f"\t0x{mem_addr:08x}=0x{mem_value:02x} {mem_value_chr:s}")
                except Exception as e:
                    if not mem_value == "$$":
                        self._logger.warning(f"Failed to set memory at address '0x{mem_addr:08x}': {str(e):s}")
            # Set symbolic memory values
            if "$$" in mem_values:
                try:
                    mem = MemoryAccess(mem_addr, CPUSIZE.BYTE)
                    self.ctx.symbolizeMemory(mem, SymbexHelper.create_symvar_alias(mem_addr=mem_addr))
                    self._logger.debug(f"\t0x{mem_addr:08x}=$$")
                except Exception as e:
                    self._logger.warning(f"Failed to symbolize memory at address '0x{mem_addr:08x}': {str(e):s}")
        # Setup hooks
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
                        mode = addr.get("mode", "skip").lower()
                    except:
                        self._logger.warning(f"\tHook: '{lib:s}:{fun:s}' (failed)")
                        continue
                    # Register corresponding hook functions
                    for _, m_name, _ in pkgutil.iter_modules([os.path.dirname(hooking.__file__)]):
                        if m_name != lib: continue
                        module = importlib.import_module(f"morion.symbex.hooking.{m_name:s}")
                        classes = inspect.getmembers(module, predicate=inspect.isclass)
                        for c_name, c in classes:
                            if c_name != fun: continue

                            # Instantiate class
                            ci = c(f"{m_name:s}:{c_name:s}", entry, leave, mode, self._logger)

                            # Register hook at entry address
                            self._addr_mapper.add(addr=entry,
                                                symbol=f"{m_name:s}:{c_name:s} (on=entry, mode={mode:s})",
                                                function=ci.on_entry,
                                                return_addr=leave)
                            self._logger.debug(f"\t0x{entry:08x}: '{m_name:s}:{c_name:s} (on=entry, mode={mode:s})'")

                            # Register hook at leave address
                            self._addr_mapper.add(addr=leave,
                                                symbol=f"{m_name:s}:{c_name:s} (on=leave, mode={mode:s})",
                                                function=ci.on_leave,
                                                return_addr=None)
                            self._logger.debug(f"\t0x{leave:08x}: '{m_name:s}:{c_name:s} (on=leave, mode={mode:s})'")
        self._logger.info(f"... finished loading file '{trace_file:s}'.")
        return

    def _is_controllable(self, ast, val: int, byte_size: int) -> List[bool]:
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

    def _is_register_symbolic(self, reg_name: str) -> List[bool]:
        reg = self.ctx.getRegister(reg_name)
        reg_size = reg.getSize()
        byte_mask = [False] * reg_size
        # Register AST contains symbolic variables
        if self.ctx.isRegisterSymbolized(reg) and reg_size > 0:
            reg_ast = self.ctx.getRegisterAst(reg)
            reg_val = self.ctx.getConcreteRegisterValue(reg)
            byte_mask = self._is_controllable(reg_ast, reg_val, reg_size)
        return byte_mask

    def _is_memory_symbolic(self, mem_addr: int, mem_size: int = CPUSIZE.BYTE) -> List[bool]:
        mem = MemoryAccess(mem_addr, mem_size)
        byte_mask = [False] * mem_size
        # Memory AST contains symbolic variables
        if self.ctx.isMemorySymbolized(mem) and mem_size > 0:
            mem_ast = self.ctx.getMemoryAst(mem)
            mem_val = self.ctx.getConcreteMemoryValue(mem)
            byte_mask = self._is_controllable(mem_ast, mem_val, mem_size)
        return byte_mask
    
    def _hook(self, addr: int) -> None:
        hook_funs, hook_return_addr = self._addr_mapper.get_hooks(addr)
        for hook_fun in hook_funs:
            hook_symbols = self._addr_mapper.get_symbols(addr)
            hook_symbols = ", ".join(s for s in hook_symbols if s)
            if hook_return_addr is not None:
                self._logger.debug(f"--> Hook: '{hook_symbols:s}'")
                self._logger.debug(f"          '{hook_fun.__self__.synopsis:s}'")
                self.inside_hook = True
            hook_fun(self.ctx)
            self._logger.debug(f"    ---")
            if hook_return_addr is None and self.inside_hook:
                self._logger.debug(f"<-- Hook: '{hook_symbols:s}'")
                self.inside_hook = False
        return

    def _step(self, addr: int, opcode: bytes, disassembly: str, comment: str = None) -> bool:
        try:
            # Create instruction
            inst = Instruction(addr, opcode)

            # Disassemble instruction
            self.ctx.disassembly(inst)
            disassembly = inst.getDisassembly()

            # Pre-process instruction
            for pre_processing_function in self._pre_processing_functions:
                pre_processing_function(self.ctx, inst, self._logger, "PRE")

            # Build instruction semantics
            is_supported = self.ctx.buildSemantics(inst) == EXCEPTION.NO_FAULT

            # Increment instruction counter
            SymbexHelper.inst_cnt += 1

            # Log instruction
            inst_addr = f"0x{addr:08x}"
            inst_opcode = opcode.hex()
            inst_opcode = " ".join(a+b for a, b in zip(inst_opcode[::2], inst_opcode[1::2]))
            inst_line = [f"{inst_addr:s} ({inst_opcode:s}): {disassembly:s}", f"# {comment:s}"]
            self._logger.debug("".join(item.ljust(50) for item in inst_line), color="cyan")

            # Post-process instruction
            for post_processing_function in self._post_processing_functions:
                post_processing_function(self.ctx, inst, self._logger, "POST")
        except Exception as e:
            self._logger.error(f"Failed to symbolically execute instruction '0x{addr:x}: {disassembly:s}': {str(e):s}")
            return False
        return is_supported
        
    def run(self, args: dict = {}, exe_last_inst: bool = True) -> None:
        # Initialization
        self.stepping = args.get("stepping", False)
        VulnerabilityAnalysis.disallow_user_inputs = args.get("disallow_user_inputs", True)
        VulnerabilityAnalysis.analysis_history = {}
        self.inside_hook = False

        # Symbolic execution
        self._logger.info(f"Start symbolic execution...")
        pc = self._recorder.get_entry_address()
        stop_addr = self._recorder.get_leave_address()
        insts = self._recorder.get_instructions().copy()
        if not exe_last_inst: insts.pop()
        for addr, opcode, disassembly, comment in insts:
            # Parse instruction address and opcode
            try:
                addr = int(addr, base=16)
                opcode = bytes.fromhex(opcode.replace(" ", ""))
            except:
                self._logger.error("Failed to parse instruction address and/or opcode.")
                break

            # Validate trace synchronization
            if addr != pc:
                self._logger.error(f"Trace desynchronized: CON.PC 0x{addr:08x} != 0x{pc:08x} SYM.PC")
                break

            # Execute potential hooks
            self._hook(pc)

            # Symbolic execution
            if not self._step(pc, opcode, disassembly, comment): break
            if self.stepping:
                Shell.interact("Use 'se.stepping = False' to disable stepping.", se=self)

            # Upgrade program counter
            pc = self.ctx.getConcreteRegisterValue(self.ctx.registers.pc)

        # Validate stop address
        if pc != stop_addr:
            self._logger.error(f"Not terminated at a stop address: pc=0x{pc:08x}")
        self._logger.info(f"... finished symbolic execution (pc=0x{pc:08x}).")

        # Analyze symbolic state
        self.skip_state_analysis = args.get("skip_state_analysis", False)
        if self.skip_state_analysis: return
        self._logger.info("Start analyzing symbolic state...")
        self._logger.info("Symbolic Regs:", color="magenta")
        reg_names = set()
        # Process symbolic registers
        for reg_id in self.ctx.getSymbolicRegisters().keys():
            reg = self.ctx.getRegister(reg_id)
            reg_names.add(reg.getName())
        # Process registers accessed in entry state
        for reg_name, _ in self._recorder._trace["states"]["entry"]["regs"].items():
            reg_name = SymbexHelper.parse_register_name(reg_name, self.ctx)
            reg_names.add(reg_name)
        # Process registers
        for reg_name in sorted(reg_names):
            reg = self.ctx.getRegister(reg_name)
            reg_value = self.ctx.getConcreteRegisterValue(reg)
            byte_mask = self._is_register_symbolic(reg_name)
            reg_mask = "".join("$$" if b else "XX" for b in byte_mask)
            is_symbolic = "$$" in reg_mask
            self._recorder.add_concrete_register(reg_name, reg_value, is_entry=False)
            if is_symbolic:
                self._recorder.add_symbolic_register(reg_name, len(byte_mask), is_entry=False)
                self._logger.info(f"\t{reg_name:s}={reg_mask:s}", color="magenta")
        self._logger.info("Symbolic Mems:", color="magenta")
        mem_addrs = set()
        # Process symbolic memory addresses
        for mem_addr in self.ctx.getSymbolicMemory().keys():
            mem_addrs.add(mem_addr)
        # Process memory addresses accessed in entry state
        for mem_addr, _ in self._recorder._trace["states"]["entry"]["mems"].items():
            try:
                if not isinstance(mem_addr, int):
                    mem_addr = int(mem_addr, base=0)
            except:
                continue
            mem_addrs.add(mem_addr)        
        # Process memory addresses
        sym_mem_addrs = []
        for mem_addr in sorted(mem_addrs):
            mem_value = self.ctx.getConcreteMemoryValue(mem_addr)
            byte_mask = self._is_memory_symbolic(mem_addr)
            mem_mask = "".join("$$" if b else "XX" for b in byte_mask)
            is_symbolic = "$$" in mem_mask
            self._recorder.add_concrete_memory(mem_addr, mem_value, is_entry=False)
            if is_symbolic:
                self._recorder.add_symbolic_memory(mem_addr, is_entry=False)
                sym_mem_addrs.append(mem_addr)
        idxs = [0]+[idx for idx, (i,j) in enumerate(zip(sym_mem_addrs, sym_mem_addrs[1:]),1) if j-i>1]+[len(sym_mem_addrs)+1]
        sym_mem_ranges = [sym_mem_addrs[i:j] for i, j in zip(idxs, idxs[1:])]
        for sym_mem_range in sym_mem_ranges:
            if len(sym_mem_range) == 1:
                mem_addr = sym_mem_range[0]
                byte_mask = self._is_memory_symbolic(mem_addr)
                mem_mask = "".join("$$" if b else "XX" for b in byte_mask)
                self._logger.info(f"\t0x{mem_addr:08x}={mem_mask:s}", color="magenta")
            elif len(sym_mem_range) >= 2:
                mem_addr1 = sym_mem_range[0]
                mem_addr2 = sym_mem_range[-1]
                byte_mask1 = self._is_memory_symbolic(mem_addr1)
                byte_mask2 = self._is_memory_symbolic(mem_addr2)
                mem_mask1 = "".join("$$" if b else "XX" for b in byte_mask1)
                mem_mask2 = "".join("$$" if b else "XX" for b in byte_mask2)
                self._logger.info(f"\t0x{mem_addr1:08x}={mem_mask1:s}", color="magenta")
                if len(sym_mem_range) >= 3:
                    self._logger.info("\t...", color="magenta")
                self._logger.info(f"\t0x{mem_addr2:08x}={mem_mask2:s}", color="magenta")

        self._logger.info("... finished analyzing symbolic state.")
        return

    def store(self, trace_file: str) -> None:
        self._logger.info(f"Start storing file '{trace_file:s}'...")
        self._recorder.store(trace_file)
        self._logger.info(f"... finished storing file '{trace_file:s}'.")
        return

    @staticmethod
    def get_memory_string(ctx: TritonContext, mem_addr: int) -> str:
        s = ""
        if not mem_addr: return s
        while True:
            # Examine byte at address `mem_addr`
            c = ctx.getConcreteMemoryValue(mem_addr)
            # Terminate at a null byte
            if c == 0:
                break
            # Decode value to UTF-8 string
            c = bytes.fromhex(f"{c:02x}")
            c = c.decode("utf-8", errors="replace")
            # Step towards next null byte
            s += c
            mem_addr += 1
        return s


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
    parser.add_argument("--stepping",
                        action="store_true",
                        help="open a debug shell after each instruction")
    parser.add_argument("--disallow_user_inputs",
                        action="store_true",
                        help="run without requesting the user for inputs")
    parser.add_argument("--skip_state_analysis",
                        action="store_true",
                        help="skip analyzing the symbolic state at the end of the execution")
    args = vars(parser.parse_args())

    # Symbolic execution
    se = Executor(Logger(args["log_level"]))
    se.load(args["trace_file"])
    se.run(args)
    se.store(args["trace_file"])
    return

if __name__ == "__main__":
    main()
