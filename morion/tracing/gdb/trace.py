#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import gdb
import importlib
import inspect
import os
import pkgutil
import re
import string
import sys
from   morion.log         import Logger
from   morion.map         import AddressMapper
from   morion.record      import Recorder
from   morion.tracing.gdb import hooking
from   triton             import ARCH, AST_REPRESENTATION, CPUSIZE, EXCEPTION, Instruction, MODE, OPCODE, OPERAND, TritonContext
from   typing             import Tuple


logger = Logger()


class GdbHelper:
    """
    Helper functions to interact with GDB.
    """
    @staticmethod
    def get_byteorder() -> str:
        cpsr = int(gdb.parse_and_eval("$cpsr"))
        return "big" if (cpsr & 0x100) != 0x0 else "little"
    
    @staticmethod
    def get_architecture() -> str:
        frame = gdb.selected_frame()
        arch  = frame.architecture().name()
        return arch

    @staticmethod
    def get_thumb_state() -> bool:
        cpsr = int(gdb.parse_and_eval("$cpsr"))
        return (cpsr & 0x20) != 0x0
    
    @staticmethod
    def get_register_value(reg_name: str) -> int:

        def get_reg_val(reg_name: str) -> int:
            value = gdb.parse_and_eval(f"${reg_name:s}")
            return int(value.cast(gdb.lookup_type('unsigned int')))

        arch = GdbHelper.get_architecture()
        if arch in ["armv6", "armv7"]:
            # CPSR negative flag
            if reg_name == 'n':
                cpsr = get_reg_val("cpsr")
                return cpsr >> 31 & 1
            # CPSR zero flag
            elif reg_name == 'z':
                cpsr = get_reg_val("cpsr")
                return cpsr >> 30 & 1
            # CPSR carry flag
            elif reg_name == 'c':
                cpsr = get_reg_val("cpsr")
                return cpsr >> 29 & 1
            # CPSR overflow flag
            elif reg_name == 'v':
                cpsr = get_reg_val("cpsr")
                return cpsr >> 28 & 1
        return get_reg_val(reg_name)

    @staticmethod
    def set_register_value(reg_name: str, reg_value: int) -> None:
        gdb.parse_and_eval(f"${reg_name:s} = {reg_value:d}")
        return

    @staticmethod
    def get_memory_bytes(mem_addr: int, mem_size: int = CPUSIZE.QWORD) -> bytes:
        v = b""
        if not mem_addr: return v
        for i in range(mem_size):
            # Examine byte at address `mem_addr+i`
            b = gdb.execute(f"x/1xb {mem_addr+i:d}", to_string=True)
            # Parse byte value
            pattern = r"^0x[0-9a-fA-F]+[^:]*:\s*0x([0-9a-fA-F]{1,2})$"
            match = re.match(pattern, b)
            if match is None:
                logger.error(f"Failed to parse byte at address 0x{mem_addr+i:08x}: '{b:s}'")
                break
            v += bytes.fromhex(match.group(1))
        return v
 
    @staticmethod
    def get_memory_value(mem_addr: int, mem_size: int = CPUSIZE.QWORD) -> int:
        v = GdbHelper.get_memory_bytes(mem_addr, mem_size)
        # Transfor bytes to unsigned integer respecting endianess
        mem_value = int.from_bytes(v, byteorder=GdbHelper.get_byteorder(), signed=False)
        return mem_value

    @staticmethod
    def set_memory_value(mem_addr: int, mem_value: int) -> None:
        gdb.parse_and_eval(f"{{unsigned char}} 0x{mem_addr:x} = 0x{mem_value:x}")
        return
    
    @staticmethod
    def get_memory_string(mem_addr: int) -> str:
        s = ""
        if not mem_addr: return s
        while True:
            # Examine byte at address `mem_addr`
            b = gdb.execute(f"x/1xb {mem_addr:d}", to_string=True)
            # Parse byte value
            pattern = r"^0x[0-9a-fA-F]+[^:]*:\s*0x([0-9a-fA-F]{1,2})$"
            match = re.match(pattern, b)
            if match is None:
                logger.error(f"Failed to parse byte at address 0x{mem_addr:08x}: '{b:s}'")
                break
            # Terminate at a null byte
            b = match.group(1)
            if b == '00':
                break
            # Decode value to UTF-8 string
            b = bytes.fromhex(match.group(1))
            b = b.decode("utf-8", errors="replace")
            # Step towards next null byte
            s += b
            mem_addr += 1
        return s

    @staticmethod
    def parse_register_name(reg_name: object) -> str:
        """Helper function that translates register names to the ones used by Triton.
        """
        reg_name_str = str(reg_name).strip().lower()

        arch = GdbHelper.get_architecture()
        if arch in ["armv6", "armv7"]:
            reg_aliases = {
                "sb": "r9",
                "sl": "r10",
                "fp": "r11",
                "ip": "r12",
                "r13": "sp",
                "lr": "r14",
                "r15": "pc"
            }
            if reg_name_str in reg_aliases:
                reg_name_str = reg_aliases[reg_name_str]

        return reg_name_str

    @staticmethod
    def parse_memory_address(mem_addr: object) -> int:
        """Helper function that parses memory addresses. It supports memory addresses calculated
        based on register values (see examples below).

        Examples:
            - 0                 (decimal integer)
            - 0x00              (hexadecimal integer)
            - '0x00'            (hexadecimal integer as string)
            - '[sp+0]'          (single register with decimal offset)
            - '[sp-0x0]'        (single register with hexadecimal offset)
            - '[sp+4-fp-0x0]'   (multiple registers/offsets)
        """
        mem_addr_int = 0
        mem_addr_str = str(mem_addr)
        try:
            mem_addr_int = int(mem_addr_str, base=0)
        except:
            mem_addr_str = mem_addr_str.translate({ord(c): None for c in string.whitespace})
            m = re.fullmatch(r"\[([^\]]+)\]", mem_addr_str)
            if m is None:
                raise Exception(f"Failed to parse memory address '{mem_addr_str:s}'")
            terms = [m for m in re.finditer(r"([+-])?([^+-]+)", m.group(1), flags=re.VERBOSE)]
            for term in terms:
                sign, term = term.groups()
                try:
                    value = int(term, base=0)
                except:
                    try:
                        value = GdbHelper.get_register_value(term)
                    except Exception as e:
                        raise Exception(f"Failed to parse memory address '{mem_addr_str:s}': {str(e):s}")
                if sign == "-":
                    mem_addr_int -+ value
                else:
                    mem_addr_int += value
        return mem_addr_int

    @staticmethod
    def get_instruction(addr: int = None) -> Tuple[int, bytes, str]:
        # Get opcodes at given address (or program counter)
        try:
            if addr is None:
                addr = GdbHelper.get_register_value("pc")
            border = GdbHelper.get_byteorder()
            opcode = GdbHelper.get_memory_value(addr, CPUSIZE.DWORD)
            opcode = opcode.to_bytes(CPUSIZE.DWORD, byteorder=border)
        except Exception as e:
            logger.error(f"Failed to load opcodes at address 0x{addr:08x}: '{str(e):s}'")
            return None, None, None
        # Get source code line (if available)
        try:
            gdbout = gdb.execute(f"list *0x{addr:x}, *0x{addr:x}", to_string=True)
            gdbout = gdbout.splitlines()[1]
            rmatch = re.match(r"^([0-9]+)\t\s*(.*)$", gdbout)
            code   = f"L{rmatch.group(1)}: `{rmatch.group(2):s}`"
        except Exception as e:
            code = ""
        return addr, opcode, code


class GdbTraceCommand(gdb.Command):
    """
    GDB command to trace (part of) a binary's execution.
    """
    def __init__(self, name: str) -> None:
        super().__init__(name, gdb.COMMAND_OBSCURE)
        self._name = name
        return

    def _parse_args(self, args: str) -> bool:
        try:
            argv = gdb.string_to_argv(args)
            if len(argv) <= 1:
                raise Exception("Invalid number of arguments.")
            c = 0
            # Parse debug flag
            global logger
            if argv[c] == "debug":
                logger = Logger("debug")
                c += 1
            else:
                logger = Logger("info")
            # Parse trace file
            self._tracer = GdbTracer()
            self._trace_file = argv[c]
            if not self._tracer.load(argv[c]):
                raise Exception("Cannot load trace file.")
            c += 1
            # Parse stop addresses
            if self._tracer.add_stop_addrs([int(arg, base=0) for arg in argv[c:]]) <= 0:
                raise Exception("No valid stop address.")
        except:
            usage = """Usage:
            {cmd_name:s} [debug] <trace_file_yaml:str> <stop_addr:int> [<stop_addr:int> [...]]
            """
            print(usage.format(cmd_name=self._name))
            return False
        return True

    def invoke(self, args: str, from_tty: bool) -> bool:
        # Parse command arguments
        if not self._parse_args(args):
            return False

        # Run tracer
        if not self._tracer.run():
            return False

        # Store trace file
        return self._tracer.store_trace_file(self._trace_file)


class GdbTracer:
    """
    Trace (part of) a binary's execution.
    """
    def __init__(self) -> None:
        self._accessed_regs = {}
        self._accessed_mems = {}
        self._stop_addrs = []
        self._recorder = Recorder(logger)
        self._addr_mapper = AddressMapper()
        return

    def _init_context(self) -> TritonContext:
        ctx = TritonContext()
        ctx.setMode(MODE.ALIGNED_MEMORY, True)
        ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
        arch = GdbHelper.get_architecture()
        if arch in ["armv6", "armv7"]:
            ctx.setArchitecture(ARCH.ARM32)
            ctx.setThumb(GdbHelper.get_thumb_state())
        else:
            logger.critical(f"Architecture '{arch:s}' not supported.")
            sys.exit("Unsupported architecture.")
        return ctx
    
    def run(self) -> bool:
        logger.info("Start tracing...")
        # Store architecture information
        info = {
            "arch": GdbHelper.get_architecture()
        }
        if info["arch"] in ["armv6", "armv7"]:
            info["thumb"] = GdbHelper.get_thumb_state()
        self._recorder.add_info(**info)
        
        # Store initial program counter value
        pc = GdbHelper.get_register_value("pc")
        self._accessed_regs["pc"] = pc
        self._recorder.add_address(pc, True)

        def execute_hook_functions(inst: Instruction) -> bool:
            addr = inst.getAddress()
            entry_hook_funs, hook_return_addr = self._addr_mapper.get_hooks(addr)
            leave_hook_funs, _ = self._addr_mapper.get_hooks(hook_return_addr)
            if hook_return_addr is not None:
                # Execute entry hooks
                for entry_hook_fun in entry_hook_funs:
                    symbols = self._addr_mapper.get_symbols(addr)
                    symbols = ", ".join(s for s in symbols if s)
                    logger.info(f"--> Hook: '{symbols:s}'")
                    logger.info(f"          '{entry_hook_fun.__self__.synopsis:s}'")
                    for addr, opcode, disassembly, comment in entry_hook_fun():
                        self._recorder.add_instruction(addr, opcode, disassembly, f"// Hook: {comment:s}")
                    logger.info(f"   ---")
                
                # Run concrete execution till return address
                gdb.execute(f"tbreak *{hook_return_addr:d}")
                gdb.execute(f"continue")

                # Execute leave hooks
                for leave_hook_fun in leave_hook_funs:
                    symbols = self._addr_mapper.get_symbols(hook_return_addr)
                    symbols = ", ".join(s for s in symbols if s)
                    for addr, opcode, disassembly, comment in leave_hook_fun():
                        self._recorder.add_instruction(addr, opcode, disassembly, f"// Hook: {comment:s}")
                    logger.info(f"<-- Hook: '{symbols:s}'")

                # Address was hooked
                return True

            # Address was not hooked
            return False

        def process_instruction(inst: Instruction, ctx: TritonContext = None) -> bool:
            # Disassembling
            if ctx is None: ctx = self._init_context()
            try:
                ctx.disassembly(inst)
            except Exception as e:
                logger.error(f"Failed to disassemble instruction at address 0x{inst.getAddress():08x}: '{str(e):s}'")
                return False
            # Building semantics
            res = ctx.buildSemantics(inst)
            if res != EXCEPTION.NO_FAULT:
                logger.error(f"Failed to build semantics for the instruction at address 0x{inst.getAddress():08x}: {res:d}")
                return False
            return True

        def record_reg_mem_accesses(inst: Instruction, code: str = "") -> Tuple[bool, TritonContext]:
            # Create fresh context
            rctx = self._init_context()
            mctx = self._init_context()

            # Process instruction  (fresh context)
            if not process_instruction(inst, rctx): return False, mctx
            self._recorder.add_instruction(inst.getAddress(), inst.getOpcode(), inst.getDisassembly(), code)

            # Identify accessed registers
            logger.debug("Regs:")
            def process_register(reg: "Register") -> None:
                reg_name = reg.getName()
                if reg_name.lower() == "unknown": return
                try:
                    reg_value = GdbHelper.get_register_value(reg_name)
                    # Store register value on first access
                    if reg_name not in self._accessed_regs:
                        self._accessed_regs[reg_name] = reg_value
                        self._recorder.add_concrete_register(reg_name, reg_value, is_entry=True)
                        logger.debug(f"\t{reg_name:s} = 0x{reg_value:x}")
                    # Set register value in context
                    mctx.setConcreteRegisterValue(reg, reg_value)
                    mctx.concretizeRegister(reg)
                except Exception as e:
                    logger.error(f"\tFailed to process register {reg_name:s}: '{str(e):s}'")

            for reg, _ in inst.getReadRegisters():
                process_register(reg)
            for op in inst.getOperands():
                op_type = op.getType()
                if op_type == OPERAND.REG:
                    process_register(op)
                elif op_type == OPERAND.MEM:
                    process_register(op.getBaseRegister())
                    process_register(op.getIndexRegister())
                    process_register(op.getSegmentRegister())

            # Process instruction (registers concretized)
            if not process_instruction(inst, mctx): return False, mctx

            # Identify accessed memory
            logger.debug("Mems:")
            for mem, _ in inst.getLoadAccess():
                mem_addr = mem.getAddress()
                mem_size = mem.getSize()
                for i in range(mem_size):
                    try:
                        # Store memory value on first access
                        if mem_addr+i not in self._accessed_mems:
                            mem_value = GdbHelper.get_memory_value(mem_addr+i, CPUSIZE.BYTE)
                            mem_value_chr = chr(mem_value) if 33 <= mem_value <= 126 else ' '
                            self._accessed_mems[mem_addr+i] = mem_value
                            self._recorder.add_concrete_memory(mem_addr+i, mem_value, is_entry=True)
                            logger.debug(f"\t0x{mem_addr+i:08x} = 0x{mem_value:02x} {mem_value_chr:s}")
                    except Exception as e:
                        logger.error(f"\tFailed to process memory at address 0x{mem_addr+i:08x}: '{str(e):s}'")
            return True, mctx

        try:
            while True:
                # Get next instruction
                pc, opcode, code = GdbHelper.get_instruction()

                # Stop condition
                if not pc or pc in self._stop_addrs: break
                inst = Instruction(pc, opcode)

                # Execute potential hook functions
                is_hooked = execute_hook_functions(inst)
                if is_hooked: continue

                # Record accessed registers and memory locations
                success, ctx = record_reg_mem_accesses(inst, code)
                if not success: break

                # Handle ARM32 IT instructions
                # NOTE: Hooking instructions within an ARM32 IT block is not supported
                if inst.getType() == OPCODE.ARM32.IT:
                    # Parse condition switches from disassembly
                    rmatch = re.match(r"^i(t[te]{0,3})\s", inst.getDisassembly())

                    # Store instructions within IT block
                    addr     = pc
                    opcode   = inst.getOpcode()
                    it_block = {}
                    for condition in rmatch.group(1):
                        addr, opcode, code = GdbHelper.get_instruction(addr + len(opcode))
                        inst = Instruction(addr, opcode)
                        process_instruction(inst)
                        it_block[addr] = (condition, inst, code, False)
                        opcode = inst.getOpcode()

                    # Record instructions within IT block
                    while True:
                        # Step through instructions inside IT block
                        gdb.execute("stepi")
                        pc = GdbHelper.get_register_value("pc")
                        for addr, (condition, inst, code, recorded) in it_block.items():
                            # Record non-executed instruction (without register and memory accesses)
                            if not recorded and addr < pc:
                                opcode = inst.getOpcode()
                                disas  = inst.getDisassembly()
                                if code: code += " "
                                code = f"{code:s}// IT Block: Instruction not exectued"
                                self._recorder.add_instruction(addr, opcode, disas, code)
                                it_block[addr] = (condition, inst, code, True)
                            # Record executed instruction (with register and memory acccesses)
                            elif not recorded and addr == pc:
                                if code: code += " "
                                code = f"{code:s}// IT Block: Instruction executed"
                                record_reg_mem_accesses(inst, code)
                                it_block[addr] = (condition, inst, code, True)
                        # Program counter left IT block
                        if not pc in it_block:
                            break
                else:
                    # Step over instruction
                    gdb.execute("stepi")

            # Store accessed registers at leave
            for reg_name, _ in self._recorder._trace["states"]["entry"]["regs"].items():
                reg_name = GdbHelper.parse_register_name(reg_name)
                reg_value = GdbHelper.get_register_value(reg_name)
                self._recorder.add_concrete_register(reg_name, reg_value, is_entry=False)

            # Store accessed memory at leave
            for mem_addr, _ in self._recorder._trace["states"]["entry"]["mems"].items():
                mem_addr = int(mem_addr, base=0)
                mem_value = GdbHelper.get_memory_value(mem_addr, CPUSIZE.BYTE)
                self._recorder.add_concrete_memory(mem_addr, mem_value, is_entry=False)

        except Exception as e:
            logger.error(f"\tFailed to execute instruction at address 0x{pc:08x}: '{str(e):s}'")
        finally:
            self._recorder.add_address(pc, False)
            self._stop_addrs.clear()
            logger.info(f"... finished tracing (pc=0x{pc:08x}).")
        return True

    def load(self, trace_file: str) -> bool:
        # Load trace file
        logger.info(f"Start loading trace file '{trace_file:s}'...")
        if not self._recorder.load(trace_file):
            return False
        # Empty instructions
        self._recorder._trace["trace"]["instructions"] = []
        # Setup registers
        logger.debug("Regs:")
        regs = self._recorder._trace.get("states", {}).get("entry", {}).get("regs", {}).copy()
        for reg_name, reg_values in regs.items():
            reg_alias = GdbHelper.parse_register_name(reg_name)
            if reg_name != reg_alias:
                rs = self._recorder._trace.get("states", {}).get("entry", {}).get("regs", {})
                r = rs.get(reg_name, {})
                del rs[reg_name]
                reg_name = reg_alias
                rs[reg_name] = r
            if not isinstance(reg_values, list): reg_values = [reg_values]
            # Set concrete register values
            for reg_value in reg_values:
                try:
                    reg_value = str(reg_value)
                    reg_value = int(reg_value, base=0)
                    GdbHelper.set_register_value(reg_name, reg_value)
                    logger.debug(f"\t{reg_name:s}=0x{reg_value:x}")
                except Exception as e:
                    if not "$$" in reg_value:
                        logger.warning(f"Failed to set register '{reg_name:s}': {str(e):s}")
            # Record register accesses
            try:
                reg_value = GdbHelper.get_register_value(reg_name)
                self._accessed_regs[reg_name] = reg_value
                self._recorder.add_concrete_register(reg_name, reg_value, is_entry=True)
            except Exception as e:
                logger.warning(f"Failed to record register '{reg_name:s}': {str(e):s}")
        # Setup memory
        logger.debug("Mems:")
        mems = self._recorder._trace.get("states", {}).get("entry", {}).get("mems", {}).copy()
        for mem_addr, mem_values in mems.items():
            mem_addr = str(mem_addr)
            if not isinstance(mem_values, list): mem_values = [mem_values]
            # Parse memory address
            try:
                mem_addr = GdbHelper.parse_memory_address(mem_addr)
            except Exception as e:
                logger.warning(f"Failed to parse memory address '{mem_addr:s}': {str(e):s}")
                continue
            # Set concrete memory values
            for mem_value in mem_values:
                try:
                    mem_value = str(mem_value)
                    mem_value = int(mem_value, base=0)
                    mem_value_chr = chr(mem_value) if 33 <= mem_value <= 126 else ' '
                    GdbHelper.set_memory_value(mem_addr, mem_value)
                    logger.debug(f"\t0x{mem_addr:08x} = 0x{mem_value:02x} {mem_value_chr:s}")
                except Exception as e:
                    if not mem_value == "$$":
                        logger.warning(f"Failed to set memory at address 0x{mem_addr:08x}: {str(e):s}")
            # Record memory accesses
            try:
                mem_value = GdbHelper.get_memory_value(mem_addr, CPUSIZE.BYTE)
                self._accessed_mems[mem_addr] = mem_value
                self._recorder.add_concrete_memory(mem_addr, mem_value, is_entry=True)
            except Exception as e:
                logger.warning(f"Failed to record memory at address 0x{mem_addr:08x}: {str(e):s}")
        # Setup hooks
        logger.debug("Hooks:")
        hooks = self._recorder._trace.get("hooks", {})
        if hooks is None: hooks = {}
        for lib, funs in hooks.items():
            if funs is None: funs = {}
            for fun, addrs in funs.items():
                if addrs is None: addrs = []
                for addr in addrs:
                    if addr is None: addr = {}
                    try:
                        entry  = int(addr["entry"], base=0)
                        leave  = int(addr["leave"], base=0)
                        target = int(addr.get("target", "0x1000"), base=0)
                        mode   = addr.get("mode", "skip").lower()
                    except:
                        logger.warning(f"Failed to register hook '{lib:s}:{fun:s}': invalid parameter")
                        continue
                    # Register corresponding hook functions
                    registered = False
                    for _, m_name, _ in pkgutil.iter_modules([os.path.dirname(hooking.__file__)]):
                        if m_name != lib: continue
                        module = importlib.import_module(f"morion.tracing.gdb.hooking.{m_name:s}")
                        classes = inspect.getmembers(module, predicate=inspect.isclass)
                        for c_name, c in classes:
                            if c_name != fun: continue

                            # Instantiate class
                            ci = c(f"{m_name:s}:{c_name:s}", entry, leave, target, mode, logger)

                            # Register hook at entry address
                            self._addr_mapper.add(addr=entry,
                                               symbol=f"{m_name:s}:{c_name:s} (on=entry, mode={mode:s})",
                                               function=ci.on_entry,
                                               return_addr=leave)
                            logger.debug(f"\t0x{entry:08x} '{m_name:s}:{c_name:s} (on=entry, mode={mode:s})'")

                            # Register hook at leave address
                            self._addr_mapper.add(addr=leave,
                                               symbol=f"{m_name:s}:{c_name:s} (on=leave, mode={mode:s})",
                                               function=ci.on_leave,
                                               return_addr=None)
                            logger.debug(f"\t0x{leave:08x} '{m_name:s}:{c_name:s} (on=leave, mode={mode:s})'")
                            registered = True
                    if not registered:
                        logger.warning(f"Failed to register hook '{lib:s}:{fun:s}': library or function not found")
        logger.info(f"... finished loading trace file '{trace_file:s}'.")
        return True

    def store_trace_file(self, trace_file: str) -> bool:
        logger.info(f"Start storing trace file '{trace_file:s}'...")
        result = self._recorder.store(trace_file)
        logger.info(f"... finished storing trace file '{trace_file:s}'.")
        return result

    def add_stop_addrs(self, addrs: list) -> int:
        self._stop_addrs.extend(addrs)
        return len(self._stop_addrs)

    
if __name__ == "__main__":
    # GDB settings
    gdb.execute(f"set pagination off")
    gdb.execute(f"set disassembly-flavor intel")
    
    # Register commands in GDB
    GdbTraceCommand("morion_trace")
