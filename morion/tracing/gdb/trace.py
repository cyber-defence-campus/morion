#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import gdb
import importlib
import inspect
import os
import pkgutil
import re
import sys
from   morion.log         import Logger
from   morion.record      import Recorder
from   morion.tracing.gdb import hooking
from   triton             import ARCH, AST_REPRESENTATION, CPUSIZE, Instruction, MODE, OPERAND, TritonContext


logger = Logger()


class GdbHelper:
    """
    """
    @staticmethod
    def get_byteorder() -> str:
        cpsr = int(gdb.parse_and_eval("$cpsr"))
        return "big" if (cpsr & 0x100) != 0x0 else "little"

    @staticmethod
    def get_architecture() -> str:
        frame = gdb.selected_frame()
        arch = frame.architecture()
        return arch.name()

    @staticmethod
    def get_thumb_state() -> bool:
        cpsr = int(gdb.parse_and_eval("$cpsr"))
        return (cpsr & 0x20) != 0x0

    @staticmethod
    def get_register_value(reg_name: str) -> int:
        value = gdb.parse_and_eval(f"${reg_name:s}")
        return int(value.cast(gdb.lookup_type('unsigned int')))

    @staticmethod
    def get_memory_value(mem_addr: int, mem_size: int = CPUSIZE.DWORD) -> int:
        # Examine `mem_size` bytes at address `mem_addr`
        memory = gdb.execute(f"x/{mem_size:d}xb {mem_addr:d}", to_string=True)
        # Parse address and bytes
        pattern = r"^0x([0-9a-f]+)[^:]*:" + mem_size * r"[^0x]*0x([0-9a-f]{2})" + r".*$"
        match = re.match(pattern, memory)
        # Transfor bytes to unsigned integer respecting endianess
        mem_value = bytes.fromhex(''.join(match.groups()[1:mem_size+1]))
        return int.from_bytes(mem_value, byteorder=GdbHelper.get_byteorder(), signed=False)

    @staticmethod
    def get_memory_string(addr: int) -> str:
        # Examine string at address `addr`
        memory_string = gdb.execute(f"x/s {addr:d}", to_string=True)
        # Parse string
        pattern = r"^0x[0-9a-f]+[^:]*:[^\"]*\"([^\"]*)\".*$"
        match = re.match(pattern, memory_string)
        if match is not None:
            return match.group(1)
        return ''

    @staticmethod
    def get_instruction() -> (int, bytes):
        pc = GdbHelper.get_register_value("pc")
        opcode = GdbHelper.get_memory_value(pc)
        opcode = opcode.to_bytes((opcode.bit_length() + 7) // 8, byteorder=GdbHelper.get_byteorder())
        return pc, opcode


class GdbTraceCommand(gdb.Command):
    """
    """
    def __init__(self, name: str) -> None:
        super().__init__(name, gdb.COMMAND_OBSCURE)
        self._name = name
        self._tracer = GdbTracer()
        return

    def __parse_args(self, args: str) -> bool:
        try:
            argv = gdb.string_to_argv(args)
            if len(argv) <= 1:
                raise Exception("Invalid number of arguments.")
            c = 0
            # Parse debug flag
            if argv[c] == "debug":
                global logger
                logger = Logger("debug")
                c += 1
            # Parse trace file
            self._trace_file = argv[c]
            if not self._tracer.load_trace_file(argv[c]):
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
        if not self.__parse_args(args):
            return False

        # Run tracer
        if not self._tracer.run():
            return False

        # Store trace file
        return self._tracer.store_trace_file(self._trace_file)


class GdbTracer:
    """
    """
    def __init__(self) -> None:
        self._stop_addrs = []
        self._accessed_regs = {}
        self._accessed_mems = {}
        self._addr_map = {
            # 0x0: {
            #    "symbols": ["sample"],
            #    "hooks": {
            #        "funs": [],
            #        "return_addr": 0x0
            #    }
            #}
        }
        self._recorder = Recorder(logger)
        return

    def __init_context(self) -> TritonContext:
        ctx = TritonContext()
        ctx.setMode(MODE.ALIGNED_MEMORY, True)
        ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
        arch = GdbHelper.get_architecture()
        if arch in ["armv6", "armv7"]:
            ctx.setArchitecture(ARCH.ARM32)
            ctx.setThumb(GdbHelper.get_thumb_state())
        else:
            logger.critical(f"Architecture {arch:s} not supported.")
            sys.exit("Unsupported architecture.")
        return ctx
    
    def __get_register_value(self, reg_name: str) -> int:
        arch = GdbHelper.get_architecture()
        if arch in ["armv6", "armv7"]:
            # CPSR negative flag
            if reg_name == 'n':
                cpsr = GdbHelper.get_register_value("cpsr")
                reg_value = cpsr >> 31 & 1
            # CPSR zero flag
            elif reg_name == 'z':
                cpsr = GdbHelper.get_register_value("cpsr")
                reg_value = cpsr >> 30 & 1
            # CPSR carry flag
            elif reg_name == 'c':
                cpsr = GdbHelper.get_register_value("cpsr")
                reg_value = cpsr >> 29 & 1
            # CPSR overflow flag
            elif reg_name == 'v':
                cpsr = GdbHelper.get_register_value("cpsr")
                reg_value = cpsr >> 28 & 1
            # General purpose registers
            else:
                reg_value = GdbHelper.get_register_value(reg_name)
        else:
            logger.critical(f"Architecture {arch:s} not supported.")
            sys.exit("Unsupported architecture.")
        return reg_value

    def __get_memory_value(self, mem_addr: int, mem_size: int = CPUSIZE.DWORD) -> int:
        return GdbHelper.get_memory_value(mem_addr, mem_size)

    def __process(self, inst: Instruction, ctx: TritonContext) -> bool:
        # Disassembling
        try:
            ctx.disassembly(inst)
        except Exception as exc:
            logger.error(f"Failed to disassemble instruction at address 0x{inst.getAddress():x}: '{str(exc):s}'")
            return False
        # Building semantics
        try:
            supported = ctx.buildSemantics(inst)
        except Exception as exc:
            logger.error(f"Failed to build semantics for the instruction at address 0x{inst.getAddress():x}: '{str(exc):s}'")
            return False
        return supported
    
    def run(self) -> bool:
        # Store initial program counter value
        pc = self.__get_register_value("pc")
        self._accessed_regs["pc"] = pc
        self._recorder.add_address(pc, True)

        while True:
            # Create instruction
            pc, opcode = GdbHelper.get_instruction()
            inst = Instruction(pc, opcode)

            # Stop condition
            if not pc or pc in self._stop_addrs: break

            # Hook information
            hooks = self._addr_map.get(pc, {}).get("hooks", {})
            hook_funs = hooks.get("funs", [])
            hook_reta = hooks.get("return_addr", None)
            hook_symb = ", ".join(s for s in hooks.get("symbols", []) if s)

            # Execute hook functions
            for hook_fun in hook_funs:
                hook_name = f"{hook_fun.__self__.name:s} ({hook_fun.__name__:s})"
                logger.info(f"Start hooking function '{hook_name:s}'...", color="blue")
                for addr, opcode, disassembly, comment in hook_fun():
                    self._recorder.add_instruction(addr, opcode, disassembly, comment)
                logger.info(f"... finished hooking function '{hook_name:s}'.", color="blue")

            # Skip until return address
            if hook_reta is not None:
                gdb.execute(f"tbreak *{hook_reta:d}")
                gdb.execute(f"continue")
                continue

            # Create fresh context
            rctx = self.__init_context()
            mctx = self.__init_context()

            # Process instruction  (fresh context)
            if not self.__process(inst, rctx): break
            self._recorder.add_instruction(inst.getAddress(), inst.getOpcode(), inst.getDisassembly())

            # Identify accessed registers
            logger.debug("Regs:")
            def process_register(reg: "Register") -> None:
                reg_name = reg.getName()
                if reg_name.lower() == "unknown": return
                try:
                    reg_value = self.__get_register_value(reg_name)
                    # Store register value on first access
                    if reg_name not in self._accessed_regs:
                        self._accessed_regs[reg_name] = reg_value
                        self._recorder.add_register(reg_name, reg_value, is_entry=True)
                        logger.debug(f"\t{reg_name:s} = 0x{reg_value:x}")
                    # Set register value in context
                    mctx.setConcreteRegisterValue(reg, reg_value)
                    mctx.concretizeRegister(reg)
                except Exception as exc:
                    logger.error(f"\tFailed to process register {reg_name:s}: '{str(exc):s}'")

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
            if not self.__process(inst, mctx): break

            # Identify accessed memory
            logger.debug("Mems:")
            for mem, _ in inst.getLoadAccess():
                mem_addr = mem.getAddress()
                mem_size = mem.getSize()
                for i in range(mem_size):
                    try:
                        # Store memory value on first access
                        if mem_addr+i not in self._accessed_mems:
                            mem_value = self.__get_memory_value(mem_addr+i, CPUSIZE.BYTE)
                            self._accessed_mems[mem_addr+i] = mem_value
                            self._recorder.add_memory(mem_addr+i, mem_value, is_entry=True)
                            logger.debug(f"\t0x{mem_addr+i:x} = 0x{mem_value:02x}")
                    except Exception as exc:
                        logger.error(f"\tFailed to process memory at address 0x{mem_addr+i:x}: '{str(exc):s}'")
            
            # Step over instruction
            gdb.execute("stepi")

        # Store accessed registers at leave
        for reg_name, _ in self._recorder._trace["states"]["entry"]["regs"].items():
            reg_value = self.__get_register_value(reg_name)
            self._recorder.add_register(reg_name, reg_value, is_entry=False)

        # Store accessed memory at leave
        for mem_addr, _ in self._recorder._trace["states"]["entry"]["mems"].items():
            mem_addr = int(mem_addr, base=16)
            mem_value = self.__get_memory_value(mem_addr, CPUSIZE.BYTE)
            self._recorder.add_memory(mem_addr, mem_value, is_entry=False)

        self._recorder.add_address(pc, False)
        self._stop_addrs.clear()
        return True

    def load_trace_file(self, trace_file: str) -> bool:
        # Load file
        if not self._recorder.load(trace_file):
            return False
        # Register hooks
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
                        logger.warning(f"Failed to hook {lib:s}.{fun:s}.")
                        continue
                    # Register corresponding hook functions
                    for _, m_name, _ in pkgutil.iter_modules([os.path.dirname(hooking.__file__)]):
                        if m_name != lib: continue
                        module = importlib.import_module(f"morion.tracing.gdb.hooking.{m_name:s}")
                        classes = inspect.getmembers(module, predicate=inspect.isclass)
                        for c_name, c in classes:
                            if c_name != fun: continue

                            # Instantiate class
                            ci = c(f"{m_name:s}:{c_name:s}", entry, leave, logger)

                            # Register hook at entry address
                            _addr_map = self._addr_map.get(ci.entry_addr, {})
                            _symbol = f"{ci.name:s} (entry)"
                            _symbols = _addr_map.get("symbols", [])
                            _symbols.append(_symbol)
                            _hooks = _addr_map.get("hooks", {})
                            _funs = _hooks.get("funs", [])
                            _funs.append(ci.on_concex_entry)
                            _hooks["funs"] = _funs
                            _hooks["return_addr"] = ci.leave_addr
                            _addr_map["hooks"] = _hooks
                            _addr_map["symbols"] = _symbols
                            self._addr_map[ci.entry_addr] = _addr_map

                            # Register hook at leave address
                            _addr_map = self._addr_map.get(ci.leave_addr, {})
                            _symbol = f"{ci.name:s} (leave)"
                            _symbols = _addr_map.get("symbols", [])
                            _symbols.append(_symbol)
                            _hooks = _addr_map.get("hooks", {})
                            _funs = _hooks.get("funs", [])
                            _funs.append(ci.on_concex_leave)
                            _hooks["funs"] = _funs
                            _hooks["return_addr"] = None
                            _addr_map["hooks"] = _hooks
                            _addr_map["symbols"] = _symbols
                            self._addr_map[ci.leave_addr] = _addr_map
                            
        return True

    def store_trace_file(self, trace_file: str) -> bool:
        return self._recorder.store(trace_file)

    def add_stop_addrs(self, addrs: list) -> int:
        self._stop_addrs.extend(addrs)
        return len(self._stop_addrs)

    
if __name__ == "__main__":
    # GDB settings
    gdb.execute(f"set pagination off")
    gdb.execute(f"set disassembly-flavor intel")
    
    # Register commands in GDB
    GdbTraceCommand("trace")
