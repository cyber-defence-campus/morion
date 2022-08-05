#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import yaml
from   morion.log import Logger
from   typing     import List, Tuple

class Recorder:
    """
    Read/write recorded information from/to YAML files.
    """
    def __init__(self, logger: Logger = Logger()) -> None:
        self._logger = logger
        self._trace = {
            "info": {
            #    "arch": "armv7",
            #    "thumb": False
            },
            "hooks": {
            #    "lib": {
            #        "fun": [
            #            {"entry": "0x0", "leave": "0x0", "target": "0x0"}
            #        ]
            #    }
            },
            "states": {
                "entry": {
                #   "addr": "0x0",
                    "regs": {
                #       "reg": ["0x0", "$"]
                    },
                    "mems": {
                #       "0x0": ["0x0", "$"]
                    }
                },
                "leave": {
                 #  "addr": "0x0",
                    "regs": {
                 #      "reg": ["0x0", "$"]
                    },
                    "mems": {
                 #      "0x0": ["0x0", "$"]
                    }
                }
            },
            "code": {
                "0x0": ["00 00", "inst", "comment"]
            }
        }
        return
    
    def load(self, trace_file: str) -> bool:
        self._trace_file = trace_file
        try:
            with open(trace_file, "r") as f:
                self._trace = yaml.safe_load(f)
        except:
            self._trace = {}
        info = self._trace.get("info", {})
        if info is None: info = {}
        self._trace["info"] = info
        hooks = self._trace.get("hooks", {})
        if hooks is None: hooks = {}
        self._trace["hooks"] = hooks
        states = self._trace.get("states", {})
        if states is None: states = {}
        entry_state = states.get("entry", {})
        if entry_state is None: entry_state = {}
        regs = entry_state.get("regs", {})
        if regs is None: regs = {}
        entry_state["regs"] = regs
        mems = entry_state.get("mems", {})
        if mems is None: mems = {}
        entry_state["mems"] = mems
        states["entry"] = entry_state
        leave_state = states.get("leave", {})
        if leave_state is None: leave_state = {}
        regs = leave_state.get("regs", {})
        if regs is None: regs = {}
        leave_state["regs"] = regs
        mems = leave_state.get("mems", {})
        if mems is None: mems = {}
        leave_state["mems"] = mems
        states["leave"] = leave_state
        self._trace["states"] = states
        code = self._trace.get("code", {})
        if code is None: code = {}
        self._trace["code"] = code
        return True

    def store(self, trace_file: str) -> bool:
        try:
            with open(trace_file, "w+") as f:
                yaml.safe_dump(self._trace, f,
                               default_style=None,
                               default_flow_style=None,
                               encoding='utf-8',
                               width=float("inf"))
        except:
            return False
        return True

    def add_info(self, **kwargs) -> None:
        for key, value in kwargs.items():
            self._trace["info"][key] = value
        return

    def add_address(self, addr: int, is_entry: bool = True) -> None:
        state = "entry" if is_entry else "leave"
        self._trace["states"][state]["addr"] = f"0x{addr:08x}"
        return

    def add_concrete_register(self, reg_name: str, reg_value: int, is_entry: bool = True) -> None:
        state = "entry" if is_entry else "leave"
        old_reg_values = self._trace["states"][state]["regs"].get(reg_name, [])
        new_reg_values = [f"0x{reg_value:08x}"]
        if "$" in old_reg_values:
            new_reg_values.append("$")
        self._trace["states"][state]["regs"][reg_name] = new_reg_values
        return

    def add_symbolic_register(self, reg_name: str, is_entry: bool = True) -> None:
        state = "entry" if is_entry else "leave"
        old_reg_values = self._trace["states"][state]["regs"].get(reg_name, [])
        old_reg_values_concrete = [v for v in old_reg_values if not v == "$"]
        new_reg_values = []
        if len(old_reg_values_concrete) > 0:
            new_reg_values.append(old_reg_values_concrete[-1])
        new_reg_values.append("$")
        self._trace["states"][state]["regs"][reg_name] = new_reg_values
        return

    def add_concrete_memory(self, mem_addr: int, mem_value: int, is_entry: bool = True) -> None:
        state = "entry" if is_entry else "leave"
        old_mem_values = self._trace["states"][state]["mems"].get(f"0x{mem_addr:08x}", [])
        new_mem_values = [f"0x{mem_value:02x}"]
        if "$" in old_mem_values:
            new_mem_values.append("$")
        self._trace["states"][state]["mems"][f"0x{mem_addr:08x}"] = new_mem_values
        return

    def add_symbolic_memory(self, mem_addr: int, is_entry: bool = True) -> None:
        state = "entry" if is_entry else "leave"
        old_mem_values = self._trace["states"][state]["mems"].get(f"0x{mem_addr:08x}", [])
        old_mem_values_concrete = [v for v in old_mem_values if not v == "$"]
        new_mem_values = []
        if len(old_mem_values_concrete) > 0:
            new_mem_values.append(old_mem_values_concrete[-1])
        new_mem_values.append("$")
        self._trace["states"][state]["mems"][f"0x{mem_addr:08x}"] = new_mem_values
        return

    def add_instruction(self, inst_addr: int, inst_opcode: bytes, inst_disassembly: str, inst_comment: str = "") -> None:
        inst_addr = f"0x{inst_addr:08x}"
        inst_opcode = inst_opcode.hex()
        inst_opcode = " ".join(a+b for a, b in zip(inst_opcode[::2], inst_opcode[1::2]))
        self._trace["code"][inst_addr] = [inst_opcode, inst_disassembly, inst_comment]
        inst_line = [f"{inst_addr:s} ({inst_opcode:s}): {inst_disassembly:s}", f"# {inst_comment:s}"]
        self._logger.info("".join(item.ljust(50) for item in inst_line), color="cyan")
        return

    def get_entry_address(self) -> int:
        try:
            addr = self._trace["states"]["entry"]["addr"]
            if not isinstance(addr, int):
                addr = int(addr, base=0)
        except:
            return 0x0
        return addr

    def get_leave_address(self) -> int:
        try:
            addr = self._trace["states"]["leave"]["addr"]
            if not isinstance(addr, int):
                addr = int(addr, base=0)
        except:
            return 0x0
        return addr

    def get_instruction(self, inst_addr: int) -> Tuple[bytes, str, str]:
        inst_addr = f"0x{inst_addr:08x}"
        opcode, disassembly, comment = self._trace["code"].get(inst_addr, (None, None, None))
        try:
            opcode = bytes.fromhex(opcode.replace(" ", ""))
        except:
            opcode = None
        return (opcode, disassembly, comment)
