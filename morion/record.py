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
            #            {"entry": "0x0", "leave": "0x0"}
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
            "trace": [
                # ["0x0", 00, "inst", "comment"]
            ]
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
        trace = self._trace.get("trace", [])
        if trace is None: trace = []
        self._trace["trace"] = trace
        return True

    def store(self, trace_file: str) -> bool:
        try:
            with open(trace_file, "w+") as f:
                yaml.dump(self._trace, f, default_flow_style=None)
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

    def add_register(self, reg_name: str, reg_value: int, is_entry: bool = True) -> None:
        state = "entry" if is_entry else "leave"
        reg = self._trace["states"][state]["regs"].get(reg_name, [])
        self._trace["states"][state]["regs"][reg_name] = [f"0x{reg_value:08x}"]
        if '$' in reg:
            self._trace["states"][state]["regs"][reg_name].append('$')
        return

    def add_memory(self, mem_addr: int, mem_value: int, is_entry: bool = True) -> None:
        state = "entry" if is_entry else "leave"
        mem = self._trace["states"][state]["mems"].get(f"0x{mem_addr:08x}", [])
        self._trace["states"][state]["mems"][f"0x{mem_addr:08x}"] = [f"0x{mem_value:02x}"]
        if '$' in mem:
            self._trace["states"][state]["mems"][f"0x{mem_addr:08x}"].append('$')
        return

    def add_instruction(self, inst_addr: int, inst_opcode: bytes, inst_disassembly: str, inst_comment: str = "") -> None:
        inst_addr = f"0x{inst_addr:08x}"
        inst_opcode = inst_opcode.hex()
        inst_opcode = ' '.join(a+b for a, b in zip(inst_opcode[::2], inst_opcode[1::2]))
        self._trace["trace"].append([inst_addr, inst_opcode, inst_disassembly, inst_comment])
        self._logger.info(f"{inst_addr:s} ({inst_opcode:s}): {inst_disassembly:s}", color="cyan")
        return

    def get_trace(self) -> List[Tuple[str, str, str, str]]:
        return self._trace["trace"]
