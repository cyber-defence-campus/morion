#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
import re
import string
from   morion.log                           import Logger
from   morion.symbex.analysis.vulnerability import VulnerabilityAnalysis
from   morion.symbex.tools.execute          import Executor
from   morion.symbex.help                   import SymbexHelper
from   triton                               import CPUSIZE, Instruction, MemoryAccess, TritonContext


class ROPGenerator(Executor):
    """
    Symbolic execution to generate payloads, triggering a specified ROP chain.
    """

    def load(self, trace_file: str, rop_chain: str) -> None:
        """
        Load trace file and included ROP chain.
        """
        # Load trace
        super().load(trace_file)
        # Load ROP chain
        self._logger.info(f"Start loading ROP chain from file '{trace_file:s}'...")
        self._rop_chain = self._recorder._trace.get(rop_chain, [])
        if self._rop_chain is None: self._rop_chain = []
        self._logger.info(f"... finished loading ROP chain from file '{trace_file:s}'.")
        return
    
    def run(self, args: dict = {}) -> dict:
        """
        Run trace and included ROP chain.
        """
        # Run trace
        super().run(args, exe_last_inst=False)
        # Ensure that the ROP chain is correctly aligned with the trace end
        try:
            g0_i0_addr = int(self._rop_chain[0]["instructions"][0][0], base=0)
        except:
            self._logger.error(f"Failed to access the 1st instruction of gadget 0.")
            return
        pc = self.ctx.getConcreteRegisterValue(self.ctx.registers.pc)
        if g0_i0_addr != pc:
            self._logger.error(f"Address of 1st instruction in gadget 0 (0x{g0_i0_addr:08x}) does not match the PC (0x{pc:08x}) at the trace end.")
            return
        # Run ROP chain
        ast = self.ctx.getAstContext()
        payloads = {}
        for gadget_id, gadget in enumerate(self._rop_chain):
            preconditions = gadget.get("preconditions", {})
            if preconditions is None: preconditions = {}
            prec_regs = preconditions.get("regs", {})
            if prec_regs is None: prec_regs = {}
            prec_mems = preconditions.get("mems", {})
            if prec_mems is None: prec_mems = {}
            instructions = gadget.get("instructions", [])
            if instructions is None: instructions = []
            solution = gadget.get("solution", {})
            if solution is None: solution = {}
            # Load preconditons
            self._logger.info(f"Start loading preconditions of gadget {gadget_id:d}...")
            path_constraints = VulnerabilityAnalysis.get_path_constraints(self.ctx, False)
            constraints = [path_constraints]
            self._logger.debug("Regs:")
            for reg_name, reg_value in prec_regs.items():
                try:
                    if not isinstance(reg_value, int):
                        reg_value = int(reg_value, base=0)
                    reg = self.ctx.getRegister(reg_name)
                    reg_ast = self.ctx.getRegisterAst(reg)
                except:
                    self._logger.warning(f"Failed to parse register precondition of gadget {gadget_id:d}.")
                    continue
                constraints.append(reg_ast == reg_value)
                self._logger.debug(f"\t{reg_name:s} == 0x{reg_value:08x}")
            self._logger.debug("Mems:")
            for mem_addr, mem_value in prec_mems.items():
                try:
                    if not isinstance(mem_addr, int):
                        mem_addr = int(mem_addr, base=0)
                    if not isinstance(mem_value, int):
                        mem_value = int(mem_value, base=0)
                    mem_ast = self.ctx.getMemoryAst(MemoryAccess(mem_addr, CPUSIZE.BYTE))
                except:
                    self._logger.warning(f"Failed to parse memory precondition of gadget {gadget_id:d}.")
                    continue
                constraints.append(mem_ast == mem_value)
                self._logger.debug(f"\t0x{mem_addr:08x} == 0x{mem_value:02x}")
            self._logger.info(f"... finished loading preconditions of gadget {gadget_id:d}.")
            # Solve preconditions
            self._logger.info(f"Start solving preconditions of gadget {gadget_id:d}...")
            if len(constraints) >= 2:
                model = self.ctx.getModel(ast.land(constraints))
                model = sorted(list(model.items()), key=lambda t: t[1].getVariable())
                if not model:
                    self._logger.error(f"No solution fullfilliing the preconditions of gadget {gadget_id:d} found!")
                    return
                self._logger.debug(f"Solution:", color="green")
                for _, solver_model in model:
                    value = solver_model.getValue()
                    sym_var = solver_model.getVariable()
                    inst_cnt, reg_name, mem_addr, info = SymbexHelper.parse_symvar_alias(sym_var.getAlias())
                    if reg_name:
                        solu_regs = solution.get("regs", {})
                        if solu_regs is None: solu_regs = {}
                        solu_regs[reg_name] = f"0x{value:08x}"
                        solution["regs"] = solu_regs
                        payl = payloads.get(inst_cnt, {})
                        payl_regs = payl.get("regs", {})
                        payl_regs[reg_name] = [f"0x{value:08x}", info]
                        payl["regs"] = payl_regs
                        payloads[inst_cnt] = payl
                        self._logger.debug(f"\t{reg_name:s}: 0x{value:08x} [INST:{inst_cnt:d}, {info:s}]", color="green")
                    elif mem_addr:
                        solu_mems = solution.get("mems", {})
                        if solu_mems is None: solu_mems = {}
                        solu_mems["0x{mem_addr:08x}"] = f"0x{value:02x}"
                        solu_mems["mems"] = solu_mems
                        payl = payloads.get(inst_cnt, {})
                        payl_mems = payl.get("mems", {})
                        payl_mems[f"0x{mem_addr:08x}"] = [f"0x{value:02x}", info]
                        payl["mems"] = payl_mems
                        payloads[inst_cnt] = payl
                        self._logger.debug(f"\t0x{mem_addr:08x}: 0x{value:02x} [INST:{inst_cnt:d}, {info:s}]", color="green")
            else:
                self._logger.debug(f"Gadget {gadget_id:d} has no precondittions.")
            self._logger.info(f"... finished solving preconditions of gadget {gadget_id:d}.")
            # Concretize preconditions
            self._logger.info(f"Start concretizing preconditions of gadget {gadget_id:d}...")
            self._logger.debug("Regs:")
            for reg_name, reg_value in prec_regs.items():
                try:
                    if not isinstance(reg_value, int):
                        reg_value = int(reg_value, base=0)
                except:
                    self._logger.warning(f"Failed to parse register precondition of gadget {gadget_id:d}.")
                    continue
                try:
                    reg = self.ctx.getRegister(reg_name)
                    reg_ast = self.ctx.getRegisterAst(reg)
                    self.ctx.setConcreteRegisterValue(reg, reg_value)
                    self.ctx.concretizeRegister(reg)
                    self.ctx.pushPathConstraint(reg_ast == reg_value)
                except:
                    self._logger.warning(f"Failed to concretize register '{reg_name:s}'.")
                    continue
                self._logger.debug(f"\t{reg_name:s}: 0x{reg_value:08x}")
            self._logger.debug("Mems:")
            for mem_addr, mem_value in prec_mems.items():
                try:
                    if not isinstance(mem_addr, int):
                        mem_addr = int(mem_addr, base=0)
                    if not isinstance(mem_value, int):
                        mem_value = int(mem_value, base=0)
                except:
                    self._logger.warning(f"Failed to parse memory precondition of gadget {gadget_id:d}.")
                    continue
                try:
                    mem = MemoryAccess(mem_addr, CPUSIZE.BYTE)
                    mem_ast = self.ctx.getMemoryAst(mem)
                    self.ctx.setConcreteMemoryValue(mem, mem_value)
                    self.ctx.concretizeMemory(mem)
                    self.ctx.pushPathConstraint(mem_ast == mem_value)
                except:
                    self._logger.warning(f"Failed to concretize memory '0x{mem_addr:08x}'.")
                    continue
                self._logger.debug(f"\t0x{mem_addr:08x}: 0x{mem_value:02x}")
            self._logger.info(f"... finished concretizing preconditions of gadget {gadget_id:d}...")
            # Symbolic exeuction of gadget instructions
            self._logger.info(f"Start symbolic execution of gadget {gadget_id:d}...")
            for instruction_id, (addr, opcode, disassembly, comment) in enumerate(instructions):
                # Read instruction address and opcode
                try:
                    addr = int(addr, base=16)
                    opcode = bytes.fromhex(opcode.replace(" ", ""))
                except:
                    self._logger.error(f"Failed to read instruction {instruction_id:d} of gadget {gadget_id:d}.")
                    return
                # # Execute potential hook
                # self._hook(addr)
                # Symbolic execution
                if not self._step(addr, opcode, disassembly, comment):
                    self._logger.error(f"Instruction at address 0x{addr:08x} not supported.")
                    return
            self._logger.info(f"... finished symbolic execution of gadget {gadget_id:d}.")
        return payloads
    
    def store(self, trace_file: str, rop_chain: str) -> None:
        """
        Store trace file and included ROP chain.
        """
        self._logger.info(f"Start storing file '{trace_file:s}'...")
        self._recorder._trace[rop_chain] = self._rop_chain
        self._recorder.store(trace_file)
        self._logger.info(f"... finished storing file '{trace_file:s}'.")
        return

    def dump(self, payloads: dict, bytes_per_line: int = 8) -> None:
        """
        Dump separate payloads for separate origin instructions.
        """
        
        def get_uppercase_letter_as_hex(index: int) -> str:
            return f"{ord(string.ascii_uppercase[index % 26]):02x}"

        # Print separate payloads for separate origin instructions
        self._logger.info("Start dumping payloads...")
        uppercase_letter_idx = 0
        for trace_inst_idx, payload in payloads.items():
            mod = None
            fun = None
            var = None
            off = None
            # Process register payload
            reg_pay = []
            regs = payload.get("regs", {})
            for i, reg_name in enumerate(sorted(regs.keys())):
                reg_value, reg_info = regs[reg_name]
                match = re.match(f"^([^:]+):([^:]+):([^\+]+)\+([0-9]+)$", reg_info)
                if not match:
                    self._logger.warning(f"Info of register '{reg_name:s}' could not be parsed.")
                    self._logger.warning(f"Payload [INST:{trace_inst_idx:d}] might be incorrect!")
                    continue
                if i == 0:
                    mod, fun, var, off = match.groups()
                    off = int(off, base=10)
                    self._logger.info(f"Payload [INST:{trace_inst_idx:d}][REG][{mod:s}][{fun:s}:{var:s}]", color="green", print_raw=True)
                else:
                    _mod, _fun, _var, _off = match.groups()
                    off = int(_off, base=10)
                    if _mod != mod or _fun != fun or _var != var:
                        self._logger.warning(f"Info of register '{reg_name:s}' is inconsistent.")
                        self._logger.warning(f"Payload [INST:{trace_inst_idx:d}] might be incorrect!")
                if off != len(reg_pay):
                    reg_pay.extend([get_uppercase_letter_as_hex(uppercase_letter_idx)] * (off-len(reg_pay)))
                    uppercase_letter_idx = (uppercase_letter_idx+1) % 26
                reg_pay.append(reg_value[2:])
            # Print register payload
            byte_groups = [reg_pay[b:b+bytes_per_line] for b in range(0, len(reg_pay), bytes_per_line)]
            if len(byte_groups) > 0:
                for byte_group in byte_groups:
                    self._logger.info(f"{' '.join(byte_group):s}", color="green", print_raw=True)
                self._logger.info("---", color="green", print_raw=True)
            # Process memory payload
            mem_pay = []
            mems = payload.get("mems", {})
            for i, mem_addr in enumerate(sorted(mems.keys())):
                mem_value, mem_info = mems[mem_addr]
                match = re.match(f"^([^:]+):([^:]+):([^\+]+)\+([0-9]+)$", mem_info)
                if not match:
                    self._logger.warning(f"Info of memory '{mem_addr:s}' could not be parsed.")
                    self._logger.warning(f"Payload [INST:{trace_inst_idx:d}] might be incorrect!")
                    continue
                if i == 0:
                    mod, fun, var, off = match.groups()
                    off = int(off, base=10)
                    self._logger.info(f"Payload [INST:{trace_inst_idx:d}][MEM][{mod:s}][{fun:s}:{var:s}]", color="green", print_raw=True)
                else:
                    _mod, _fun, _var, _off = match.groups()
                    off = int(_off, base=10)
                    if _mod != mod or _fun != fun or _var != var:
                        self._logger.warning(f"Info of memory '{mem_addr:s}' is inconsistent.")
                        self._logger.warning(f"Payload [INST:{trace_inst_idx:d}] might be incorrect!")
                if off != len(mem_pay):
                    mem_pay.extend([get_uppercase_letter_as_hex(uppercase_letter_idx)] * (off-len(mem_pay)))
                    uppercase_letter_idx = (uppercase_letter_idx+1) % 26
                mem_pay.append(mem_value[2:])
            # Print memory payload
            byte_groups = [mem_pay[b:b+bytes_per_line] for b in range(0, len(mem_pay), bytes_per_line)]
            if len(byte_groups) > 0:
                for byte_group in byte_groups:
                    self._logger.info(f"{' '.join(byte_group):s}", color="green", print_raw=True)
                self._logger.info("---", color="green", print_raw=True)
        self._logger.info("... finished dumping payloads.")
        return

def main() -> None:
    # Argument parsing
    description = """Symbolically execute a program trace to generate a ROP chain.
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("trace_file",
                        help="file containing the trace to be executed symbolically")
    parser.add_argument("rop_chain",
                        help="name of the ROP chain to be used from the trace_file")
    parser.add_argument("--bytes_per_line",
                        type=int, default=8,
                        help="Number of payload bytes to print per line")
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
    args = vars(parser.parse_args())
    args["skip_state_analysis"] = True

    # Symbolic execution
    se = ROPGenerator(Logger(args["log_level"]))
    se.load(args["trace_file"], args["rop_chain"])
    payloads = se.run(args)
    se.store(args["trace_file"], args["rop_chain"])
    se.dump(payloads, args["bytes_per_line"])
    return


if __name__ == "__main__":
    main()
