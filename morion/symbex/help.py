#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import json
import re
import string
from   triton import ARCH, TritonContext
from   typing import Tuple


class SymbexHelper:

    # Count the number of symbolically executed instructions
    inst_cnt = 0
    
    @staticmethod
    def create_symvar_alias(
        reg_name: str = None, mem_addr: int = None,
        var_name: str = None, var_offs: int = None,
        mode: str = None, func: str = None,
        ) -> str:
        """Helper function to create symbolic variables aliases in a consistent way.
        """
        cnt_inst = SymbexHelper.inst_cnt
        reg_name = "" if reg_name is None else reg_name
        mem_addr = "" if mem_addr is None else f"0x{mem_addr:x}"
        var_name = "" if var_name is None else var_name
        var_offs = "" if var_offs is None else f"{var_offs:d}"
        mode = "" if mode is None else mode
        func = "" if func is None else func
        return f"{cnt_inst:d};{reg_name:s};{mem_addr:s};{mode:s};{func:s};{var_name:s}+{var_offs:s}"
    
    @staticmethod
    def parse_symvar_alias(alias: str) -> Tuple[int, str, int, str, str, str, int]:
        """Helper function to parse symbolic variable aliases in a consistent way.
        """
        cnt_inst, reg_name, mem_addr, mode, func, var = alias.split(";")
        cnt_inst = int(cnt_inst, base=10)
        reg_name = reg_name if reg_name else None
        mem_addr = int(mem_addr, base=16) if mem_addr else None
        mode = mode if mode else None
        func = func if func else None
        var_name, var_offs = var.split("+")
        var_name = var_name if var_name else None
        var_offs = int(var_offs, base=10) if var_offs else None
        return (cnt_inst, reg_name, mem_addr, mode, func, var_name, var_offs)

    
    @staticmethod
    def transform_model(model: dict) -> dict:
        """Helper function to transform models into the following form:
        {
            "regs": {
                reg_name: (value, inst_cnt, mode, func, var_name, var_offs)
            },
            "mems": {
                f"0x{mem_addr:08x}": (value, inst_cnt, mode, func, var_name, var_offs)
            }
        }
        """
        m = {}
        for _, sovler_model in model.items():
            value = sovler_model.getValue()
            alias = sovler_model.getVariable().getAlias()
            cnt_inst, reg_name, mem_addr, mode, func, var_name, var_offs = SymbexHelper.parse_symvar_alias(alias)
            if reg_name:
                regs = m.get("regs", {})
                regs.update({reg_name: (value, cnt_inst, mode, func, var_name, var_offs)})
                m.update({"regs": regs})
            if mem_addr:
                mems = m.get("mems", {})
                mems.update({f"0x{mem_addr:08x}": (value, cnt_inst, mode, func, var_name, var_offs)})
                m.update({"mems": mems})
        return m
    
    @staticmethod
    def parse_register_name(reg_name: object, ctx: TritonContext) -> str:
        """Helper function that translates register names to the ones used by Triton.
        """
        reg_name_str = str(reg_name).strip().lower()

        arch = ctx.getArchitecture()
        if arch == ARCH.ARM32:
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
    def parse_memory_address(mem_addr: object, ctx: TritonContext) -> int:
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
                        reg = ctx.getRegister(term)
                        value = ctx.getConcreteRegisterValue(reg)
                    except Exception as e:
                        raise Exception(f"Failed to parse memory address '{mem_addr_str:s}': {str(e):s}")
                if sign == "-":
                    mem_addr_int -= value
                else:
                    mem_addr_int += value
        return mem_addr_int