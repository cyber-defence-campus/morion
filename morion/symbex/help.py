#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import re
import string
from   triton import TritonContext
from   typing import Tuple


class SymbexHelper:

    # Count the number of symbolically executed instructions
    inst_cnt = 0

    @staticmethod
    def create_symvar_alias(reg_name: str = None, mem_addr: int = None, info: str = None) -> str:
        """Helper function to create symbolic variables aliases in a consistent way.

        Examples:
        - i: 0, r: r0
        - i: 1, r: r0 [info]
        - i: 2, m: 0x1000
        - i: 3, m: 0x1000 [info]
        """
        alias = f"i: {SymbexHelper.inst_cnt:d}"
        if reg_name and mem_addr is None:
            alias = f"{alias:s}, r: {reg_name:s}"
        elif mem_addr and reg_name is None:
            alias = f"{alias:s}, m: 0x{mem_addr:x}"
        if info:
            alias = f"{alias:s} [{info:s}]"
        return alias
    
    @staticmethod
    def parse_symvar_alias(alias: str) -> Tuple[int, str, int, str]:
        """Helper function to parse symbolic variable aliases in a consistent way.

        Examples:
        - i: 0, r: r0
        - i: 1, r: r0 [info]
        - i: 2, m: 0x1000
        - i: 3, m: 0x1000 [info]
        """
        inst_cnt = None
        reg_name = None
        mem_addr = None
        info = None
        match = re.match(r"^\s*i\s*:\s*([0-9]+)(?:\s*,\s*([rm])\s*:\s*([^\s]+))?(?:\s*\[([^\]]*)\])?$", alias)
        if match:
            groups = match.groups()
            inst_cnt = int(groups[0], base=0)
            if groups[1] == "r":
                reg_name = groups[2]
            elif groups[1] == "m":
                mem_addr = int(groups[2], base=0)
            if groups[3]:
                info = groups[3]
        return (inst_cnt, reg_name, mem_addr, info)
    
    @staticmethod
    def transform_model(model: dict) -> dict:
        """Helper function to transform models into the following form:
        {
            "regs": {
                reg_name: (value, inst_cnt, info)
            },
            "mems": {
                f"0x{mem_addr:08x}": (value, inst_cnt, info)
            }
        }
        """
        m = {}
        for _, sovler_model in model.items():
            value = sovler_model.getValue()
            alias = sovler_model.getVariable().getAlias()
            inst_cnt, reg_name, mem_addr, info = SymbexHelper.parse_symvar_alias(alias)
            if reg_name:
                regs = m.get("regs", {})
                regs.update({reg_name: (value, inst_cnt, info)})
                m.update({"regs": regs})
            if mem_addr:
                mems = m.get("mems", {})
                mems.update({f"0x{mem_addr:08x}": (value, inst_cnt, info)})
                m.update({"mems": mems})
        return m
    
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