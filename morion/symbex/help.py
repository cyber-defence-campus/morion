#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import re
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
        """Helpler function to parse symbolic variable aliases in a consistent way.

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