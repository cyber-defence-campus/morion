#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from typing import Tuple, List


class AddressMapper:
    """
    A datastructure tracking symbols and hooks for addresses.
    """
    def __init__(self) -> None:
        self._addr_map = {
            # 0x0: {
            #     "symbols": ["sample"],
            #     "hooks": {
            #         "funs": [],
            #         "return_addr": 0x0
            #         }
            # }
        }
        return

    def add(self,
            addr: int,
            symbol: str = None,
            function: 'Function' = None,
            return_addr: int = None) -> None:
        addr_map = self._addr_map.get(addr, {})
        if symbol is not None:
            symbols = addr_map.get("symbols", [])
            if symbols is None: symbols = []
            symbols.extend([symbol])
            addr_map["symbols"] = symbols
        if function is not None:
            hooks = addr_map.get("hooks", {})
            if hooks is None: hooks = {}
            funs = hooks.get("funs", [])
            if funs is None: funs = []
            funs.extend([function])
            hooks["funs"] = funs
            addr_map["hooks"] = hooks
        if return_addr is not None:
            hooks = addr_map.get("hooks", {})
            if hooks is None: hooks = {}
            hooks["return_addr"] = return_addr
            addr_map["hooks"] = hooks
        self._addr_map[addr] = addr_map
        return

    def get_symbols(self, addr: int) -> List[str]:
        return self._addr_map.get(addr, {}).get("symbols", [])

    def get_hooks(self, addr: int) -> Tuple[List, int]:
        hooks = self._addr_map.get(addr, {}).get("hooks", {})
        return hooks.get("funs", []), hooks.get("return_addr", None)
            
