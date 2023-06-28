#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import ctypes


class Converter:
    """
    Convert between various data types.
    """

    @staticmethod
    def uint_to_int(i: int) -> int:
        return ctypes.c_int(i).value
    
    @staticmethod
    def int_to_uint(i: int) -> int:
        return ctypes.c_uint(i).value
    
    @staticmethod
    def ulong_to_long(i: int) -> int:
        return ctypes.c_long(i).value
    
    @staticmethod
    def long_to_ulong(i: int) -> int:
        return ctypes.c_ulong(i).value