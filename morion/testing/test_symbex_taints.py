#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import unittest
from   morion.testing.test_symbex import TestSymbex
from   triton import CPUSIZE, MemoryAccess


class TestTaintLibcMemcmp(TestSymbex):

    def test_no_taint(self) -> None:
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': False},
            'hooks': {
                'libc': {
                    'memcmp': [{
                        'entry' : '0x4006a4',
                        'leave' : '0x4006a8',
                        'target': '0x000100',
                        'mode'  : 'taint'
                    }]
                }
            },
            'states': {
                'entry': {
                    'addr': '0x4006a4',
                    'regs': {
                        'r0': ['0x412190'],         # s1
                        'r1': ['0x4121a8'],         # s2
                        'r2': ['0x000003']          # n
                    },
                    'mems': {
                        '0x412190': ['0x41'],       # s1[0] = A
                        '0x412191': ['0x42'],       # s1[1] = B
                        '0x412192': ['0x43'],       # s1[2] = C
                        '0x412193': ['0x00'],       # s1[3]
                        '0x4121a8': ['0x41'],       # s2[0] = A
                        '0x4121a9': ['0x42'],       # s2[1] = B
                        '0x4121aa': ['0x41'],       # s2[2] = A
                        '0x4121ab': ['0x00']        # s2[3]
                    }
                },
                'leave': {
                    'addr': '0x4006ac'
                }
            },
            'instructions': [
                ['0x4006a4', '95 fe ef ea', 'b #-0x4005a4',  '// Hook: libc:memcmp (on=entry, mode=taint)'],
                ['0x000100', '02 00 a0 e3', 'mov  r0, #0x2', '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x000104', '00 00 40 e3', 'movt r0, #0x0', '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x000108', '66 01 10 ea', 'b #0x4005a0',   '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x4006a8', '00 f0 20 e3', 'nop',           '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()

        # Validate results
        self.assertFalse(self.se.ctx.isRegisterSymbolized(self.se.ctx.registers.r0))

        return

    def test_addr(self) -> None:
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': False},
            'hooks': {
                'libc': {
                    'memcmp': [{
                        'entry' : '0x4006a4',
                        'leave' : '0x4006a8',
                        'target': '0x000100',
                        'mode'  : 'taint'
                    }]
                }
            },
            'states': {
                'entry': {
                    'addr': '0x4006a4',
                    'regs': {
                        'r0': ['0x412190'],         # s1
                        'r1': ['0x4121a8', '$$'],   # s2
                        'r2': ['0x000003']          # n
                    },
                    'mems': {
                        '0x412190': ['0x41'],       # s1[0] = A
                        '0x412191': ['0x42'],       # s1[1] = B
                        '0x412192': ['0x43'],       # s1[2] = C
                        '0x412193': ['0x00'],       # s1[3]
                        '0x4121a8': ['0x41'],       # s2[0] = A
                        '0x4121a9': ['0x42'],       # s2[1] = B
                        '0x4121aa': ['0x41'],       # s2[2] = A
                        '0x4121ab': ['0x00']        # s2[3]
                    }
                },
                'leave': {
                    'addr': '0x4006ac'
                }
            },
            'instructions': [
                ['0x4006a4', '95 fe ef ea', 'b #-0x4005a4',  '// Hook: libc:memcmp (on=entry, mode=taint)'],
                ['0x000100', '02 00 a0 e3', 'mov  r0, #0x2', '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x000104', '00 00 40 e3', 'movt r0, #0x0', '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x000108', '66 01 10 ea', 'b #0x4005a0',   '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x4006a8', '00 f0 20 e3', 'nop',           '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()

        # Validate results
        self.assertTrue(self.se.ctx.isRegisterSymbolized(self.se.ctx.registers.r0))

        return

    def test_value(self) -> None:
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': False},
            'hooks': {
                'libc': {
                    'memcmp': [{
                        'entry' : '0x4006a4',
                        'leave' : '0x4006a8',
                        'target': '0x000100',
                        'mode'  : 'taint'
                    }]
                }
            },
            'states': {
                'entry': {
                    'addr': '0x4006a4',
                    'regs': {
                        'r0': ['0x412190'],         # s1
                        'r1': ['0x4121a8'],         # s2
                        'r2': ['0x000003']          # n
                    },
                    'mems': {
                        '0x412190': ['0x41'],       # s1[0] = A
                        '0x412191': ['0x42'],       # s1[1] = B
                        '0x412192': ['0x43'],       # s1[2] = C
                        '0x412193': ['0x00'],       # s1[3]
                        '0x4121a8': ['0x41'],       # s2[0] = A
                        '0x4121a9': ['0x42', '$$'], # s2[1] = B
                        '0x4121aa': ['0x41'],       # s2[2] = A
                        '0x4121ab': ['0x00']        # s2[3]
                    }
                },
                'leave': {
                    'addr': '0x4006ac'
                }
            },
            'instructions': [
                ['0x4006a4', '95 fe ef ea', 'b #-0x4005a4',  '// Hook: libc:memcmp (on=entry, mode=taint)'],
                ['0x000100', '02 00 a0 e3', 'mov  r0, #0x2', '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x000104', '00 00 40 e3', 'movt r0, #0x0', '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x000108', '66 01 10 ea', 'b #0x4005a0',   '// Hook: libc:memcmp (on=leave, mode=taint)'],
                ['0x4006a8', '00 f0 20 e3', 'nop',           '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()

        # Validate results
        self.assertTrue(self.se.ctx.isRegisterSymbolized(self.se.ctx.registers.r0))

        return

    
if __name__ == "__main__":
    unittest.main()