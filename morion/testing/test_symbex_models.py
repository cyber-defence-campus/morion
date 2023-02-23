#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import unittest
from   morion.testing.test_symbex import TestSymbex


class TestModelLibcMemcmp(TestSymbex):

    def test_1(self):
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': False},
            'hooks': {
                'libc': {
                    'memcmp': [{
                        'entry': '0x4006a4',
                        'leave': '0x4006a8',
                        'target': '0x0100',
                        'mode': 'model'
                    }]
                }
            },
            'states': {
                'entry': {
                    'addr': '0x004006a4',
                    'regs': {
                        'r0': ['0x412190'],         # s1
                        'r1': ['0x4121a8'],         # s2
                        'r2': ['0x03']              # n
                    },
                    'mems': {
                        '0x412190': ['0x41'],       # s1[0] = A
                        '0x412191': ['0x42'],       # s1[1] = B
                        '0x412192': ['0x43'],       # s1[2] = C
                        '0x412193': ['0x00'],       # s1[3]
                        '0x4121a8': ['0x41'],       # s2[0] = A
                        '0x4121a9': ['0x42'],       # s2[1] = B
                        '0x4121aa': ['0x41', '$$'], # s2[2] = A
                        '0x4121ab': ['0x00']        # s2[3]
                    }
                },
                'leave': {
                    'addr': '0x004006ac'
                }
            },
            'instructions': [
                ['0x004006a4', '95 fe ef ea', 'b #-0x4005a4',  '// Hook: libc:memcmp (on=entry, mode=model)'],
                ['0x00000100', '02 00 a0 e3', 'mov  r0, #0x2', '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x00000104', '00 00 40 e3', 'movt r0, #0x0', '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x00000108', '66 01 10 ea', 'b #0x4005a0',   '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x004006a8', '00 f0 20 e3', 'nop',           '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()

        # Validate results
        r0_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r0)
        self.assertEqual(r0_val, 0x02, 'r0 == 0x02 (concrete value)')

        r0_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r0)
        r0_val = self.se.ctx.evaluateAstViaSolver(r0_ast)
        self.assertEqual(r0_val, 0x02, 'r0 == 0x02 (AST value)')

        model = self.se.ctx.getModel(r0_ast == 0)
        mem_addr  = model[0].getVariable().getAlias()
        mem_value = model[0].getValue()
        self.assertEqual(mem_addr, '0x4121aa', '0x4121aa == 0x43 C (mem_addr)')
        self.assertEqual(mem_value, 0x43,      '0x4121aa == 0x43 C (mem_val)')

        model = self.se.ctx.getModel(r0_ast == -2)
        mem_addr  = model[0].getVariable().getAlias()
        mem_value = model[0].getValue()
        self.assertEqual(mem_addr, '0x4121aa', '0x4121aa == 0x45 E (mem_addr)')
        self.assertEqual(mem_value, 0x45,      '0x4121aa == 0x45 E (mem_val)')

        model = self.se.ctx.getModel(r0_ast == 1)
        mem_addr  = model[0].getVariable().getAlias()
        mem_value = model[0].getValue()
        self.assertEqual(mem_addr, '0x4121aa', '0x4121aa == 0x42 B (mem_addr)')
        self.assertEqual(mem_value, 0x42,      '0x4121aa == 0x42 B (mem_val)')

    
if __name__ == "__main__":
    unittest.main()