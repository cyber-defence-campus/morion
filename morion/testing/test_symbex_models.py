#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import unittest
from   morion.testing.test_symbex import TestSymbex
from   triton                     import CPUSIZE, MemoryAccess


class TestModelLibcMemcmp(TestSymbex):

    def test_n0(self):
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': False},
            'hooks': {
                'libc': {
                    'memcmp': [{
                        'entry' : '0x4006a4',
                        'leave' : '0x4006a8',
                        'target': '0x000100',
                        'mode'  : 'model'
                    }]
                }
            },
            'states': {
                'entry': {
                    'addr': '0x4006a4',
                    'regs': {
                        'r0': ['0x412190'],         # s1
                        'r1': ['0x4121a8'],         # s2
                        'r2': ['0x000000', '$$']    # n
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
                    'addr': '0x4006ac'
                }
            },
            'instructions': [
                ['0x4006a4', '95 fe ef ea', 'b #-0x4005a4',  '// Hook: libc:memcmp (on=entry, mode=model)'],
                ['0x000100', '02 00 a0 e3', 'mov  r0, #0x2', '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x000104', '00 00 40 e3', 'movt r0, #0x0', '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x000108', '66 01 10 ea', 'b #0x4005a0',   '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x4006a8', '00 f0 20 e3', 'nop',           '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()

        # Validate results
        r0_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r0)
        self.assertEqual(r0_val, 0x00, 'r0 == 0x00 (concrete value)')

        r0_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r0)
        r0_val = self.se.ctx.evaluateAstViaSolver(r0_ast)
        self.assertEqual(r0_val, 0x00, 'r0 == 0x00 (AST value)')

        # NOTE: Model does not support symbolic n's
        self.assertFalse(self.se.ctx.isSat(r0_ast != 0))

    def test_n3(self):
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': False},
            'hooks': {
                'libc': {
                    'memcmp': [{
                        'entry' : '0x4006a4',
                        'leave' : '0x4006a8',
                        'target': '0x000100',
                        'mode'  : 'model'
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
                        '0x4121aa': ['0x41', '$$'], # s2[2] = A
                        '0x4121ab': ['0x00']        # s2[3]
                    }
                },
                'leave': {
                    'addr': '0x4006ac'
                }
            },
            'instructions': [
                ['0x4006a4', '95 fe ef ea', 'b #-0x4005a4',  '// Hook: libc:memcmp (on=entry, mode=model)'],
                ['0x000100', '02 00 a0 e3', 'mov  r0, #0x2', '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x000104', '00 00 40 e3', 'movt r0, #0x0', '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x000108', '66 01 10 ea', 'b #0x4005a0',   '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x4006a8', '00 f0 20 e3', 'nop',           '']
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
        mem_add = model[0].getVariable().getAlias()
        mem_val = model[0].getValue()
        self.assertEqual(mem_add, '0x4121aa', '0x4121aa == 0x43 C (mem_add)')
        self.assertEqual(mem_val, 0x43,       '0x4121aa == 0x43 C (mem_val)')

        model = self.se.ctx.getModel(r0_ast == -2)
        mem_add = model[0].getVariable().getAlias()
        mem_val = model[0].getValue()
        self.assertEqual(mem_add, '0x4121aa', '0x4121aa == 0x45 E (mem_add)')
        self.assertEqual(mem_val, 0x45,       '0x4121aa == 0x45 E (mem_val)')

        model = self.se.ctx.getModel(r0_ast == 1)
        mem_add = model[0].getVariable().getAlias()
        mem_val = model[0].getValue()
        self.assertEqual(mem_add, '0x4121aa', '0x4121aa == 0x42 B (mem_add)')
        self.assertEqual(mem_val, 0x42,       '0x4121aa == 0x42 B (mem_val)')

    def test_n15(self):
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': False},
            'hooks': {
                'libc': {
                    'memcmp': [{
                        'entry' : '0x4006a4',
                        'leave' : '0x4006a8',
                        'target': '0x000100',
                        'mode'  : 'model'
                    }]
                }
            },
            'states': {
                'entry': {
                    'addr': '0x4006a4',
                    'regs': {
                        'r0': ['0x412190'],         # s1
                        'r1': ['0x4121a8'],         # s2
                        'r2': ['0x00000f']          # n
                    },
                    'mems': {
                        '0x412190': ['0x41'],       # s1[0]  = A
                        '0x412191': ['0x42'],       # s1[1]  = B
                        '0x412192': ['0x43'],       # s1[2]  = C
                        '0x412193': ['0x44', '$$'], # s1[4]  = D
                        '0x412194': ['0x41'],       # s1[5]  = A
                        '0x412195': ['0x42'],       # s1[6]  = B
                        '0x412196': ['0x43'],       # s1[7]  = C
                        '0x412197': ['0x44'],       # s1[8]  = D
                        '0x412198': ['0x41'],       # s1[9]  = A
                        '0x412199': ['0x42'],       # s1[10] = B
                        '0x41219a': ['0x43'],       # s1[11] = C
                        '0x41219b': ['0x44'],       # s1[12] = D
                        '0x41219c': ['0x41'],       # s1[13] = A
                        '0x41219d': ['0x42'],       # s1[14] = B
                        '0x41219e': ['0x43'],       # s1[15] = C
                        '0x41219f': ['0x00'],       # s1[16]
                        '0x4121a8': ['0x41'],       # s2[0]  = A
                        '0x4121a9': ['0x42'],       # s2[1]  = B
                        '0x4121aa': ['0x43'],       # s2[2]  = C
                        '0x4121ab': ['0x44'],       # s2[3]  = D
                        '0x4121ac': ['0x41'],       # s2[4]  = A
                        '0x4121ad': ['0x42'],       # s2[5]  = B
                        '0x4121ae': ['0x43'],       # s2[6]  = C
                        '0x4121af': ['0x44'],       # s2[7]  = D
                        '0x4121b0': ['0x41'],       # s2[8]  = A
                        '0x4121b1': ['0x42'],       # s2[9]  = B
                        '0x4121b2': ['0x43'],       # s2[10] = C
                        '0x4121b3': ['0x44', '$$'], # s2[11] = D
                        '0x4121b4': ['0x41'],       # s2[12] = A
                        '0x4121b5': ['0x42'],       # s2[13] = B
                        '0x4121b6': ['0x43'],       # s2[14] = C
                        '0x4121b7': ['0x00']        # s2[15]
                    }
                },
                'leave': {
                    'addr': '0x4006ac'
                }
            },
            'instructions': [
                ['0x4006a4', '95 fe ef ea', 'b #-0x4005a4',  '// Hook: libc:memcmp (on=entry, mode=model)'],
                ['0x000100', '02 00 a0 e3', 'mov  r0, #0x2', '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x000104', '00 00 40 e3', 'movt r0, #0x0', '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x000108', '66 01 10 ea', 'b #0x4005a0',   '// Hook: libc:memcmp (on=leave, mode=model)'],
                ['0x4006a8', '00 f0 20 e3', 'nop',           '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()

        # Validate results
        ast = self.se.ctx.getAstContext()
        
        r0_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r0)
        self.assertEqual(r0_val, 0x00, 'r0 == 0x00 (concrete value)')

        r0_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r0)
        r0_val = self.se.ctx.evaluateAstViaSolver(r0_ast)
        self.assertEqual(r0_val, 0x00, 'r0 == 0x00 (AST value)')

        mem_0_ast = self.se.ctx.getMemoryAst(MemoryAccess(0x412193, CPUSIZE.BYTE))
        mem_1_ast = self.se.ctx.getMemoryAst(MemoryAccess(0x4121b3, CPUSIZE.BYTE))

        model = self.se.ctx.getModel(ast.land([r0_ast == -3, mem_1_ast == 0x44]))
        model = sorted(list(model.items()), key=lambda t: t[1].getVariable())
        mem_0_add = model[0][1].getVariable().getAlias()
        mem_0_val = model[0][1].getValue()
        self.assertEqual(mem_0_add, '0x412193', '0x412193 == 0x41 A (mem_add)')
        self.assertEqual(mem_0_val, 0x41,       '0x412193 == 0x41 A (mem_val)')
        
        model = self.se.ctx.getModel(ast.land([r0_ast == 4, mem_0_ast == 0x44]))
        model = sorted(list(model.items()), key=lambda t: t[1].getVariable())
        mem_1_add = model[1][1].getVariable().getAlias()
        mem_1_val = model[1][1].getValue()
        self.assertEqual(mem_1_add, '0x4121b3', '0x4121b3 == 0x40 @ (mem_add)')
        self.assertEqual(mem_1_val, 0x40,       '0x4121b3 == 0x40 @ (mem_val)')

    
if __name__ == "__main__":
    unittest.main()