#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import unittest
from   morion.testing.test_symbex import TestSymbex


class TestA32instIT(TestSymbex):

    def test_ite(self):
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': True},
            'states': {
                'entry': {
                    'addr': '0x1000',
                    'regs': {
                        'r0': ['0x00', '$$'],
                        'r1': ['0x00', '$$']
                    }
                },
                'leave': {
                    'addr': '0x1010'
                }
            },
            'instructions': [
                ['0x1000', '88 42',       'cmp r0, r1', ''],
                ['0x1002', '0c bf',       'ite eq',     ''],
                ['0x1004', '4f f0 02 02', 'mov r2, #2', '// eq'],
                ['0x1008', '4f f0 03 02', 'mov r2, #3', '// ne'],
                ['0x100c', '4f f0 04 03', 'mov r3, #4', '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()

        # Validate results
        r0_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r0)
        r1_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r1)
        r2_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r2)
        r3_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r3)

        r0_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r0)
        r1_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r1)
        r2_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r2)
        r3_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r3)

        self.assertEqual(r0_val, 0x00, 'r0')
        self.assertEqual(r1_val, 0x00, 'r1')
        self.assertEqual(r2_val, 0x02, 'r2')
        self.assertEqual(r3_val, 0x04, 'r3')

        self.assertTrue(self.se.ctx.isSat(r0_ast != 0x00))
        self.assertTrue(self.se.ctx.isSat(r1_ast != 0x00))
        model = self.se.ctx.getModel(r2_ast == 0x03)
        self.assertTrue(model[0].getValue() != model[1].getValue())
        self.assertFalse(self.se.ctx.isSat(r3_ast != 0x04))


    def test_itete(self):
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': True},
            'states': {
                'entry': {
                    'addr': '0x1000',
                    'regs': {
                        'r0': ['0x00', '$$'],
                        'r1': ['0x00', '$$']
                    }
                },
                'leave': {
                    'addr': '0x1018'
                }
            },
            'instructions': [
                ['0x1000', '88 42',       'cmp r0, r1', ''],
                ['0x1002', '15 bf',       'itete ne',   ''],
                ['0x1004', '4f f0 02 02', 'mov r2, #2', '// ne'],
                ['0x1008', '4f f0 03 02', 'mov r2, #3', '// eq'],
                ['0x100c', '4f f0 04 03', 'mov r3, #4', '// ne'],
                ['0x1010', '4f f0 05 03', 'mov r3, #5', '// eq'],
                ['0x1014', '4f f0 06 04', 'mov r4, #6', '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()
        
        # Validate results
        r0_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r0)
        r1_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r1)
        r2_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r2)
        r3_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r3)
        r4_val = self.se.ctx.getConcreteRegisterValue(self.se.ctx.registers.r4)

        r0_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r0)
        r1_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r1)
        r2_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r2)
        r3_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r3)
        r4_ast = self.se.ctx.getRegisterAst(self.se.ctx.registers.r4)

        self.assertEqual(r0_val, 0x00, 'r0')
        self.assertEqual(r1_val, 0x00, 'r1')
        self.assertEqual(r2_val, 0x03, 'r2')
        self.assertEqual(r3_val, 0x05, 'r3')
        self.assertEqual(r4_val, 0x06, 'r4')

        self.assertTrue(self.se.ctx.isSat(r0_ast != 0x00))
        self.assertTrue(self.se.ctx.isSat(r1_ast != 0x00))
        model = self.se.ctx.getModel(r2_ast == 0x02)
        self.assertTrue(model[0].getValue() != model[1].getValue())
        model = self.se.ctx.getModel(r3_ast == 0x04)
        self.assertTrue(model[0].getValue != model[1].getValue())
        self.assertFalse(self.se.ctx.isSat(r4_ast != 0x06))

    
if __name__ == "__main__":
    unittest.main()