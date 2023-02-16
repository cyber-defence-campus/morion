#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import unittest
import tempfile
import yaml
from   morion.log            import Logger
from   morion.symbex.execute import Executor


class TestSymbex(unittest.TestCase):

    def setUp(self):
        self.se = Executor(Logger("debug"))
        self.tf = tempfile.NamedTemporaryFile()

    def _write_tmp_trace_file(self, trace):
        yaml.safe_dump(trace, self.tf,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8",
            width=float("inf"))
        print("\n")

    def tearDown(self):
        self.tf.close()
        print("\n")

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

if __name__ == "__main__":
    unittest.main()