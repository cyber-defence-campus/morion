#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import unittest
import tempfile
import yaml
from   morion.log                  import Logger
from   morion.symbex.tools.execute import Executor
from   triton                      import CPUSIZE, MemoryAccess


class TestSymbex(unittest.TestCase):

    def setUp(self) -> None:
        self.se = Executor(Logger("debug"))
        self.tf = tempfile.NamedTemporaryFile()
        return

    def _write_tmp_trace_file(self, trace: dict) -> None:
        yaml.safe_dump(trace, self.tf,
            default_style=None,
            default_flow_style=None,
            encoding="utf-8",
            width=float("inf"))
        print("\n")
        return

    def tearDown(self) -> None:
        self.tf.close()
        print("\n")
        return
    

class TestLoading(TestSymbex):

    def test_parse_memory_address(self) -> None:
        # Init trace file
        self._write_tmp_trace_file({
            'info': {'arch': 'armv7', 'thumb': False},
            'states': {
                'entry': {
                    'addr': '0x2000',
                    'regs': {
                        'sp' : '0x100c',
                        'r11': '0xffffffff'
                    },
                    'mems': {
                        4096                     : 1,
                        4097                     : [0x02],
                        4098                     : ['3', '$$'],
                        4099                     : ['0x04', '$$'],
                        0x1004                   : 1,
                        0x1005                   : [0x02],
                        0x1006                   : ['3', '$$'],
                        0x1007                   : ['0x04', '$$'],
                        '0x1008'                 : 1,
                        '0x1009'                 : [0x02],
                        '0x100a'                 : ['3', '$$'],
                        '0x100b'                 : ['0x04', '$$'],
                        '[sp+0]'                 : 1,
                        '[sp+1]'                 : [0x02],
                        '[sp+2]'                 : ['3', '$$'],
                        '[sp+3]'                 : ['0x04', '$$'],
                        '[sp+8-0x4]'             : 1,
                        '[sp+8-0x3]'             : [0x02],
                        '[sp+8-0x2]'             : ['3', '$$'],
                        '[sp+8-0x1]'             : ['0x04', '$$'],
                        '[sp+8-r11+0xffffffff+0]': 1,
                        '[sp+8-r11+0xffffffff+1]': [0x02],
                        '[sp+8-r11+0xffffffff+2]': ['3', '$$'],
                        '[sp+8-r11+0xffffffff+3]': ['0x04', '$$'],
                    }
                },
                'leave': {
                    'addr': '0x2004'
                }
            },
            'instructions': [
                ['0x2000', '00 f0 20 e3', 'nop', '']
            ]
        })

        # Run symbolic execution
        self.se.load(self.tf.name)
        self.se.run()

        # Validate results
        mem_con = self.se.ctx.getConcreteMemoryValue(MemoryAccess(0x1000, CPUSIZE.DWORD))
        mem_sym = self.se._is_memory_symbolic(0x1000, CPUSIZE.DWORD)
        self.assertEqual(mem_con, 0x04030201,   '0x1000 [concrete]: decimal integer')
        self.assertEqual(mem_sym, [1, 1, 0, 0], '0x1000 [symbolic]: decimal integer')

        mem_con = self.se.ctx.getConcreteMemoryValue(MemoryAccess(0x1004, CPUSIZE.DWORD))
        mem_sym = self.se._is_memory_symbolic(0x1004, CPUSIZE.DWORD)
        self.assertEqual(mem_con, 0x04030201,   '0x1004 [concrete]: hexadecimal integer')
        self.assertEqual(mem_sym, [1, 1, 0, 0], '0x1004 [symbolic]: hexadecimal integer')

        mem_con = self.se.ctx.getConcreteMemoryValue(MemoryAccess(0x1008, CPUSIZE.DWORD))
        mem_sym = self.se._is_memory_symbolic(0x1008, CPUSIZE.DWORD)
        self.assertEqual(mem_con, 0x04030201,   '0x1008 [concrete]: hexadecimal integer as string')
        self.assertEqual(mem_sym, [1, 1, 0, 0], '0x1008 [symbolic]: hexadecimal integer as string')

        mem_con = self.se.ctx.getConcreteMemoryValue(MemoryAccess(0x100c, CPUSIZE.DWORD))
        mem_sym = self.se._is_memory_symbolic(0x100c, CPUSIZE.DWORD)
        self.assertEqual(mem_con, 0x04030201,   '0x100c [concrete]: single register with decimal offset')
        self.assertEqual(mem_sym, [1, 1, 0, 0], '0x100c [symbolic]: single register with decimal offset')

        mem_con = self.se.ctx.getConcreteMemoryValue(MemoryAccess(0x1010, CPUSIZE.DWORD))
        mem_sym = self.se._is_memory_symbolic(0x1010, CPUSIZE.DWORD)
        self.assertEqual(mem_con, 0x04030201,   '0x1010 [concrete]: single register with hexadecimal offset')
        self.assertEqual(mem_sym, [1, 1, 0, 0], '0x1010 [symbolic]: single register with hexadecimal offset')

        mem_con = self.se.ctx.getConcreteMemoryValue(MemoryAccess(0x1014, CPUSIZE.DWORD))
        mem_sym = self.se._is_memory_symbolic(0x1014, CPUSIZE.DWORD)
        self.assertEqual(mem_con, 0x04030201,   '0x1014 [concrete]: multiple registers/offsets')
        self.assertEqual(mem_sym, [1, 1, 0, 0], '0x1014 [symbolic]: multiple registers/offsets')

        return