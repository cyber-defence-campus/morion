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
