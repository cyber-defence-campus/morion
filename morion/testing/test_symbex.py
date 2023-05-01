#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import unittest
import tempfile
import yaml
from   morion.log            import Logger
from   morion.symbex.execute import Executor


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