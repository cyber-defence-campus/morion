#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
from   morion.log                           import Logger
from   morion.symbex.tools.execute          import Executor
from   morion.symbex.analysis.vulnerability import VulnerabilityAnalysis
from   triton                               import MODE


class ControlHijacker(Executor):

    def run(self, args: dict = {}) -> None:
        # Set symbolic execution mode
        self._only_on_symbolized = self.ctx.isModeEnabled(MODE.ONLY_ON_SYMBOLIZED)
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
        # Set post-processing functions
        self._post_processing_functions.append(VulnerabilityAnalysis.identify_controllable_flows)
        # Run symbolic execution
        super().run(args)
        # Remove post-processing functions
        self._post_processing_functions.pop()
        # Restore symbolic execution mode
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, self._only_on_symbolized)
        return
    

def main() -> None:
    # Argument parsing
    description = """Symbolically execute a program trace to identify potential
    control flow hijacks.

    A control flow hijack corresponds to registers, influencing the control flow
    (such as PC), becoming (partly) symbolic.
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("trace_file",
                        help="file containing the trace to be executed symbolically")
    parser.add_argument("--log_level",
                        choices=["critical", "error", "warning", "info", "debug"],
                        default="debug",
                        help="log level")
    parser.add_argument("--stepping",
                        action="store_true",
                        help="open a debug shell after each instruction")
    parser.add_argument("--disallow_user_inputs",
                        action="store_true",
                        help="run without requesting the user for inputs")
    parser.add_argument("--skip_state_analysis",
                        action="store_true",
                        help="skip analyzing the symbolic state at the end of the execution")
    args = vars(parser.parse_args())

    # Symbolic Execution
    se = ControlHijacker(Logger(args["log_level"]))
    se.load(args["trace_file"])
    se.run(args)
    se.store(args["trace_file"])
    return

if __name__ == "__main__":
    main()
