#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
from   morion.log                           import Logger
from   morion.symbex.execute                import Executor
from   morion.symbex.analysis.vulnerability import identify_controllable_flows
from   triton                               import MODE


class ControlHijacker(Executor):

    def run(self, stepping: bool = False) -> None:
        # Set symbolic execution mode
        self._only_on_symbolized = self.ctx.isModeEnabled(MODE.ONLY_ON_SYMBOLIZED)
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
        # Add post-processing function
        self._post_processing_functions.append(identify_controllable_flows)
        # Run symbolic execution
        super().run(stepping)
        # Remove post-processing function
        self._post_processing_functions.pop()
        # Restore symbolic execution mode
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, self._only_on_symbolized)
        return
    

def main() -> None:
    # Argument parsing
    description = """
    Identify potential control flow hijacks in a binary's program trace. A
    control flow hijack corresponds to registers, influencing the control flow
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
                        help="Open a debug shell after each instruction")
    args = parser.parse_args()

    # Symbolic Execution
    se = ControlHijacker(Logger(args.log_level))
    se.load(args.trace_file)
    se.run(args.stepping)
    se.store(args.trace_file)
    return

if __name__ == "__main__":
    main()
