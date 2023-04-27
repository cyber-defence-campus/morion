#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
from   morion.log                           import Logger
from   morion.symbex.execute                import Executor
from   morion.symbex.analysis.vulnerability import VulnerabilityAnalysis
from   triton                               import MODE


class PathAnalyzer(Executor):

    def run(self, args: dict = {}) -> None:
        # Set symbolic execution mode
        self._only_on_symbolized = self.ctx.isModeEnabled(MODE.ONLY_ON_SYMBOLIZED)
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
        # Set post-processing functions
        self._post_processing_functions.append(VulnerabilityAnalysis.identify_controllable_paths)
        # Run symbolic execution
        super().run(args)
        # Remove post-processing functions
        self._post_processing_functions.pop()
        # Log path analysis summary
        self._logger.info(f"Summarizing path analysis...")
        for i, (path, model_summary) in enumerate(VulnerabilityAnalysis.analysis_history.items()):
            self._logger.info(f"\tPath {i:d}: {path:s}:", color="magenta")
            self._logger.info(f"\tState:", color="magenta")
            model_summary.sort()
            for line in model_summary:
                self._logger.info(f"\t\t{line:s}", color="magenta")
        path_count = len(VulnerabilityAnalysis.analysis_history)
        self._logger.info(f"... a total of {path_count:d} new path(s) identified.")
        # Restore symbolic execution mode
        self.ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, self._only_on_symbolized)
        return
    

def main() -> None:
    # Argument parsing
    description = """Symbolically execute a program trace for path analysis.

    The analysis identifies unique paths along the trace and outputs concrete
    values of how to reach these paths. A path consists of a sequence of
    multiway branches. The last multiway branch in each outputted path is non-
    taken in the concrete execution of the trace.
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
    parser.add_argument("--disallow_user_inputs",
                        action="store_true",
                        help="Run without requesting the user for inputs")
    args = vars(parser.parse_args())

    # Symbolic Execution
    se = PathAnalyzer(Logger(args["log_level"]))
    se.load(args["trace_file"])
    se.run(args)
    se.store(args["trace_file"])
    return

if __name__ == "__main__":
    main()
