import argparse
from   morion.log            import Logger
from   morion.symbex.execute import Executor


class ControlHijacker(Executor):
    pass
    

def main() -> None:
    # Argument parsing
    description = """
    TODO
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("trace_file",
                        help="file containing the trace to be executed symbolically")
    parser.add_argument("--log_level",
                        choices=["critical", "error", "warning", "info", "debug"],
                        default="debug",
                        help="log level")
    args = parser.parse_args()

    # Symbolic Execution
    se = ControlHijacker(Logger(args.log_level))
    se.load(args.trace_file)
    se.run()
    se.store(args.trace_file)
    return

if __name__ == "__main__":
    main()
