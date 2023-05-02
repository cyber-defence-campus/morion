#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
import libtmux

# References
# - https://libtmux.git-pull.com/reference/windows.html
# - https://github.com/tmux-python/libtmux


def main() -> None:
    # Argument parsing
    description = """
    TODO
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # parser.add_argument("--gdb",
    #                     choices=["gdb", "gdb-multiarch"],
    #                     default="gdb-multiarch",
    #                     help="Multi-architecture or regular GNU debugger")
    args = vars(parser.parse_args())

    session_name = "morion"
    window_name  = "morion-pwndbg"

    # Create tmux session
    server = libtmux.Server()
    session = server.new_session(
        session_name=session_name,
        kill_session=True,
        attach=False,
        window_name=window_name
    )

    # Create window and panes
    window = session.windows.get(window_name=window_name)
    pane_gdb = window.panes[0]
    pane_gdb.send_keys("gdb-multiarch -q")
    pane_morion = window.split_window(
        attach=False,
        vertical=False,
        percent=50
    )
    pane_morion.send_keys("morion -h")
    pane_disasm = pane_gdb.split_window(
        attach=False,
        vertical=True,
        percent=30
    )
    pane_gdb.send_keys(
f"""
python
from pwndbg.commands.context import contextoutput
contextoutput("disasm", "{pane_disasm.pane_tty:s}", True)
end
# shell clear
"""
    )

    # Attach tmux session
    server.attach_session(session_name)
    return


if __name__ == "__main__":
    main()