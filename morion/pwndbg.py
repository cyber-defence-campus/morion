#!/usr/bin/env python3
## -*- coding: utf-8 -*-
import argparse
import os
import subprocess
from   typing import List


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    t = subprocess.run(cmd, capture_output=True, text=True)
    return t

def main() -> None:
    # Argument parsing
    description = """
    Use morion together with the GDB-plugin pwndbg.
    """
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-m', '--multiarch',
                        action='store_true',
                        help='use the multi-architecture version of GDB')
    parser.add_argument('-w', '--tmux_window_name',
                        default='morion-pwndbg',
                        help='tmux window name')
    parser.add_argument('-s', '--tmux_session_name',
                        default='morion',
                        help='tmux session name')
    parser.add_argument('-x', '--gdb_cmd_files',
                        nargs='*',
                        help='files with GDB commands to execute')
    args = vars(parser.parse_args())

    # Parameters
    session_name = args['tmux_session_name']
    window_name  = args['tmux_window_name']
    gdb = "gdb-multiarch" if "multiarch" in args else "gdb"
    gdb_cmd_files = [] if args['gdb_cmd_files'] is None else args['gdb_cmd_files']

    # Terminal size
    terminal_size = os.get_terminal_size()

    # Kill a potential previous tmux session
    p = run_cmd([
        'tmux', 'kill-session',             # Kill tmux session
        '-t', session_name                  # Session name
    ])

    # Create new tmux session and pwndbg pane
    p = run_cmd([
        'tmux', 'new-session',                  # New tmux session
        '-d',                                   # Detach session from current terminal
        '-P', '-F', '#{pane_id}:#{pane_tty}',   # Print information
        '-n', window_name,                      # Window name
        '-s', session_name,                     # Session name
        '-x', str(terminal_size.columns),       # Window width
        '-y', str(terminal_size.lines),         # Window height
        gdb, '-q'                               # Shell command
    ])
    pane_pwndbg = p.stdout.strip().split(':')

    # Create stack pane
    p = run_cmd([
        'tmux', 'split-window',                 # Split pane
        '-d',                                   # Do not change active pane
        '-v',                                   # Vertical split
        '-P', '-F', '#{pane_id}:#{pane_tty}',   # Print information
        '-p', '40',                             # Percentage of new pane
        '-t', pane_pwndbg[0]                    # Target pane to split
    ])
    pane_stack = p.stdout.strip().split(':')

    # Create disassembly pane
    p = run_cmd([
        'tmux', 'split-window',                 # Split pane
        '-d',                                   # Do not change active pane
        '-h',                                   # Horizontal split
        '-P', '-F', '#{pane_id}:#{pane_tty}',   # Print information
        '-p', '70',                             # Percentage of new pane
        '-t', pane_stack[0]                     # Target pane to split
    ])
    pane_disasm = p.stdout.strip().split(':')

    # Create registers pane
    p = run_cmd([
        'tmux', 'split-window',                 # Split pane
        '-d',                                   # Do not change active pane
        '-h',                                   # Horizontal split
        '-P', '-F', '#{pane_id}:#{pane_tty}',   # Print information
        '-p', '50',                             # Percentage of new pane
        '-t', pane_disasm[0]                    # Target pane to split
    ])
    pane_regs = p.stdout.strip().split(':')

    # Create backtrace pane
    p = run_cmd([
        'tmux', 'split-window',                 # Split pane
        '-d',                                   # Do not change active pane
        '-v',                                   # Vertical split
        '-P', '-F', '#{pane_id}:#{pane_tty}',   # Print information
        '-p', '50',                             # Percentage of new pane
        '-t', pane_stack[0]                     # Target pane to split
    ])
    pane_backtrace = p.stdout.strip().split(':')

    # Create morion pane
    p = run_cmd([
        'tmux', 'split-window',                 # Split pane
        '-d',                                   # Do not change active pane
        '-h',                                   # Horizontal split
        '-P', '-F', '#{pane_id}:#{pane_tty}',   # Print information
        '-p', '50',                             # Percentage of new pane
        '-t', pane_pwndbg[0]                    # Target pane to split
    ])
    pane_morion = p.stdout.strip().split(':')

    # Configure panes
    layout_pwndbg_contexts = f'''
python
from pwndbg.commands.context import contextoutput
contextoutput("stack", "{pane_stack[1]:s}", True)
contextoutput("backtrace", "{pane_backtrace[1]:s}", True)
contextoutput("disasm", "{pane_disasm[1]:s}", True)
contextoutput("regs", "{pane_regs[1]:s}", True)
contextoutput("legend", "{pane_stack[1]:s}", True)
end
    '''
    p = run_cmd([
        'tmux', 'send',
        '-t', f'{session_name}.{pane_pwndbg[0]:s}',
        layout_pwndbg_contexts, 'ENTER'
    ])
    
    p = run_cmd([
        'tmux', 'send',
        '-t', f'{session_name:s}.{pane_morion[0]:s}',
        'morion -h', 'ENTER'
    ])

    # Run GDB command files
    for gdb_cmd_file in gdb_cmd_files:
        p = run_cmd([
            'tmux', 'send',
            '-t', f'{session_name}.{pane_pwndbg[0]:s}',
            f'source {gdb_cmd_file:s}', 'ENTER'
        ])

    # Attach tmux session
    p = run_cmd([
        'tmux', 'attach',
        '-t', session_name
    ])

    return


if __name__ == "__main__":
    main()