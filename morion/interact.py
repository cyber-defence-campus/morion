#!/usr/bin/env python3
## -*- coding: utf-8 -*-

class Shell:

    @staticmethod
    def interact(entry_msg: str = '', **kwargs) -> None:
        import code
        import readline
        import sys
        from   pprint import pprint

        # stdin or stdout are not connected to the TTY
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("[!] Morion shell is not supported.")
            return
        
        # Show banner
        entry_msg = [
            f"""
                      _                   _          _ _ 
 _ __ ___   ___  _ __(_) ___  _ __    ___| |__   ___| | |
| '_ ` _ \ / _ \| '__| |/ _ \| '_ \  / __| '_ \ / _ \ | |
| | | | | | (_) | |  | | (_) | | | | \__ \ | | |  __/ | |
|_| |_| |_|\___/|_|  |_|\___/|_| |_| |___/_| |_|\___|_|_|
            """,
            entry_msg,
            "",
            "Available objects:"
        ] + [
            "- " + key for key in kwargs.keys()
        ] + [
            "",
            "Type quit, exit or CTRL-d to leave the interpreter."
        ]
        entry_msg = "\n".join(entry_msg)
        print(entry_msg)

        # stdin and stdout are connected to the TTY
        ns = kwargs
        ns['pprint'] = pprint
        try:
            import IPython
        except ImportError:
            # Use regular Python interpreter
            def __raise_sys_exit(): raise SystemExit
            try:
                ns.update({'quit': __raise_sys_exit, 'exit': __raise_sys_exit})
                code.InteractiveConsole(ns).interact('', '')
            except SystemExit:
                pass
        else:
            # Use IPython interpreter
            console = IPython.terminal.embed.InteractiveShellEmbed(argv=[], display_banner=False, user_ns=ns)
            console()

        return