class Shell:

    @staticmethod
    def interact(entry_msg: str = '', **kwargs) -> None:
        import readline
        import code

        def __quit():
            raise SystemExit

        vars  = locals().copy()
        vars.update(kwargs)
        vars.update({'quit': __quit, 'exit': __quit})
        vars.update(globals())

        entry_msg = f"""
                      _                   _          _ _ 
 _ __ ___   ___  _ __(_) ___  _ __    ___| |__   ___| | |
| '_ ` _ \ / _ \| '__| |/ _ \| '_ \  / __| '_ \ / _ \ | |
| | | | | | (_) | |  | | (_) | | | | \__ \ | | |  __/ | |
|_| |_| |_|\___/|_|  |_|\___/|_| |_| |___/_| |_|\___|_|_|

{entry_msg:s}

Available objects:"""
        for key in kwargs.keys():
            entry_msg = f"""
{entry_msg:s}
- {key:s}"""
        entry_msg = f"""
{entry_msg:s}

Type quit() or ctrl-d to leave the interpreter.
"""

        shell = code.InteractiveConsole(vars)
        try:
            shell.interact(entry_msg)
        except SystemExit:
            pass
        
        return