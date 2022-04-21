#!/usr/bin/env python3
## -*- coding: utf-8 -*-
from   __future__ import print_function
from   datetime   import datetime
from   termcolor  import colored
from   typing     import List
import sys


class Logger:
    """
    Print colored log messages to stdout and stderr.
    """

    def __init__(self, level: str = 'info') -> None:
        self.set_level(level)

    def _print(self, tag: str, msg: str, color: str, on_color: str = None,
               attrs: List[str] = [], file = sys.stdout) -> None:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(colored(f"[{now:s}] [{tag:s}] {msg:s}", color=color, on_color=on_color, attrs=attrs),
              file=file)

    def set_level(self, level: str) -> None:
        level = level.lower()
        if level == 'debug':
            self.level = 0
        elif level == 'info':
            self.level = 1
        elif level == 'warning':
            self.level = 2
        elif level == 'error':
            self.level = 3
        else:
            self.level = 4

    def debug(self, msg: str, color: str = 'magenta', on_color: str = None,
              attrs: List[str] = []) -> None:
        if self.level <= 0:
            self._print('DEBG', msg, color, on_color=on_color, attrs=attrs, file=sys.stdout)

    def info(self, msg: str, color: str = 'blue', on_color: str = None,
             attrs: List[str] = []) -> None:
        if self.level <= 1:
            self._print('INFO', msg, color, on_color=on_color, attrs=attrs, file=sys.stdout)

    def warning(self, msg: str, color: str = 'yellow', on_color: str = None,
                attrs: List[str] = []) -> None:
        if self.level <= 2:
            self._print('WARN', msg, color, on_color=on_color, attrs=attrs, file=sys.stderr)

    def error(self, msg: str, color: str = 'red', on_color: str = None,
              attrs: List[str] = []) -> None:
        if self.level <= 3:
            self._print('ERRR', msg, color, on_color=on_color, attrs=attrs, file=sys.stderr)

    def critical(self, msg: str, color: str = 'red', on_color: str = None,
                 attrs: List[str] = []) -> None:
        if self.level <= 4:
            self._print('CRIT', msg, color, on_color=on_color, attrs=attrs.append('dark'), file=sys.stderr)
