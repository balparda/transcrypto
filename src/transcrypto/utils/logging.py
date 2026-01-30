# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto logging library."""

from __future__ import annotations

import logging
import os
import threading

from rich import console as rich_console
from rich import logging as rich_logging

from transcrypto.utils import base

# Logging
_LOG_FORMAT_NO_PROCESS: str = '%(funcName)s: %(message)s'
_LOG_FORMAT_WITH_PROCESS: str = '%(processName)s/' + _LOG_FORMAT_NO_PROCESS
_LOG_FORMAT_DATETIME: str = '[%Y%m%d-%H:%M:%S]'  # e.g., [20240131-13:45:30]
_LOG_LEVELS: dict[int, int] = {
  0: logging.ERROR,
  1: logging.WARNING,
  2: logging.INFO,
  3: logging.DEBUG,
}
_LOG_COMMON_PROVIDERS: set[str] = {
  'werkzeug',
  'gunicorn.error',
  'gunicorn.access',
  'uvicorn',
  'uvicorn.error',
  'uvicorn.access',
  'django.server',
}

__console_lock: threading.RLock = threading.RLock()
__console_singleton: rich_console.Console | None = None


def Console() -> rich_console.Console:
  """Get the global console instance.

  Returns:
    rich.console.Console: The global console instance.

  """
  with __console_lock:
    if __console_singleton is None:
      return rich_console.Console()  # fallback console if InitLogging hasn't been called yet
    return __console_singleton


def ResetConsole() -> None:
  """Reset the global console instance."""
  global __console_singleton  # noqa: PLW0603
  with __console_lock:
    __console_singleton = None


def InitLogging(
  verbosity: int,
  /,
  *,
  include_process: bool = False,
  soft_wrap: bool = False,
  color: bool | None = False,
) -> tuple[rich_console.Console, int, bool]:
  """Initialize logger (with RichHandler) and get a rich.console.Console singleton.

  This method will also return the actual decided values for verbosity and color use.
  If you have a CLI app that uses this, its pytests should call `ResetConsole()` in a fixture, like:

      from transcrypto.utils import logging
      @pytest.fixture(autouse=True)
      def _reset_base_logging() -> Generator[None, None, None]:  # type: ignore
        logging.ResetConsole()
        yield  # stop

  Args:
    verbosity (int): Logging verbosity level: 0==ERROR, 1==WARNING, 2==INFO, 3==DEBUG
    include_process (bool, optional): Whether to include process name in log output.
    soft_wrap (bool, optional): Whether to enable soft wrapping in the console.
        Default is False, and it means rich will hard-wrap long lines (by adding line breaks).
    color (bool | None, optional): Whether to enable/disable color output in the console.
        If None, respects NO_COLOR env var.

  Returns:
    tuple[rich_console.Console, int, bool]:
        (The initialized console instance, actual log level, actual color use)

  Raises:
    base.Error: if you call this more than once

  """
  global __console_singleton  # noqa: PLW0603
  with __console_lock:
    if __console_singleton is not None:
      raise base.Error(
        'calling InitLogging() more than once is forbidden; '
        'use Console() to get a console after first creation'
      )
    # set level
    logging_level: int = _LOG_LEVELS.get(min(verbosity, 3), logging.ERROR)
    # respect NO_COLOR unless the caller has already decided (treat env presence as "disable color")
    no_color: bool = (
      False
      if (os.getenv('NO_COLOR') is None and color is None)
      else ((os.getenv('NO_COLOR') is not None) if color is None else (not color))
    )
    # create console and configure logging
    console = rich_console.Console(soft_wrap=soft_wrap, no_color=no_color)
    logging.basicConfig(
      level=logging_level,
      format=_LOG_FORMAT_WITH_PROCESS if include_process else _LOG_FORMAT_NO_PROCESS,
      datefmt=_LOG_FORMAT_DATETIME,
      handlers=[
        rich_logging.RichHandler(  # we show name/line, but want time & level
          console=console,
          rich_tracebacks=True,
          show_time=True,
          show_level=True,
          show_path=True,
        ),
      ],
      force=True,  # force=True to override any previous logging config
    )
    # configure common loggers
    logging.captureWarnings(True)
    for name in _LOG_COMMON_PROVIDERS:
      log: logging.Logger = logging.getLogger(name)
      log.handlers.clear()
      log.propagate = True
      log.setLevel(logging_level)
    __console_singleton = console  # need a global statement to re-bind this one
    logging.info(
      f'Logging initialized at level {logging.getLevelName(logging_level)} / '
      f'{"NO " if no_color else ""}COLOR'
    )
    return (console, logging_level, not no_color)
