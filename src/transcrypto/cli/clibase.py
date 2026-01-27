# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's CLI base library."""

from __future__ import annotations

import dataclasses
import functools
import logging
import os
import threading
from collections import abc
from typing import cast

import click
import typer
from click import testing as click_testing
from rich import console as rich_console
from rich import logging as rich_logging

from transcrypto import base

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

      from transcrypto import logging
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
    RuntimeError: if you call this more than once

  """
  global __console_singleton  # noqa: PLW0603
  with __console_lock:
    if __console_singleton is not None:
      raise RuntimeError(
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


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class CLIConfig:
  """CLI global context, storing the configuration."""

  console: rich_console.Console
  verbose: int
  color: bool | None


def CLIErrorGuard[**P](fn: abc.Callable[P, None], /) -> abc.Callable[P, None]:
  """Guard CLI command functions.

  Returns:
    A wrapped function that catches expected user-facing errors and prints them consistently.

  """

  @functools.wraps(fn)
  def _Wrapper(*args: P.args, **kwargs: P.kwargs) -> None:
    try:
      # call the actual function
      fn(*args, **kwargs)
    except (base.Error, ValueError) as err:
      # get context
      ctx: object | None = dict(kwargs).get('ctx')
      if not isinstance(ctx, typer.Context):
        ctx = next((a for a in args if isinstance(a, typer.Context)), None)
      # print error nicely
      if isinstance(ctx, typer.Context):
        # we have context
        obj: CLIConfig = cast('CLIConfig', ctx.obj)
        if obj.verbose >= 2:  # verbose >= 2 means INFO level or more verbose  # noqa: PLR2004
          obj.console.print_exception()  # print full traceback
        else:
          obj.console.print(str(err))  # print only error message
      # no context
      elif logging.getLogger().getEffectiveLevel() < logging.INFO:
        Console().print(str(err))  # print only error message (DEBUG level is verbose already)
      else:
        Console().print_exception()  # print full traceback (less verbose mode needs it)

  return _Wrapper


def _ClickWalk(
  command: click.Command,
  ctx: typer.Context,
  path: list[str],
  /,
) -> abc.Iterator[tuple[list[str], click.Command, typer.Context]]:
  """Recursively walk Click commands/groups.

  Yields:
    tuple[list[str], click.Command, typer.Context]: path, command, ctx

  """
  yield (path, command, ctx)  # yield self
  # now walk subcommands, if any
  sub_cmd: click.Command | None
  sub_ctx: typer.Context
  # prefer the explicit `.commands` mapping when present; otherwise fall back to
  # click's `list_commands()`/`get_command()` for dynamic groups
  if not isinstance(command, click.Group):
    return
  # explicit commands mapping
  if command.commands:
    for name, sub_cmd in sorted(command.commands.items()):
      sub_ctx = typer.Context(sub_cmd, info_name=name, parent=ctx)
      yield from _ClickWalk(sub_cmd, sub_ctx, [*path, name])
    return
  # dynamic commands
  for name in sorted(command.list_commands(ctx)):
    sub_cmd = command.get_command(ctx, name)
    if sub_cmd is None:
      continue  # skip invalid subcommands
    sub_ctx = typer.Context(sub_cmd, info_name=name, parent=ctx)
    yield from _ClickWalk(sub_cmd, sub_ctx, [*path, name])


def GenerateTyperHelpMarkdown(
  typer_app: typer.Typer,
  /,
  *,
  prog_name: str,
  heading_level: int = 1,
  code_fence_language: str = 'text',
) -> str:
  """Capture `--help` for a Typer CLI and all subcommands as Markdown.

  This function converts a Typer app to its underlying Click command tree and then:
  - invokes `--help` for the root ("Main") command
  - walks commands/subcommands recursively
  - invokes `--help` for each command path

  It emits a Markdown document with a heading per command and a fenced block
  containing the exact `--help` output.

  Notes:
    - This uses Click's `CliRunner().invoke(...)` for faithful output.
    - The walk is generic over Click `MultiCommand`/`Group` structures.
    - If a command cannot be loaded, it is skipped.

  Args:
    typer_app: The Typer app (e.g. `app`).
    prog_name: Program name used in usage strings (e.g. "profiler").
    heading_level: Markdown heading level for each command section.
    code_fence_language: Language tag for fenced blocks (default: "text").

  Returns:
    Markdown string.

  """
  # prepare Click root command and context
  click_root: click.Command = typer.main.get_command(typer_app)
  root_ctx: typer.Context = typer.Context(click_root, info_name=prog_name)
  runner = click_testing.CliRunner()
  parts: list[str] = []
  for path, _, _ in _ClickWalk(click_root, root_ctx, []):
    # build command path
    command_path: str = ' '.join([prog_name, *path]).strip()
    heading_prefix: str = '#' * max(1, heading_level + len(path))
    ResetConsole()  # ensure clean state for each command (also it raises on duplicate loggers)
    # invoke --help for this command path
    result: click_testing.Result = runner.invoke(
      click_root,
      [*path, '--help'],
      prog_name=prog_name,
      color=False,
    )
    if result.exit_code != 0 and not result.output:
      continue  # skip invalid commands
    # build markdown section
    global_prefix: str = (  # only for the top-level command
      (
        '<!-- cspell:disable -->\n'
        '<!-- auto-generated; DO NOT EDIT! see base.GenerateTyperHelpMarkdown() -->\n\n'
      )
      if not path
      else ''
    )
    extras: str = (  # type of command, by level
      ('Command-Line Interface' if not path else 'Command') if len(path) <= 1 else 'Sub-Command'
    )
    parts.extend(
      (
        f'{global_prefix}{heading_prefix} `{command_path}` {extras}',
        '',
        f'```{code_fence_language}',
        result.output.strip(),
        '```',
        '',
      )
    )
  # join all parts and return
  return '\n'.join(parts).rstrip()
