# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's CLI base library."""

from __future__ import annotations

import dataclasses
import functools
import logging
from collections import abc
from typing import cast

import click
import typer
from click import testing as click_testing
from rich import console as rich_console

from transcrypto.utils import base
from transcrypto.utils import logging as tc_logging


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class CLIConfig:
  """CLI global context, storing the configuration.

  Attributes:
    console (rich_console.Console): Rich console instance for output
    verbose (int): Verbosity level (0-3)
    color (bool | None): Color preference (None=auto, True=force, False=disable)

  """

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
        tc_logging.Console().print(str(err))  # print only error message (DEBUG is verbose already)
      else:
        tc_logging.Console().print_exception()  # print full traceback (less verbose mode needs it)

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
    tc_logging.ResetConsole()  # ensure clean state for the command
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
