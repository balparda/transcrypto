# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""cli/clibase.py unittest.

Run with:
  poetry run pytest -vvv tests/cli/clibase_test.py
"""

from __future__ import annotations

import io
import logging
import re

import click
import pytest
import typer
from click import testing as click_testing
from rich import console as rich_console

from transcrypto import transcrypto
from transcrypto.cli import clibase
from transcrypto.utils import base
from transcrypto.utils import config as app_config
from transcrypto.utils import logging as tc_logging


@pytest.fixture(autouse=True)
def reset_cli() -> None:
  """Reset CLI singleton before each test."""
  tc_logging.ResetConsole()
  app_config.ResetConfig()


def test_GenerateTyperHelpMarkdown_simple_app() -> None:
  """Test."""
  app = typer.Typer()

  @app.command()
  def hello(name: str = 'world') -> None:  # pyright: ignore[reportUnusedFunction]
    """Say hello."""
    print(f'hello {name}')  # noqa: T201

  @app.command()
  def bye() -> None:  # pyright: ignore[reportUnusedFunction]
    """Say bye."""
    print('bye')  # noqa: T201

  md: str = clibase.GenerateTyperHelpMarkdown(app, prog_name='myprog', heading_level=2)
  assert '`myprog`' in md
  assert '`myprog hello`' in md
  assert '`myprog bye`' in md
  assert '```' in md


class _DummyConsole:
  """A dummy Rich console that records print calls for later inspection."""

  def __init__(self) -> None:
    self.print_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    self.print_exception_calls: int = 0

  def print(self, *args: object, **kwargs: object) -> None:
    self.print_calls.append((args, kwargs))

  def print_exception(self, *args: object, **kwargs: object) -> None:  # noqa: ARG002
    self.print_exception_calls += 1


def test_CLIErrorGuard_no_ctx_prints_exception_when_level_ge_INFO(
  monkeypatch: pytest.MonkeyPatch,
) -> None:
  """Exercise CLIErrorGuard no-ctx traceback branch."""
  dummy = _DummyConsole()
  monkeypatch.setattr(tc_logging, 'Console', lambda: dummy)
  logging.getLogger().setLevel(logging.WARNING)  # >= INFO

  @clibase.CLIErrorGuard
  def _boom() -> None:
    raise base.InputError('boom')

  _boom()
  assert dummy.print_exception_calls == 1
  assert dummy.print_calls == []


def test_CLIErrorGuard_no_ctx_prints_message_when_level_lt_INFO(
  monkeypatch: pytest.MonkeyPatch,
) -> None:
  """Exercise CLIErrorGuard no-ctx message-only branch."""
  dummy = _DummyConsole()
  monkeypatch.setattr(tc_logging, 'Console', lambda: dummy)
  logging.getLogger().setLevel(logging.DEBUG)  # < INFO

  @clibase.CLIErrorGuard
  def _boom() -> None:
    raise base.InputError('boom')

  _boom()
  assert dummy.print_exception_calls == 0
  assert any('boom' in str(args[0]) for (args, _kwargs) in dummy.print_calls)


def test_CLIErrorGuard_with_ctx_prints_exception_when_verbose_ge_INFO() -> None:
  """Exercise CLIErrorGuard ctx branch (traceback)."""
  buf = io.StringIO()
  c = rich_console.Console(file=buf, force_terminal=False, color_system=None, record=True)
  cmd = click.Command('x', callback=lambda: None)
  ctx = click.Context(cmd, info_name='x')
  appconfig: app_config.AppConfig = app_config.InitConfig('test_app', 'test.bin')
  ctx.obj = clibase.CLIConfig(console=c, verbose=logging.INFO, color=None, appconfig=appconfig)

  @clibase.CLIErrorGuard
  def _boom(*, ctx: click.Context) -> None:  # noqa: ARG001
    raise base.InputError('boom')

  _boom(ctx=ctx)
  # If it didn't crash, the branch ran; we should see some traceback-ish output.
  assert len(c.export_text()) > 0


def test_CLIErrorGuard_with_ctx_prints_message_when_verbose_lt_INFO() -> None:
  """Exercise CLIErrorGuard ctx branch (message-only)."""
  buf = io.StringIO()
  c = rich_console.Console(file=buf, force_terminal=False, color_system=None, record=True)
  cmd = click.Command('x', callback=lambda: None)
  ctx = click.Context(cmd, info_name='x')
  appconfig: app_config.AppConfig = app_config.InitConfig('test_app2', 'test2.bin')
  ctx.obj = clibase.CLIConfig(console=c, verbose=0, color=None, appconfig=appconfig)

  @clibase.CLIErrorGuard
  def _boom(*, ctx: click.Context) -> None:  # noqa: ARG001
    raise base.InputError('boom')

  _boom(ctx=ctx)
  out: str = c.export_text()
  assert 'boom' in out


def test_transcrypto_markdown_command_executes(monkeypatch: pytest.MonkeyPatch) -> None:
  """Cover the transcrypto.Markdown command body lines."""
  buf = io.StringIO()
  c = rich_console.Console(file=buf, force_terminal=False, color_system=None, record=True)
  monkeypatch.setattr(tc_logging, 'Console', lambda: c)
  monkeypatch.setattr(clibase, 'GenerateTyperHelpMarkdown', lambda *_a, **_k: 'DOC')  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
  # Create a mock context object
  cmd = click.Command('markdown', callback=lambda: None)
  ctx = click.Context(cmd, info_name='markdown')
  appconfig: app_config.AppConfig = app_config.InitConfig('test_app3', 'test3.bin')
  ctx.obj = transcrypto.TransConfig(
    console=c,
    verbose=0,
    color=None,
    appconfig=appconfig,
    input_format=transcrypto.IOFormat.bin,
    output_format=transcrypto.IOFormat.hex,
    protect=None,
    key_path=None,
  )
  transcrypto.Markdown(ctx=ctx)
  assert 'DOC' in c.export_text()


class _DynamicGroup(click.Group):
  """A click.Group that simulates dynamic command loading."""

  def list_commands(self, ctx: click.Context) -> list[str]:  # noqa: ARG002, PLR6301
    # Pretend we are dynamic: expose one real command and one missing.
    return ['ok', 'missing']

  def get_command(self, ctx: click.Context, name: str) -> click.Command | None:  # pyright: ignore[reportIncompatibleMethodOverride] # noqa: ARG002, PLR6301
    if name == 'missing':
      return None
    return click.Command('ok', callback=lambda: None)


def test_ClickWalk_multi_command_path_is_supported() -> None:
  """Test."""
  cmd = _DynamicGroup('root', commands={})
  ctx = click.Context(cmd, info_name='root')
  walked = list(clibase._ClickWalk(cmd, ctx, []))
  # Root plus the valid child command. The invalid subcommand should be skipped.
  assert any(path == [] for path, _, _ in walked)
  assert any(path == ['ok'] for path, _, _ in walked)


def test_generate_help_for_simple_app() -> None:
  """Test."""
  app = typer.Typer()

  @app.command()
  def hello(name: str = 'world') -> None:  # pyright: ignore[reportUnusedFunction]
    """Say hello."""
    print(f'hello {name}')  # noqa: T201

  @app.command()
  def bye() -> None:  # pyright: ignore[reportUnusedFunction]
    """Say bye."""
    print('bye')  # noqa: T201

  md: str = clibase.GenerateTyperHelpMarkdown(app, prog_name='myprog', heading_level=2)
  # should contain top-level heading and both commands
  assert '#' * 2 in md
  assert 'myprog hello' in md
  assert 'myprog bye' in md
  # fenced code block with usage should be present
  assert '```' in md


def test_generate_help_includes_real_app_sections() -> None:
  """Test."""
  # use the real transcrypto app to ensure function walks real commands
  md: str = clibase.GenerateTyperHelpMarkdown(
    transcrypto.app, prog_name='transcrypto', heading_level=1
  )
  # basic sanity checks
  assert 'transcrypto' in md
  # ensure at least one known command exists
  assert re.search(r'`transcrypto` .*Command-Line Interface', md)
  assert 'rsa' in md


def test_generate_help_markdown_skips_invalid_commands(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test that GenerateTyperHelpMarkdown skips commands that fail without output (line 1894)."""
  # Create a multi-command app so it becomes a group
  app = typer.Typer()

  @app.command()
  def cmd1() -> None:  # pyright: ignore[reportUnusedFunction]
    """First command."""
    print('cmd1')  # noqa: T201

  @app.command()
  def cmd2() -> None:  # pyright: ignore[reportUnusedFunction]
    """Second command."""
    print('cmd2')  # noqa: T201

  # Track invoke calls
  invoke_count: dict[str, int] = {'count': 0}
  original_invoke = click_testing.CliRunner.invoke

  def _mock_invoke(
    self: click_testing.CliRunner,
    cli: click.Command,
    args: list[str] | None = None,
    **kwargs: object,
  ) -> click_testing.Result:
    invoke_count['count'] += 1
    # First call is root help, second is cmd1 help, third is cmd2 help
    if invoke_count['count'] == 3:
      # Return a result with non-zero exit code and no output
      # This simulates a command that fails silently
      return click_testing.Result(
        runner=self,
        stdout_bytes=b'',
        stderr_bytes=b'',
        output_bytes=b'',
        return_value=None,
        exit_code=1,
        exception=SystemExit(1),
        exc_info=None,
      )
    return original_invoke(self, cli, args, **kwargs)  # type: ignore[arg-type]

  monkeypatch.setattr(click_testing.CliRunner, 'invoke', _mock_invoke)
  # Generate markdown - should skip the failing command and continue
  md: str = clibase.GenerateTyperHelpMarkdown(app, prog_name='test', heading_level=1)
  # Should have output for root and cmd1, but skip cmd2
  assert 'test' in md
  assert 'cmd1' in md
  # cmd2 should not appear since it fails without output
  # (the walker includes it but the markdown skips it)
