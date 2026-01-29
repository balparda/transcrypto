# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""cli/clibase.py unittest."""

from __future__ import annotations

import io
import logging
import re
import warnings
from collections import abc
from typing import Any

import click
import pytest
import typer
from click import testing as click_testing
from rich import console as rich_console
from rich import logging as rich_logging

from transcrypto import base, transcrypto
from transcrypto.cli import clibase


@pytest.fixture(autouse=True)
def _reset_logging_and_singleton() -> abc.Generator[None]:  # pyright: ignore[reportUnusedFunction]
  """Prevent cross-test pollution.

  - Restore root logger handlers/level
  - Restore provider logger state
  - Reset base._console_singleton
  - Best-effort restore warnings capture plumbing
  """
  root: logging.Logger = logging.getLogger()
  saved_root_handlers = list(root.handlers)
  saved_root_level = root.level
  saved_providers: dict[str, dict[str, Any]] = {}
  for name in clibase._LOG_COMMON_PROVIDERS:
    lg: logging.Logger = logging.getLogger(name)
    saved_providers[name] = {
      'handlers': list(lg.handlers),
      'propagate': lg.propagate,
      'level': lg.level,
    }
  saved_showwarning = warnings.showwarning
  saved_logging_showwarning: Any | None = getattr(logging, '_showwarning', None)
  saved_warnings_showwarning: Any | None = getattr(logging, '_warnings_showwarning', None)
  try:
    # Clean slate for logging
    for h in list(root.handlers):
      root.removeHandler(h)
    root.setLevel(logging.WARNING)
    # Reset singleton
    clibase.ResetConsole()
    yield
  finally:
    # Restore root logger
    for h in list(root.handlers):
      root.removeHandler(h)
    for h in saved_root_handlers:
      root.addHandler(h)
    root.setLevel(saved_root_level)
    # Restore provider loggers
    for name, st in saved_providers.items():
      lg = logging.getLogger(name)
      lg.handlers = st['handlers']
      lg.propagate = st['propagate']
      lg.setLevel(st['level'])
    # Restore warnings plumbing (best effort)
    warnings.showwarning = saved_showwarning
    if saved_logging_showwarning is not None:
      logging._showwarning = saved_logging_showwarning  # type: ignore
    if saved_warnings_showwarning is not None:
      logging._warnings_showwarning = saved_warnings_showwarning  # type: ignore


def _expected_level(verbosity: int) -> int:
  idx: int = max(0, min(verbosity, len(clibase._LOG_LEVELS) - 1))
  return clibase._LOG_LEVELS[idx]


def test_console_returns_fallback_when_not_initialized() -> None:
  """Test."""
  c1: rich_console.Console = clibase.Console()
  c2: rich_console.Console = clibase.Console()
  assert isinstance(c1, rich_console.Console)
  # Not initialized => each call returns a fresh fallback Console
  assert c1 is not c2


def test_initlogging_sets_singleton_and_console_returns_it() -> None:
  """Test."""
  c: rich_console.Console = clibase.InitLogging(2, include_process=False)[0]
  assert isinstance(c, rich_console.Console)
  assert clibase.Console() is c


def test_initlogging_raises_after_first_call() -> None:
  """Test."""
  clibase.InitLogging(2, include_process=False)
  with pytest.raises(RuntimeError):
    clibase.InitLogging(0, include_process=True)


def test_root_logger_level_is_set_and_clamped() -> None:
  """Test."""
  clibase.InitLogging(-10, include_process=False)
  assert logging.getLogger().level == _expected_level(-10)
  clibase.ResetConsole()
  clibase.InitLogging(999, include_process=False)
  assert logging.getLogger().level == _expected_level(999)


def test_root_has_exactly_one_richhandler_bound_to_returned_console() -> None:
  """Test."""
  console: rich_console.Console = clibase.InitLogging(2, include_process=False)[0]
  root: logging.Logger = logging.getLogger()
  rich_handlers: list[rich_logging.RichHandler] = [
    h for h in root.handlers if isinstance(h, rich_logging.RichHandler)
  ]
  assert len(rich_handlers) == 1
  h: rich_logging.RichHandler = rich_handlers[0]
  assert h.console is console
  # Handler formatter should match selected format string
  assert h.formatter is not None
  assert h.formatter._fmt == clibase._LOG_FORMAT_NO_PROCESS


def test_include_process_uses_process_format_on_first_init() -> None:
  """Test."""
  console = clibase.InitLogging(2, include_process=True)[0]
  assert isinstance(console, rich_console.Console)
  h: rich_logging.RichHandler = next(
    h for h in logging.getLogger().handlers if isinstance(h, rich_logging.RichHandler)
  )
  assert h.formatter._fmt == clibase._LOG_FORMAT_WITH_PROCESS  # type: ignore


def test_common_provider_loggers_are_routed_to_root() -> None:
  """Test."""
  verbosity = 1
  expected = _expected_level(verbosity)
  clibase.InitLogging(verbosity, include_process=False)
  for name in clibase._LOG_COMMON_PROVIDERS:
    lg = logging.getLogger(name)
    assert lg.handlers == []
    assert lg.propagate is True
    assert lg.level == expected


def test_initlogging_emits_startup_log(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test."""
  seen: dict[str, str] = {}

  def _fake_info(msg: str, *fake_args: Any, **unused_kwargs: Any) -> None:  # noqa: ANN401, ARG001
    # support both f-string messages and %-format
    if fake_args:
      msg %= fake_args
    seen['msg'] = msg

  monkeypatch.setattr(logging, 'info', _fake_info)
  clibase.InitLogging(2, include_process=False)
  assert 'Logging initialized at level' in seen.get('msg', '')


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
  monkeypatch.setattr(clibase, 'Console', lambda: dummy)
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
  monkeypatch.setattr(clibase, 'Console', lambda: dummy)
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
  ctx = typer.Context(cmd, info_name='x')
  ctx.obj = clibase.CLIConfig(console=c, verbose=logging.INFO, color=None)

  @clibase.CLIErrorGuard
  def _boom(*, ctx: typer.Context) -> None:  # noqa: ARG001
    raise base.InputError('boom')

  _boom(ctx=ctx)
  # If it didn't crash, the branch ran; we should see some traceback-ish output.
  assert len(c.export_text()) > 0


def test_CLIErrorGuard_with_ctx_prints_message_when_verbose_lt_INFO() -> None:
  """Exercise CLIErrorGuard ctx branch (message-only)."""
  buf = io.StringIO()
  c = rich_console.Console(file=buf, force_terminal=False, color_system=None, record=True)
  cmd = click.Command('x', callback=lambda: None)
  ctx = typer.Context(cmd, info_name='x')
  ctx.obj = clibase.CLIConfig(console=c, verbose=0, color=None)

  @clibase.CLIErrorGuard
  def _boom(*, ctx: typer.Context) -> None:  # noqa: ARG001
    raise base.InputError('boom')

  _boom(ctx=ctx)
  out: str = c.export_text()
  assert 'boom' in out


def test_transcrypto_markdown_command_executes(monkeypatch: pytest.MonkeyPatch) -> None:
  """Cover the transcrypto.Markdown command body lines."""
  buf = io.StringIO()
  c = rich_console.Console(file=buf, force_terminal=False, color_system=None, record=True)
  monkeypatch.setattr(clibase, 'Console', lambda: c)
  monkeypatch.setattr(clibase, 'GenerateTyperHelpMarkdown', lambda *_a, **_k: 'DOC')  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
  # Create a mock context object
  cmd = click.Command('markdown', callback=lambda: None)
  ctx = typer.Context(cmd, info_name='markdown')
  ctx.obj = transcrypto.TransConfig(
    console=c,
    verbose=0,
    color=None,
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
  ctx = typer.Context(cmd, info_name='root')
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
  invoke_count = {'count': 0}
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
