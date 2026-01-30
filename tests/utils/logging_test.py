# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/logging.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/logging_test.py
"""

from __future__ import annotations

import logging
import warnings
from collections import abc
from typing import Any

import pytest
from rich import console as rich_console
from rich import logging as rich_logging

from transcrypto.cli import clibase


@pytest.fixture(autouse=True)
def reset_logging_and_singleton() -> abc.Generator[None]:
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
  expected: int = _expected_level(verbosity)
  clibase.InitLogging(verbosity, include_process=False)
  for name in clibase._LOG_COMMON_PROVIDERS:
    lg: logging.Logger = logging.getLogger(name)
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
