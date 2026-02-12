# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/timer.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/timer_test.py
"""

from __future__ import annotations

import logging
import time
from collections import abc

import pytest

from transcrypto.utils import base, timer


@pytest.fixture(autouse=True)
def ResetLoggingHandlers() -> abc.Generator[None]:
  """Reset logging handlers before and after each test to prevent pollution."""
  root: logging.Logger = logging.getLogger()
  saved_handlers: list[logging.Handler] = list(root.handlers)
  saved_level: int = root.level
  try:
    for h in list(root.handlers):
      root.removeHandler(h)
    root.setLevel(logging.WARNING)
    yield
  finally:
    for h in list(root.handlers):
      root.removeHandler(h)
    for h in saved_handlers:
      root.addHandler(h)
    root.setLevel(saved_level)


def test_time_utils() -> None:
  """Test."""
  assert timer.MIN_TM == 946684800
  assert timer.TimeStr(timer.MIN_TM) == '2000/Jan/01-00:00:00-UTC'
  assert timer.Now() > timer.MIN_TM
  assert timer.StrNow()


def _mock_perf(monkeypatch: pytest.MonkeyPatch, values: list[float]) -> None:
  """Install a perf_counter that yields from `values`."""
  it: abc.Iterator[float] = iter(values)
  monkeypatch.setattr(time, 'perf_counter', lambda: next(it))


def test_Timer_str_unstarted() -> None:
  """Test."""
  t = timer.Timer('T')
  assert str(t) == 'T: <UNSTARTED>'


def test_Timer_str_partial(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test."""
  # Start at 100.00; __str__ calls perf_counter again (100.12) → delta 0.12 s
  _mock_perf(monkeypatch, [100.00, 100.12])
  t = timer.Timer('P')
  t.Start()
  assert str(t) == 'P: <PARTIAL> 120.000 ms'


def test_Timer_start_twice_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test."""
  _mock_perf(monkeypatch, [1.0])
  t = timer.Timer('X')
  t.Start()
  with pytest.raises(base.Error, match='Re-starting timer is forbidden'):
    t.Start()


def test_Timer_stop_unstarted_forbidden() -> None:
  """Test."""
  t = timer.Timer('X')
  with pytest.raises(base.Error, match='Stopping an unstarted timer'):
    t.Stop()


def test_Timer_negative_elapsed(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test."""
  _mock_perf(monkeypatch, [1.0, 0.5])
  t = timer.Timer('X')
  t.Start()
  with pytest.raises(base.Error, match='negative/zero delta'):
    t.Stop()


def test_Timer_stop_twice_forbidden(
  monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
  """Test."""
  # Start=1.0, Stop=2.5  → elapsed=1.5
  _mock_perf(monkeypatch, [1.0, 2.5])
  caplog.set_level(logging.INFO)
  t = timer.Timer('X')
  t.Start()
  t.Stop()
  # A second Stop should error
  with pytest.raises(base.Error, match='Re-stopping timer is forbidden'):
    t.Stop()
  # Final string reflects final (not partial)
  assert str(t) == 'X: 1.500 s'
  # Logged exactly once
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['X: 1.500 s']


def test_Timer_context_manager_logs_and_optionally_prints(
  monkeypatch: pytest.MonkeyPatch,
  caplog: pytest.LogCaptureFixture,
  capsys: pytest.CaptureFixture[str],
) -> None:
  """Test."""
  # Enter=10.00, Exit=10.25 → 0.25 s
  _mock_perf(monkeypatch, [10.00, 10.25])
  caplog.set_level(logging.INFO)
  with timer.Timer('CTX', emit_print=print):
    pass
  # Logged
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['CTX: 250.000 ms']
  # Printed (because emit_print=True in __exit__)
  out: str = capsys.readouterr().out.strip()
  assert out == 'CTX: 250.000 ms'


def test_Timer_context_manager_exception_still_times_and_logs(
  monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
  """Test."""  # noqa: DOC501
  # Enter=5.0, Exit=5.3 → 0.3 s even if exception occurs
  _mock_perf(monkeypatch, [5.0, 5.3])
  caplog.set_level(logging.INFO)

  with pytest.raises(base.Error), timer.Timer('ERR'):
    raise base.Error('boom')
  # Stop was called; message logged
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['ERR: 300.000 ms']


def test_Timer_decorator_logs(
  monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
  """Test."""
  # Start=1.00, Stop=1.40 → 0.40 s
  _mock_perf(monkeypatch, [1.00, 1.40])
  caplog.set_level(logging.INFO)

  @timer.Timer('DEC')
  def _f(a: int, b: int) -> int:
    return a + b

  assert _f(2, 3) == 5
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['DEC: 400.000 ms']


def test_Timer_decorator_emit_print_true_prints_and_logs(
  monkeypatch: pytest.MonkeyPatch,
  caplog: pytest.LogCaptureFixture,
  capsys: pytest.CaptureFixture[str],
) -> None:
  """Test."""
  # Start=2.00, Stop=2.01 → 0.01 s
  _mock_perf(monkeypatch, [2.00, 2.01])
  caplog.set_level(logging.INFO)

  @timer.Timer('PRINT', emit_print=print)
  def _g() -> str:
    return 'ok'

  assert _g() == 'ok'
  # Logs (Stop) and prints (in __exit__)
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['PRINT: 10.000 ms']
  out: str = capsys.readouterr().out.strip()
  assert out == 'PRINT: 10.000 ms'


def test_Timer_decorator_exception_propagates_and_logs(
  monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
  """Test."""
  # Start=3.0, Stop=3.2 → 0.2 s even when raising
  _mock_perf(monkeypatch, [3.0, 3.2])
  caplog.set_level(logging.INFO)

  @timer.Timer('ERR')
  def _h() -> None:
    raise base.Error('nope')

  with pytest.raises(base.Error, match='nope'):
    _h()
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['ERR: 200.000 ms']
