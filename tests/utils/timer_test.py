# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/timer.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/timer_test.py
"""

from __future__ import annotations

import datetime
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


def test_DatetimeFromISO_naive_gets_utc() -> None:
  """Test: naive ISO string is treated as UTC."""
  dt: datetime.datetime = timer.DatetimeFromISO('2024-06-15T12:30:00')
  assert dt.tzinfo is datetime.UTC
  assert dt == datetime.datetime(2024, 6, 15, 12, 30, 0, tzinfo=datetime.UTC)


def test_DatetimeFromISO_with_utc_offset_preserved() -> None:
  """Test: ISO string with explicit UTC offset is preserved."""
  dt: datetime.datetime = timer.DatetimeFromISO('2024-06-15T12:30:00+00:00')
  assert dt.tzinfo is not None
  assert dt.utcoffset() == datetime.timedelta(0)
  assert dt.year == 2024 and dt.hour == 12


def test_DatetimeFromISO_with_non_utc_offset_preserved() -> None:
  """Test: ISO string with non-UTC offset keeps that offset."""
  dt = timer.DatetimeFromISO('2024-06-15T14:30:00+02:00')
  assert dt.tzinfo is not None
  assert dt.utcoffset() == datetime.timedelta(hours=2)
  assert dt.hour == 14


def test_ISOFromDatetime_utc_aware() -> None:
  """Test: UTC-aware datetime round-trips correctly."""
  dt = datetime.datetime(2024, 6, 15, 12, 30, 0, tzinfo=datetime.UTC)
  s: str = timer.ISOFromDatetime(dt)
  assert s == '2024-06-15T12:30:00+00:00'


def test_ISOFromDatetime_naive() -> None:
  """Test: naive datetime produces ISO string without tz offset."""
  dt = datetime.datetime(2024, 1, 1, 0, 0, 0)  # noqa: DTZ001
  s: str = timer.ISOFromDatetime(dt)
  assert s == '2024-01-01T00:00:00'


def test_ISOFromDatetime_roundtrip() -> None:
  """Test: DatetimeFromISO(ISOFromDatetime(dt)) round-trips for UTC datetimes."""
  original = datetime.datetime(2025, 3, 20, 8, 0, 0, tzinfo=datetime.UTC)
  assert timer.DatetimeFromISO(timer.ISOFromDatetime(original)) == original


def test_UTCDatetimeFromUnix_epoch() -> None:
  """Test: Unix timestamp 0 → 1970-01-01 00:00:00 UTC."""
  dt = timer.UTCDatetimeFromUnix(0.0)
  assert dt == datetime.datetime(1970, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)


def test_UTCDatetimeFromUnix_known_value() -> None:
  """Test: known timestamp maps to the expected UTC datetime."""
  # 2000-01-01 00:00:00 UTC = 946684800
  dt: datetime.datetime = timer.UTCDatetimeFromUnix(946684800.0)
  assert dt == datetime.datetime(2000, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)


def test_UTCDatetimeFromUnix_is_utc_aware() -> None:
  """Test: result is always timezone-aware and UTC."""
  dt: datetime.datetime = timer.UTCDatetimeFromUnix(1_000_000.0)
  assert dt.tzinfo is datetime.UTC


# ---------------------------------------------------------------------------
# Timer class tests
# ---------------------------------------------------------------------------


def _mock_perf(monkeypatch: pytest.MonkeyPatch, values: list[float]) -> None:
  """Install a perf_counter that yields from `values`."""
  it: abc.Iterator[float] = iter(values)
  monkeypatch.setattr(time, 'perf_counter', lambda: next(it))


def testTimerElapsedNotStarted() -> None:
  """Elapsed returns 0.0 before Start() is called."""
  tmr = timer.Timer('x')
  assert tmr.elapsed == pytest.approx(0.0)  # pyright: ignore[reportUnknownMemberType]


def testTimerElapsedWhileRunning(monkeypatch: pytest.MonkeyPatch) -> None:
  """Elapsed returns live value when started but not yet stopped."""
  _mock_perf(monkeypatch, [1.0, 1.5])
  tmr = timer.Timer('x', emit_log=False)
  tmr.Start()
  assert tmr.elapsed == pytest.approx(0.5)  # pyright: ignore[reportUnknownMemberType]


def testTimerElapsedAfterStop(monkeypatch: pytest.MonkeyPatch) -> None:
  """Elapsed returns stable value once stopped."""
  _mock_perf(monkeypatch, [2.0, 3.0])
  tmr = timer.Timer('x', emit_log=False)
  tmr.Start()
  tmr.Stop()
  assert tmr.elapsed == pytest.approx(1.0)  # pyright: ignore[reportUnknownMemberType]
  # elapsed must remain stable even though perf_counter is exhausted
  assert tmr.elapsed == pytest.approx(1.0)  # pyright: ignore[reportUnknownMemberType]


def testTimerElapsedNegativeDelta() -> None:
  """Elapsed raises base.Error if delta is somehow negative (invariant guard)."""
  tmr = timer.Timer('x')
  tmr.start = 10.0  # type: ignore[assignment]
  tmr.end = 5.0  # type: ignore[assignment]  # end < start → negative delta
  with pytest.raises(base.Error, match='negative delta'):
    _ = tmr.elapsed


def testTimerStr(monkeypatch: pytest.MonkeyPatch) -> None:
  """__str__ returns a human-readable elapsed time string."""
  _mock_perf(monkeypatch, [0.0, 1.0])
  tmr = timer.Timer('y', emit_log=False)
  tmr.Start()
  tmr.Stop()
  assert str(tmr) == '1.000 s'


def testTimerStart_setsStart(monkeypatch: pytest.MonkeyPatch) -> None:
  """Start() sets self.start to the current perf_counter value."""
  _mock_perf(monkeypatch, [42.0])
  tmr = timer.Timer(emit_log=False)
  assert tmr.start is None
  tmr.Start()
  assert tmr.start == pytest.approx(42.0)  # pyright: ignore[reportUnknownMemberType]


def testTimerReStart_raises() -> None:
  """Start() raises base.Error when called on an already-started timer."""
  tmr = timer.Timer(emit_log=False)
  tmr.Start()
  with pytest.raises(base.Error, match='Re-starting'):
    tmr.Start()


def testTimerStopUnstarted_raises() -> None:
  """Stop() raises base.Error when the timer was never started."""
  tmr = timer.Timer(emit_log=False)
  with pytest.raises(base.Error, match='unstarted'):
    tmr.Stop()


def testTimerReStop_doesNotRaise(monkeypatch: pytest.MonkeyPatch) -> None:
  """Stop() may be called more than once; re-stopping is allowed (logs a warning)."""
  _mock_perf(monkeypatch, [0.0, 1.0, 2.0])
  tmr = timer.Timer('restart', emit_log=False)
  tmr.Start()
  tmr.Stop()  # first stop: end = 1.0
  # second stop must NOT raise — it logs a warning and updates end
  tmr.Stop()  # re-stop: end = 2.0
  assert tmr.end == pytest.approx(2.0)  # pyright: ignore[reportUnknownMemberType]


def testTimerStop_emitLog(monkeypatch: pytest.MonkeyPatch) -> None:
  """Stop() calls logging.info when emit_log=True (default)."""
  _mock_perf(monkeypatch, [0.0, 0.5])
  records: list[logging.LogRecord] = []
  root: logging.Logger = logging.getLogger()

  class _Capture(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:  # noqa: PLR6301
      records.append(record)

  capture = _Capture()
  capture.setLevel(logging.DEBUG)
  root.addHandler(capture)
  root.setLevel(logging.DEBUG)
  try:
    tmr = timer.Timer('timed')
    tmr.Start()
    tmr.Stop()
  finally:
    root.removeHandler(capture)
    root.setLevel(logging.WARNING)
  assert any('timed' in r.getMessage() for r in records)


def testTimerStop_emitLogFalse(monkeypatch: pytest.MonkeyPatch) -> None:
  """Stop() does NOT call logging.info when emit_log=False."""
  _mock_perf(monkeypatch, [0.0, 0.5])
  records: list[logging.LogRecord] = []
  root: logging.Logger = logging.getLogger()

  class _Capture(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:  # noqa: PLR6301
      records.append(record)

  capture = _Capture()
  capture.setLevel(logging.DEBUG)
  root.addHandler(capture)
  root.setLevel(logging.DEBUG)
  try:
    tmr = timer.Timer('silent', emit_log=False)
    tmr.Start()
    tmr.Stop()
  finally:
    root.removeHandler(capture)
    root.setLevel(logging.WARNING)
  assert not any('silent' in r.getMessage() for r in records)


def testTimerStop_emitPrint(monkeypatch: pytest.MonkeyPatch) -> None:
  """Stop() calls emit_print callable with the formatted message when provided."""
  _mock_perf(monkeypatch, [0.0, 1.0])
  printed: list[str] = []
  tmr = timer.Timer('printed', emit_log=False, emit_print=printed.append)
  tmr.Start()
  tmr.Stop()
  assert len(printed) == 1
  assert 'printed' in printed[0]
  assert '1.000 s' in printed[0]


def testTimerContextManager(monkeypatch: pytest.MonkeyPatch) -> None:
  """Timer works as a context manager: starts on entry, stops on exit."""
  _mock_perf(monkeypatch, [0.0, 0.75])
  with timer.Timer('ctx', emit_log=False) as tmr:
    assert tmr.start is not None
  assert tmr.end is not None
  assert tmr.elapsed == pytest.approx(0.75)  # pyright: ignore[reportUnknownMemberType]


def testTimerDecorator(monkeypatch: pytest.MonkeyPatch) -> None:
  """Timer works as a decorator: each call is timed independently."""
  _mock_perf(monkeypatch, [0.0, 0.2, 0.0, 0.3])
  printed: list[str] = []

  @timer.Timer('deco', emit_log=False, emit_print=printed.append)
  def _Inner() -> int:
    return 42

  assert _Inner() == 42
  assert len(printed) == 1
  assert 'deco' in printed[0]


def testTimerDecorator_multipleCallsIndependent(monkeypatch: pytest.MonkeyPatch) -> None:
  """Each decorated call gets its own fresh Timer instance."""
  _mock_perf(monkeypatch, [0.0, 0.1, 0.0, 0.2])
  printed: list[str] = []

  @timer.Timer('multi', emit_log=False, emit_print=printed.append)
  def _F() -> None:
    pass

  _F()
  _F()
  assert len(printed) == 2  # two separate timing entries
