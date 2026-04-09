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

from transcrypto.utils import timer


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
  dt = timer.DatetimeFromISO('2024-06-15T12:30:00')
  assert dt.tzinfo is datetime.UTC
  assert dt == datetime.datetime(2024, 6, 15, 12, 30, 0, tzinfo=datetime.UTC)


def test_DatetimeFromISO_with_utc_offset_preserved() -> None:
  """Test: ISO string with explicit UTC offset is preserved."""
  dt = timer.DatetimeFromISO('2024-06-15T12:30:00+00:00')
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
  s = timer.ISOFromDatetime(dt)
  assert s == '2024-06-15T12:30:00+00:00'


def test_ISOFromDatetime_naive() -> None:
  """Test: naive datetime produces ISO string without tz offset."""
  dt = datetime.datetime(2024, 1, 1, 0, 0, 0)  # noqa: DTZ001
  s = timer.ISOFromDatetime(dt)
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
  dt = timer.UTCDatetimeFromUnix(946684800.0)
  assert dt == datetime.datetime(2000, 1, 1, 0, 0, 0, tzinfo=datetime.UTC)


def test_UTCDatetimeFromUnix_is_utc_aware() -> None:
  """Test: result is always timezone-aware and UTC."""
  dt = timer.UTCDatetimeFromUnix(1_000_000.0)
  assert dt.tzinfo is datetime.UTC


def _mock_perf(monkeypatch: pytest.MonkeyPatch, values: list[float]) -> None:
  """Install a perf_counter that yields from `values`."""
  it: abc.Iterator[float] = iter(values)
  monkeypatch.setattr(time, 'perf_counter', lambda: next(it))
