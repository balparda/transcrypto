# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto timer library."""

from __future__ import annotations

import datetime
import functools
import logging
import time
from collections import abc
from types import TracebackType
from typing import Self

from transcrypto.utils import base, human

# Time utils

MIN_TM = int(datetime.datetime(2000, 1, 1, 0, 0, 0, tzinfo=datetime.UTC).timestamp())
TIME_FORMAT = '%Y/%b/%d-%H:%M:%S-UTC'
TimeStr: abc.Callable[[float | None], str] = lambda tm: (
  time.strftime(TIME_FORMAT, time.gmtime(tm)) if tm else '-'
)
Now: abc.Callable[[], int] = lambda: int(time.time())
StrNow: abc.Callable[[], str] = lambda: TimeStr(Now())


def DatetimeFromISO(s: str) -> datetime.datetime:
  """Parse ISO datetime and ensure it is timezone-aware (default UTC).

  Args:
    s (str): ISO 8601 datetime string.

  Returns:
    Timezone-aware datetime (UTC if input was naive).

  """
  dt: datetime.datetime = datetime.datetime.fromisoformat(s)
  return dt if dt.tzinfo is not None else dt.replace(tzinfo=datetime.UTC)


def ISOFromDatetime(dt: datetime.datetime) -> str:
  """Convert a datetime to an ISO 8601 string.

  Args:
    dt (datetime.datetime): The datetime to convert.

  Returns:
    str: The ISO 8601 string representation of the datetime.

  """
  return dt.isoformat()


def UTCDatetimeFromUnix(tm: float) -> datetime.datetime:
  """Convert a Unix timestamp to a timezone-aware datetime (UTC).

  Args:
    tm (float): Unix timestamp (seconds since epoch).

  Returns:
    Timezone-aware datetime in UTC.

  """
  return datetime.datetime.fromtimestamp(tm, tz=datetime.UTC)


class Timer:
  """An execution timing class that can be used as both a context manager and a decorator.

  The timer is intentionally permissive:

  - ``Start()`` may only be called once; calling it again raises ``base.Error``.
  - ``Stop()`` may be called multiple times; re-stopping records the new end time and
    logs a diagnostic message instead of raising an error.
  - ``elapsed`` is always safe to read: it returns ``0.0`` before the timer is started,
    the live running time while the timer is running, and the final frozen duration once
    stopped.

  Examples:
    # As a context manager
    with Timer('Block timing') as tmr:
      time.sleep(1.2)
    # → logs: "Block timing: 1.200 s"

    # As a decorator
    @Timer('Function timing')
    def any_function():
      time.sleep(0.8)

    any_function()
    # → logs: "Function timing: 0.800 s"  (each call gets its own Timer instance)

    # As a regular object
    tm = Timer('Inline timing', emit_print=print)
    time.sleep(0.1)  # time not measured
    tm.Start()
    time.sleep(0.1)  # time measured
    tm.Stop()        # prints: "Inline timing: 0.100 s"

  Attributes:
    label (str): Timer label used in log/print output but *NOT* in ``Timer.__str__()``.
    emit_log (bool): If ``True`` (default) emits ``logging.info()`` when the timer stops.
    emit_print (Callable[[str], None] | None): Optional callable invoked with the
        formatted message when the timer stops; ``None`` means no print output (default).

  """

  def __init__(
    self,
    label: str = '',
    *,
    emit_log: bool = True,
    emit_print: abc.Callable[[str], None] | None = None,
  ) -> None:
    """Initialize the Timer.

    Args:
      label (str, optional): A description or name for the timed block or function;
          printed in logs but *NOT* used for Timer.__str__()
      emit_log (bool, optional): Emit a log message when finished; default is True
      emit_print (Callable[[str], None] | None, optional): Emit a print() message when
          finished using the provided callable; default is None

    """
    self.emit_log: bool = emit_log
    self.emit_print: abc.Callable[[str], None] | None = emit_print
    self.label: str = label.strip()
    self.start: float | None = None
    self.end: float | None = None

  @property
  def elapsed(self) -> float:
    """Elapsed time. Will be zero until a measurement is available with start/end.

    Returns:
        float: elapsed time, in seconds, >=0.0

    Raises:
        base.Error: negative elapsed time

    """
    if self.start is None:
      return 0.0
    delta: float = self.end - self.start if self.end else time.perf_counter() - self.start
    if delta < 0.0:
      raise base.Error(f'negative delta: {delta}')
    return delta

  def __str__(self) -> str:
    """Get current timer value.

    Returns:
        str: human-readable representation of current time value

    """
    return human.HumanizedSeconds(self.elapsed)

  def Start(self) -> None:
    """Start the timer (no label).

    Raises:
        base.Error: if you try to re-start the timer

    """
    if self.start is not None:
      raise base.Error('Re-starting timer is forbidden')
    self.start = time.perf_counter()

  def Stop(self) -> None:
    """Stop the timer and emit the timing message.

    Re-stopping is allowed: if ``Stop()`` is called a second time the new end
    timestamp is recorded and a diagnostic ``logging.info`` message is emitted,
    but no exception is raised.

    Raises:
      base.Error: if the timer was never started.

    """
    if self.start is None:
      raise base.Error('Stopping an unstarted timer')
    if self.end is not None:
      logging.info(f'Re-stopping previous timer @{self}')
    self.end = time.perf_counter()
    message: str = f'{self.label}: {self}'
    if self.emit_log:
      logging.info(message)
    if self.emit_print is not None:
      self.emit_print(message)

  def __enter__(self) -> Self:
    """Start the timer when entering the context.

    Returns:
        Timer: context object (self)

    """
    self.Start()
    return self

  def __exit__(
    self,
    unused_exc_type: type[BaseException] | None,
    unused_exc_val: BaseException | None,
    exc_tb: TracebackType | None,
  ) -> None:
    """Stop the timer when exiting the context."""
    self.Stop()

  def __call__[**F, R](self, func: abc.Callable[F, R]) -> abc.Callable[F, R]:
    """Allow the Timer to be used as a decorator.

    Args:
      func: The function to time.

    Returns:
      The wrapped function with timing behavior.

    """

    @functools.wraps(func)
    def _Wrapper(*args: F.args, **kwargs: F.kwargs) -> R:
      with self.__class__(self.label, emit_log=self.emit_log, emit_print=self.emit_print):
        return func(*args, **kwargs)

    return _Wrapper
