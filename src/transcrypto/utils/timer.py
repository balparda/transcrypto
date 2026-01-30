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
TimeStr: abc.Callable[[int | float | None], str] = lambda tm: (
  time.strftime(TIME_FORMAT, time.gmtime(tm)) if tm else '-'
)
Now: abc.Callable[[], int] = lambda: int(time.time())
StrNow: abc.Callable[[], str] = lambda: TimeStr(Now())


class Timer:
  """An execution timing class that can be used as both a context manager and a decorator.

  Examples:
    # As a context manager
    with Timer('Block timing'):
      time.sleep(1.2)

    # As a decorator
    @Timer('Function timing')
    def slow_function():
      time.sleep(0.8)

    # As a regular object
    tm = Timer('Inline timing')
    tm.Start()
    time.sleep(0.1)
    tm.Stop()
    print(tm)

  Attributes:
    label (str, optional): Timer label
    emit_log (bool, optional): If True (default) will logging.info() the timer, else will not
    emit_print (bool, optional): If True will print() the timer, else (default) will not

  """

  def __init__(
    self,
    label: str = '',
    /,
    *,
    emit_log: bool = True,
    emit_print: abc.Callable[[str], None] | None = None,
  ) -> None:
    """Initialize the Timer.

    Args:
      label (str, optional): A description or name for the timed block or function
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

    Raises:
        base.Error: negative elapsed time

    Returns:
        float: elapsed time, in seconds

    """
    if self.start is None or self.end is None:
      return 0.0
    delta: float = self.end - self.start
    if delta <= 0.0:
      raise base.Error(f'negative/zero delta: {delta}')
    return delta

  def __str__(self) -> str:
    """Get current timer value.

    Returns:
        str: human-readable representation of current time value

    """
    if self.start is None:
      return f'{self.label}: <UNSTARTED>' if self.label else '<UNSTARTED>'
    if self.end is None:
      return (
        f'{self.label}: ' if self.label else ''
      ) + f'<PARTIAL> {human.HumanizedSeconds(time.perf_counter() - self.start)}'
    return (f'{self.label}: ' if self.label else '') + f'{human.HumanizedSeconds(self.elapsed)}'

  def Start(self) -> None:
    """Start the timer.

    Raises:
        base.Error: if you try to re-start the timer

    """
    if self.start is not None:
      raise base.Error('Re-starting timer is forbidden')
    self.start = time.perf_counter()

  def __enter__(self) -> Self:
    """Start the timer when entering the context.

    Returns:
        Timer: context object (self)

    """
    self.Start()
    return self

  def Stop(self) -> None:
    """Stop the timer and emit logging.info with timer message.

    Raises:
        base.Error: trying to re-start timer or stop unstarted timer

    """
    if self.start is None:
      raise base.Error('Stopping an unstarted timer')
    if self.end is not None:
      raise base.Error('Re-stopping timer is forbidden')
    self.end = time.perf_counter()
    message: str = str(self)
    if self.emit_log:
      logging.info(message)
    if self.emit_print is not None:
      self.emit_print(message)

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
