# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto base library."""

from __future__ import annotations

import abc as abstract
import argparse
import base64
import codecs
import dataclasses
import datetime
import enum
import functools
import hashlib
import json
import logging
import math
import os
import pathlib
import pickle  # noqa: S403
import secrets
import sys
import threading
import time
from collections import abc
from types import TracebackType
from typing import (
  Any,
  Protocol,
  Self,
  TypeVar,
  final,
  runtime_checkable,
)

import numpy as np
import zstandard
from rich import console as rich_console
from rich import logging as rich_logging
from scipy import stats

# Data conversion utils

BytesToHex: abc.Callable[[bytes], str] = lambda b: b.hex()
BytesToInt: abc.Callable[[bytes], int] = lambda b: int.from_bytes(b, 'big', signed=False)
BytesToEncoded: abc.Callable[[bytes], str] = lambda b: base64.urlsafe_b64encode(b).decode('ascii')

HexToBytes: abc.Callable[[str], bytes] = bytes.fromhex
IntToFixedBytes: abc.Callable[[int, int], bytes] = lambda i, n: i.to_bytes(n, 'big', signed=False)
IntToBytes: abc.Callable[[int], bytes] = lambda i: IntToFixedBytes(i, (i.bit_length() + 7) // 8)
IntToEncoded: abc.Callable[[int], str] = lambda i: BytesToEncoded(IntToBytes(i))
EncodedToBytes: abc.Callable[[str], bytes] = lambda e: base64.urlsafe_b64decode(e.encode('ascii'))

PadBytesTo: abc.Callable[[bytes, int], bytes] = lambda b, i: b.rjust((i + 7) // 8, b'\x00')

# Time utils

MIN_TM = int(datetime.datetime(2000, 1, 1, 0, 0, 0, tzinfo=datetime.UTC).timestamp())
TIME_FORMAT = '%Y/%b/%d-%H:%M:%S-UTC'
TimeStr: abc.Callable[[int | float | None], str] = lambda tm: (
  time.strftime(TIME_FORMAT, time.gmtime(tm)) if tm else '-'
)
Now: abc.Callable[[], int] = lambda: int(time.time())
StrNow: abc.Callable[[], str] = lambda: TimeStr(Now())

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

# SI prefix table, powers of 1000
_SI_PREFIXES: dict[int, str] = {
  -6: 'a',  # atto
  -5: 'f',  # femto
  -4: 'p',  # pico
  -3: 'n',  # nano
  -2: 'µ',  # micro (unicode U+00B5)  # noqa: RUF001
  -1: 'm',  # milli
  0: '',  # base
  1: 'k',  # kilo
  2: 'M',  # mega
  3: 'G',  # giga
  4: 'T',  # tera
  5: 'P',  # peta
  6: 'E',  # exa
}

# these control the pickling of data, do NOT ever change, or you will break all databases
# <https://docs.python.org/3/library/pickle.html#pickle.DEFAULT_PROTOCOL>
_PICKLE_PROTOCOL = 4  # protocol 4 available since python v3.8 # do NOT ever change!
PickleGeneric: abc.Callable[[Any], bytes] = lambda o: pickle.dumps(o, protocol=_PICKLE_PROTOCOL)
UnpickleGeneric: abc.Callable[[bytes], Any] = pickle.loads  # noqa: S301
PickleJSON: abc.Callable[[dict[str, Any]], bytes] = lambda d: json.dumps(
  d, separators=(',', ':')
).encode('utf-8')
UnpickleJSON: abc.Callable[[bytes], dict[str, Any]] = lambda b: json.loads(b.decode('utf-8'))
_PICKLE_AAD = b'transcrypto.base.Serialize.1.0'  # do NOT ever change!
# these help find compressed files, do NOT change unless zstandard changes
_ZSTD_MAGIC_FRAME = 0xFD2FB528
_ZSTD_MAGIC_SKIPPABLE_MIN = 0x184D2A50
_ZSTD_MAGIC_SKIPPABLE_MAX = 0x184D2A5F
# JSON
_JSON_DATACLASS_TYPES: set[str] = {
  # native support
  'int',
  'float',
  'str',
  'bool',
  'list[int]',
  'list[float]',
  'list[str]',
  'list[bool]',
  # need conversion/encoding
  'bytes',
}


class Error(Exception):
  """TransCrypto exception."""


class InputError(Error):
  """Input exception (TransCrypto)."""


class CryptoError(Error):
  """Cryptographic exception (TransCrypto)."""


class ImplementationError(Error, NotImplementedError):
  """Feature is not implemented yet (TransCrypto)."""


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
) -> rich_console.Console:
  """Initialize logger (with RichHandler) and get a rich.console.Console singleton.

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
    rich.console.Console: The initialized console instance.

  """
  global __console_singleton  # noqa: PLW0603
  with __console_lock:
    if __console_singleton is not None:
      return __console_singleton
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
    return console


def HumanizedBytes(inp_sz: float, /) -> str:  # noqa: PLR0911
  """Convert a byte count into a human-readable string using binary prefixes (powers of 1024).

  Scales the input size by powers of 1024, returning a value with the
  appropriate IEC binary unit suffix: `B`, `KiB`, `MiB`, `GiB`, `TiB`, `PiB`, `EiB`.

  Args:
    inp_sz (int | float): Size in bytes. Must be non-negative.

  Returns:
    str: Formatted size string with up to two decimal places for units above bytes.

  Raises:
    InputError: If `inp_sz` is negative.

  Notes:
    - Units follow the IEC binary standard where:
        1 KiB = 1024 bytes
        1 MiB = 1024 KiB
        1 GiB = 1024 MiB
        1 TiB = 1024 GiB
        1 PiB = 1024 TiB
        1 EiB = 1024 PiB
    - Values under 1024 bytes are returned as an integer with a space and `B`.

  Examples:
    >>> HumanizedBytes(512)
    '512 B'
    >>> HumanizedBytes(2048)
    '2.00 KiB'
    >>> HumanizedBytes(5 * 1024**3)
    '5.00 GiB'

  """
  if inp_sz < 0:
    raise InputError(f'input should be >=0 and got {inp_sz}')
  if inp_sz < 1024:  # noqa: PLR2004
    return f'{inp_sz} B' if isinstance(inp_sz, int) else f'{inp_sz:0.3f} B'
  if inp_sz < 1024 * 1024:
    return f'{(inp_sz / 1024):0.3f} KiB'
  if inp_sz < 1024 * 1024 * 1024:
    return f'{(inp_sz / (1024 * 1024)):0.3f} MiB'
  if inp_sz < 1024 * 1024 * 1024 * 1024:
    return f'{(inp_sz / (1024 * 1024 * 1024)):0.3f} GiB'
  if inp_sz < 1024 * 1024 * 1024 * 1024 * 1024:
    return f'{(inp_sz / (1024 * 1024 * 1024 * 1024)):0.3f} TiB'
  if inp_sz < 1024 * 1024 * 1024 * 1024 * 1024 * 1024:
    return f'{(inp_sz / (1024 * 1024 * 1024 * 1024 * 1024)):0.3f} PiB'
  return f'{(inp_sz / (1024 * 1024 * 1024 * 1024 * 1024 * 1024)):0.3f} EiB'


def HumanizedDecimal(inp_sz: float, /, *, unit: str = '') -> str:
  """Convert a numeric value into a human-readable string using SI metric prefixes.

  Scales the input value by powers of 1000, returning a value with the
  appropriate SI unit prefix. Supports both large multiples (kilo, mega,
  giga, … exa) and small sub-multiples (milli, micro, nano, pico, femto, atto).

  Notes:
    • Uses decimal multiples: 1 k = 1000 units, 1 m = 1/1000 units.
    • Supported large prefixes: k, M, G, T, P, E.
    • Supported small prefixes: m, µ, n, p, f, a.
    • Unit string is stripped of surrounding whitespace before use.
    • Zero is returned as '0' plus unit (no prefix).

  Examples:
    >>> HumanizedDecimal(950)
    '950'
    >>> HumanizedDecimal(1500)
    '1.50 k'
    >>> HumanizedDecimal(0.123456, unit='V')
    '123.456 mV'
    >>> HumanizedDecimal(3.2e-7, unit='F')
    '320.000 nF'
    >>> HumanizedDecimal(9.14e18, unit='Hz')
    '9.14 EHz'

  Args:
    inp_sz (int | float): Quantity to convert. Must be finite.
    unit (str, optional): Base unit to append to the result (e.g., 'Hz', 'm').
        If given, it will be separated by a space for unscaled values and
        concatenated to the prefix for scaled values.

  Returns:
    str: Formatted string with a few decimal places

  Raises:
    InputError: If `inp_sz` is not finite.

  """  # noqa: RUF002
  if not math.isfinite(inp_sz):
    raise InputError(f'input should finite; got {inp_sz!r}')
  unit = unit.strip()
  pad_unit: str = ' ' + unit if unit else ''
  if inp_sz == 0:
    return '0' + pad_unit
  neg: str = '-' if inp_sz < 0 else ''
  inp_sz = abs(inp_sz)
  # Find exponent of 1000 that keeps value in [1, 1000)
  exp: int = math.floor(math.log10(abs(inp_sz)) / 3)
  exp = max(min(exp, max(_SI_PREFIXES)), min(_SI_PREFIXES))  # clamp to supported range
  if not exp:
    # No scaling: use int or 4-decimal float
    if isinstance(inp_sz, int) or inp_sz.is_integer():
      return f'{neg}{int(inp_sz)}{pad_unit}'
    return f'{neg}{inp_sz:0.3f}{pad_unit}'
  # scaled
  scaled: float = inp_sz / (1000**exp)
  prefix: str = _SI_PREFIXES[exp]
  return f'{neg}{scaled:0.3f} {prefix}{unit}'


def HumanizedSeconds(inp_secs: float, /) -> str:  # noqa: PLR0911
  """Convert a duration in seconds into a human-readable time string.

  Selects the appropriate time unit based on the duration's magnitude:
    - microseconds (`µs`)
    - milliseconds (`ms`)
    - seconds (`s`)
    - minutes (`min`)
    - hours (`h`)
    - days (`d`)

  Args:
    inp_secs (int | float): Time interval in seconds. Must be finite and non-negative.

  Returns:
    str: Human-readable string with the duration and unit

  Raises:
    InputError: If `inp_secs` is negative or not finite.

  Notes:
    - Uses the micro sign (`µ`, U+00B5) for microseconds.
    - Thresholds:
        < 0.001 s → µs
        < 1 s → ms
        < 60 s → seconds
        < 3600 s → minutes
        < 86400 s → hours
        ≥ 86400 s → days

  Examples:
    >>> HumanizedSeconds(0)
    '0.00 s'
    >>> HumanizedSeconds(0.000004)
    '4.000 µs'
    >>> HumanizedSeconds(0.25)
    '250.000 ms'
    >>> HumanizedSeconds(42)
    '42.00 s'
    >>> HumanizedSeconds(3661)
    '1.02 h'

  """  # noqa: RUF002
  if not math.isfinite(inp_secs) or inp_secs < 0:
    raise InputError(f'input should be >=0 and got {inp_secs}')
  if inp_secs == 0:
    return '0.000 s'
  inp_secs = float(inp_secs)
  if inp_secs < 0.001:  # noqa: PLR2004
    return f'{inp_secs * 1000 * 1000:0.3f} µs'  # noqa: RUF001
  if inp_secs < 1:
    return f'{inp_secs * 1000:0.3f} ms'
  if inp_secs < 60:  # noqa: PLR2004
    return f'{inp_secs:0.3f} s'
  if inp_secs < 60 * 60:
    return f'{(inp_secs / 60):0.3f} min'
  if inp_secs < 24 * 60 * 60:
    return f'{(inp_secs / (60 * 60)):0.3f} h'
  return f'{(inp_secs / (24 * 60 * 60)):0.3f} d'


def MeasurementStats(
  data: list[int | float], /, *, confidence: float = 0.95
) -> tuple[int, float, float, float, tuple[float, float], float]:
  """Compute descriptive statistics for repeated measurements.

  Given N ≥ 1 measurements, this function computes the sample mean, the
  standard error of the mean (SEM), and the symmetric error estimate for
  the chosen confidence interval using Student's t distribution.

  Notes:
    • If only one measurement is given, SEM and error are reported as +∞ and
      the confidence interval is (-∞, +∞).
    • This function assumes the underlying distribution is approximately
      normal, or n is large enough for the Central Limit Theorem to apply.

  Args:
    data (list[int | float]): Sequence of numeric measurements.
    confidence (float, optional): Confidence level for the interval, 0.5 <= confidence < 1;
        defaults to 0.95 (95% confidence interval).

  Returns:
    tuple:
      - n (int): number of measurements.
      - mean (float): arithmetic mean of the data
      - sem (float): standard error of the mean, sigma / √n
      - error (float): half-width of the confidence interval (mean ± error)
      - ci (tuple[float, float]): lower and upper confidence interval bounds
      - confidence (float): the confidence level used

  Raises:
    InputError: if the input list is empty.

  """
  # test inputs
  n: int = len(data)
  if not n:
    raise InputError('no data')
  if not 0.5 <= confidence < 1.0:  # noqa: PLR2004
    raise InputError(f'invalid confidence: {confidence=}')
  # solve trivial case
  if n == 1:
    return (n, float(data[0]), math.inf, math.inf, (-math.inf, math.inf), confidence)
  # call scipy for the science data
  np_data = np.array(data)
  mean = np.mean(np_data)
  sem = stats.sem(np_data)
  ci = stats.t.interval(confidence, n - 1, loc=mean, scale=sem)
  t_crit = stats.t.ppf((1.0 + confidence) / 2.0, n - 1)
  error = t_crit * sem  # half-width of the CI
  return (n, float(mean), float(sem), float(error), (float(ci[0]), float(ci[1])), confidence)


def HumanizedMeasurements(
  data: list[int | float],
  /,
  *,
  unit: str = '',
  parser: abc.Callable[[float], str] | None = None,
  clip_negative: bool = True,
  confidence: float = 0.95,
) -> str:
  """Render measurement statistics as a human-readable string.

  Uses `MeasurementStats()` to compute mean and uncertainty, and formats the
  result with units, sample count, and confidence interval. Negative values
  can optionally be clipped to zero and marked with a leading “*”.

  Notes:
    • For a single measurement, error is displayed as “± ?”.
    • The output includes the number of samples (@n) and the confidence
      interval unless a different confidence was requested upstream.

  Args:
    data (list[int | float]): Sequence of numeric measurements.
    unit (str, optional): Unit of measurement to append, e.g. "ms" or "s".
      Defaults to '' (no unit).
    parser (Callable[[float], str] | None, optional): Custom float-to-string
      formatter. If None, values are formatted with 3 decimal places.
    clip_negative (bool, optional): If True (default), negative values are
      clipped to 0.0 and prefixed with '*'.
    confidence (float, optional): Confidence level for the interval, 0.5 <= confidence < 1;
        defaults to 0.95 (95% confidence interval).

  Returns:
    str: A formatted summary string, e.g.: '9.720 ± 1.831 ms [5.253 … 14.187]95%CI@5'

  """
  n: int
  mean: float
  error: float
  ci: tuple[float, float]
  conf: float
  unit = unit.strip()
  n, mean, _, error, ci, conf = MeasurementStats(data, confidence=confidence)
  f: abc.Callable[[float], str] = lambda x: (
    ('*0' if clip_negative and x < 0.0 else str(x))
    if parser is None
    else (f'*{parser(0.0)}' if clip_negative and x < 0.0 else parser(x))
  )
  if n == 1:
    return f'{f(mean)}{unit} ±? @1'
  pct: int = round(conf * 100)
  return f'{f(mean)}{unit} ± {f(error)}{unit} [{f(ci[0])}{unit} … {f(ci[1])}{unit}]{pct}%CI@{n}'


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
    self, label: str = '', /, *, emit_log: bool = True, emit_print: bool = False
  ) -> None:
    """Initialize the Timer.

    Args:
      label (str, optional): A description or name for the timed block or function
      emit_log (bool, optional): Emit a log message when finished; default is True
      emit_print (bool, optional): Emit a print() message when finished; default is False

    """
    self.emit_log: bool = emit_log
    self.emit_print: bool = emit_print
    self.label: str = label.strip()
    self.start: float | None = None
    self.end: float | None = None

  @property
  def elapsed(self) -> float:
    """Elapsed time. Will be zero until a measurement is available with start/end.

    Raises:
        Error: negative elapsed time

    Returns:
        float: elapsed time, in seconds

    """
    if self.start is None or self.end is None:
      return 0.0
    delta: float = self.end - self.start
    if delta <= 0.0:
      raise Error(f'negative/zero delta: {delta}')
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
      ) + f'<PARTIAL> {HumanizedSeconds(time.perf_counter() - self.start)}'
    return (f'{self.label}: ' if self.label else '') + f'{HumanizedSeconds(self.elapsed)}'

  def Start(self) -> None:
    """Start the timer.

    Raises:
        Error: if you try to re-start the timer

    """
    if self.start is not None:
      raise Error('Re-starting timer is forbidden')
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
        Error: trying to re-start timer or stop unstarted timer

    """
    if self.start is None:
      raise Error('Stopping an unstarted timer')
    if self.end is not None:
      raise Error('Re-stopping timer is forbidden')
    self.end = time.perf_counter()
    message: str = str(self)
    if self.emit_log:
      logging.info(message)
    if self.emit_print:
      Console().print(message)

  def __exit__(
    self,
    unused_exc_type: type[BaseException] | None,
    unused_exc_val: BaseException | None,
    exc_tb: TracebackType | None,
  ) -> None:
    """Stop the timer when exiting the context."""
    self.Stop()

  _F = TypeVar('_F', bound=abc.Callable[..., Any])

  def __call__(self, func: Timer._F) -> Timer._F:
    """Allow the Timer to be used as a decorator.

    Args:
      func: The function to time.

    Returns:
      The wrapped function with timing behavior.

    """

    @functools.wraps(func)
    def _Wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
      with self.__class__(self.label, emit_log=self.emit_log, emit_print=self.emit_print):
        return func(*args, **kwargs)

    return _Wrapper  # type:ignore


def RandBits(n_bits: int, /) -> int:
  """Crypto-random integer with guaranteed `n_bits` size (i.e., first bit == 1).

  The fact that the first bit will be 1 means the entropy is ~ (n_bits-1) and
  because of this we only allow for a byte or more bits generated. This drawback
  is negligible for the large integers a crypto library will work with, in practice.

  Args:
    n_bits (int): number of bits to produce, ≥ 8

  Returns:
    int with n_bits size

  Raises:
    InputError: invalid n_bits

  """
  # test inputs
  if n_bits < 8:  # noqa: PLR2004
    raise InputError(f'n_bits must be ≥ 8: {n_bits}')
  # call underlying method
  n: int = 0
  while n.bit_length() != n_bits:
    n = secrets.randbits(n_bits)  # we could just set the bit, but IMO it is better to get another
  return n


def RandInt(min_int: int, max_int: int, /) -> int:
  """Crypto-random integer uniform over [min_int, max_int].

  Args:
    min_int (int): minimum integer, inclusive, ≥ 0
    max_int (int): maximum integer, inclusive, > min_int

  Returns:
    int between [min_int, max_int] inclusive

  Raises:
    InputError: invalid min/max

  """
  # test inputs
  if min_int < 0 or min_int >= max_int:
    raise InputError(f'min_int must be ≥ 0, and < max_int: {min_int} / {max_int}')
  # uniform over [min_int, max_int]
  span: int = max_int - min_int + 1
  n: int = min_int + secrets.randbelow(span)
  assert min_int <= n <= max_int, 'should never happen: generated number out of range'  # noqa: S101
  return n


def RandShuffle[T: Any](seq: abc.MutableSequence[T], /) -> None:
  """In-place Crypto-random shuffle order for `seq` mutable sequence.

  Args:
    seq (MutableSequence[T]): any mutable sequence with 2 or more elements

  Raises:
    InputError: not enough elements

  """
  # test inputs
  if (n_seq := len(seq)) < 2:  # noqa: PLR2004
    raise InputError(f'seq must have 2 or more elements: {n_seq}')
  # cryptographically sound Fisher-Yates using secrets.randbelow
  for i in range(n_seq - 1, 0, -1):
    j: int = secrets.randbelow(i + 1)
    seq[i], seq[j] = seq[j], seq[i]


def RandBytes(n_bytes: int, /) -> bytes:
  """Crypto-random `n_bytes` bytes. Just plain good quality random bytes.

  Args:
    n_bytes (int): number of bits to produce, > 0

  Returns:
    bytes: random with len()==n_bytes

  Raises:
    InputError: invalid n_bytes

  """
  # test inputs
  if n_bytes < 1:
    raise InputError(f'n_bytes must be ≥ 1: {n_bytes}')
  # return from system call
  b: bytes = secrets.token_bytes(n_bytes)
  assert len(b) == n_bytes, 'should never happen: generated bytes incorrect size'  # noqa: S101
  return b


def GCD(a: int, b: int, /) -> int:
  """Greatest Common Divisor for `a` and `b`, integers ≥0. Uses the Euclid method.

  O(log(min(a, b)))

  Args:
    a (int): integer a ≥ 0
    b (int): integer b ≥ 0 (can't be both zero)

  Returns:
    gcd(a, b)

  Raises:
    InputError: invalid inputs

  """
  # test inputs
  if a < 0 or b < 0 or (not a and not b):
    raise InputError(f'negative input or undefined gcd(0, 0): {a=} , {b=}')
  # algo needs to start with a >= b
  if a < b:
    a, b = b, a
  # euclid
  while b:
    r: int = a % b
    a, b = b, r
  return a


def ExtendedGCD(a: int, b: int, /) -> tuple[int, int, int]:
  """Greatest Common Divisor Extended for `a` and `b`, integers ≥0. Uses the Euclid method.

  O(log(min(a, b)))

  Args:
    a (int): integer a ≥ 0
    b (int): integer b ≥ 0 (can't be both zero)

  Returns:
    (gcd, x, y) so that a * x + b * y = gcd
    x and y may be negative integers or zero but won't be both zero.

  Raises:
    InputError: invalid inputs

  """
  # test inputs
  if a < 0 or b < 0 or (not a and not b):
    raise InputError(f'negative input or undefined gcd(0, 0): {a=} , {b=}')
  # algo needs to start with a >= b (but we remember if we did swap)
  swapped = False
  if a < b:
    a, b = b, a
    swapped = True
  # trivial case
  if not b:
    return (a, 0 if swapped else 1, 1 if swapped else 0)
  # euclid
  x1, x2, y1, y2 = 0, 1, 1, 0
  while b:
    q, r = divmod(a, b)
    x, y = x2 - q * x1, y2 - q * y1
    a, b, x1, x2, y1, y2 = b, r, x, x1, y, y1
  return (a, y2 if swapped else x2, x2 if swapped else y2)


def Hash256(data: bytes, /) -> bytes:
  """SHA-256 hash of bytes data. Always a length of 32 bytes.

  Args:
    data (bytes): Data to compute hash for

  Returns:
    32 bytes (256 bits) of SHA-256 hash;
    if converted to hexadecimal (with BytesToHex() or hex()) will be 64 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**256

  """
  return hashlib.sha256(data).digest()


def Hash512(data: bytes, /) -> bytes:
  """SHA-512 hash of bytes data. Always a length of 64 bytes.

  Args:
    data (bytes): Data to compute hash for

  Returns:
    64 bytes (512 bits) of SHA-512 hash;
    if converted to hexadecimal (with BytesToHex() or hex()) will be 128 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**512

  """
  return hashlib.sha512(data).digest()


def FileHash(full_path: str, /, *, digest: str = 'sha256') -> bytes:
  """SHA-256 hex hash of file on disk. Always a length of 32 bytes (if default digest=='sha256').

  Args:
    full_path (str): Path to existing file on disk
    digest (str, optional): Hash method to use, accepts 'sha256' (default) or 'sha512'

  Returns:
    32 bytes (256 bits) of SHA-256 hash (if default digest=='sha256');
    if converted to hexadecimal (with BytesToHex() or hex()) will be 64 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**256

  Raises:
    InputError: file could not be found

  """
  # test inputs
  digest = digest.lower().strip().replace('-', '')  # normalize so we can accept e.g. "SHA-256"
  if digest not in {'sha256', 'sha512'}:
    raise InputError(f'unrecognized digest: {digest!r}')
  full_path = full_path.strip()
  if not full_path or not pathlib.Path(full_path).exists():
    raise InputError(f'file {full_path!r} not found for hashing')
  # compute hash
  logging.info(f'Hashing file {full_path!r}')
  with pathlib.Path(full_path).open('rb') as file_obj:
    return hashlib.file_digest(file_obj, digest).digest()


def ObfuscateSecret(data: str | bytes | int, /) -> str:
  """Obfuscate a secret string/key/bytes/int by hashing SHA-512 and only showing the first 4 bytes.

  Always a length of 9 chars, e.g. "aabbccdd…" (always adds '…' at the end).
  Known vulnerability: If the secret is small, can be brute-forced!
  Use only on large (~>64bits) secrets.

  Args:
    data (str | bytes | int): Data to obfuscate

  Raises:
      InputError: _description_

  Returns:
      str: obfuscated string, e.g. "aabbccdd…"

  """
  if isinstance(data, str):
    data = data.encode('utf-8')
  elif isinstance(data, int):
    data = IntToBytes(data)
  if not isinstance(data, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
    raise InputError(f'invalid type for data: {type(data)}')
  return BytesToHex(Hash512(data))[:8] + '…'


class CryptoInputType(enum.StrEnum):
  """Types of inputs that can represent arbitrary bytes."""

  # prefixes; format prefixes are all 4 bytes
  PATH = '@'  # @path on disk → read bytes from a file
  STDIN = '@-'  # stdin
  HEX = 'hex:'  # hex:deadbeef → decode hex
  BASE64 = 'b64:'  # b64:... → decode base64
  STR = 'str:'  # str:hello → UTF-8 encode the literal
  RAW = 'raw:'  # raw:... → byte literals via \\xNN escapes (rare but handy)


def BytesToRaw(b: bytes, /) -> str:
  r"""Convert bytes to double-quoted string with \\xNN escapes where needed.

  1. map bytes 0..255 to same code points (latin1)
  2. escape non-printables/backslash/quotes via unicode_escape

  Args:
    b (bytes): input

  Returns:
    str: double-quoted string with \\xNN escapes where needed

  """
  inner: str = b.decode('latin1').encode('unicode_escape').decode('ascii')
  return f'"{inner.replace('"', r"\"")}"'


def RawToBytes(s: str, /) -> bytes:
  r"""Convert double-quoted string with \\xNN escapes where needed to bytes.

  Args:
    s (str): input (expects a double-quoted string; parses \\xNN, \n, \\ etc)

  Returns:
    bytes: data

  """
  if len(s) >= 2 and s[0] == s[-1] == '"':  # noqa: PLR2004
    s = s[1:-1]
  # decode backslash escapes to code points, then map 0..255 -> bytes
  return codecs.decode(s, 'unicode_escape').encode('latin1')


def DetectInputType(data_str: str, /) -> CryptoInputType | None:
  """Auto-detect `data_str` type, if possible.

  Args:
    data_str (str): data to process, putatively a bytes blob

  Returns:
    CryptoInputType | None: type if has a known prefix, None otherwise

  """
  data_str = data_str.strip()
  if data_str == CryptoInputType.STDIN:
    return CryptoInputType.STDIN
  for t in (
    CryptoInputType.PATH,
    CryptoInputType.STR,
    CryptoInputType.HEX,
    CryptoInputType.BASE64,
    CryptoInputType.RAW,
  ):
    if data_str.startswith(t):
      return t
  return None


def BytesFromInput(data_str: str, /, *, expect: CryptoInputType | None = None) -> bytes:  # noqa: C901, PLR0911, PLR0912
  """Parse input `data_str` into `bytes`. May auto-detect or enforce a type of input.

  Can load from disk ('@'). Can load from stdin ('@-').

  Args:
    data_str (str): data to process, putatively a bytes blob
    expect (CryptoInputType | None, optional): If not given (None) will try to auto-detect the
        input type by looking at the prefix on `data_str` and if none is found will suppose
        a 'str:' was given; if one of the supported CryptoInputType is given then will enforce
        that specific type prefix or no prefix

  Returns:
    bytes: data

  Raises:
    InputError: unexpected type or conversion error

  """
  data_str = data_str.strip()
  # auto-detect
  detected_type: CryptoInputType | None = DetectInputType(data_str)
  expect = CryptoInputType.STR if expect is None and detected_type is None else expect
  if detected_type is not None and expect is not None and detected_type != expect:
    raise InputError(f'Expected type {expect=} is different from detected type {detected_type=}')
  # now we know they don't conflict, so unify them; remove prefix if we have it
  expect = detected_type if expect is None else expect
  assert expect is not None, 'should never happen: type should be known here'  # noqa: S101
  data_str = data_str.removeprefix(expect)
  # for every type something different will happen now
  try:
    match expect:
      case CryptoInputType.STDIN:
        # read raw bytes from stdin: prefer the binary buffer; if unavailable,
        # fall back to text stream encoded as UTF-8 (consistent with str: policy).
        stream = getattr(sys.stdin, 'buffer', None)
        if stream is None:
          text: str = sys.stdin.read()
          if not isinstance(text, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise InputError('sys.stdin.read() produced non-text data')  # noqa: TRY301
          return text.encode('utf-8')
        data: bytes = stream.read()
        if not isinstance(data, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
          raise InputError('sys.stdin.buffer.read() produced non-binary data')  # noqa: TRY301
        return data
      case CryptoInputType.PATH:
        if not pathlib.Path(data_str).exists():
          raise InputError(f'cannot find file {data_str!r}')  # noqa: TRY301
        return pathlib.Path(data_str).read_bytes()
      case CryptoInputType.STR:
        return data_str.encode('utf-8')
      case CryptoInputType.HEX:
        return HexToBytes(data_str)
      case CryptoInputType.BASE64:
        return EncodedToBytes(data_str)
      case CryptoInputType.RAW:
        return RawToBytes(data_str)
      case _:
        raise InputError(f'invalid type {expect!r}')  # noqa: TRY301
  except Exception as err:
    raise InputError(f'invalid input: {err}') from err


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class CryptoKey(abstract.ABC):
  """A cryptographic key."""

  @abstract.abstractmethod
  def __post_init__(self) -> None:
    """Check data."""
    # every sub-class of CryptoKey has to implement its own version of __post_init__()

  @abstract.abstractmethod
  def __str__(self) -> str:
    """Safe (no secrets) string representation of the key.

    Returns:
      string representation of the key without leaking secrets

    """
    # every sub-class of CryptoKey has to implement its own version of __str__()

  @final
  def __repr__(self) -> str:
    """Safe (no secrets) string representation of the key. Same as __str__().

    Returns:
      string representation of the key without leaking secrets

    """
    # concrete __repr__() delegates to the (abstract) __str__():
    # this avoids marking __repr__() abstract while still unifying behavior
    return self.__str__()

  @final
  def _DebugDump(self) -> str:
    """Debug dump of the key object. NOT for logging, NOT for regular use, EXPOSES secrets.

    We disable default __repr__() for the CryptoKey classes for security reasons, so we won't
    leak private key values into logs, but this method allows for explicit access to the
    class fields for debugging purposes by mimicking the usual dataclass __repr__().

    Returns:
      string with all the object's fields explicit values

    """
    cls: str = type(self).__name__
    parts: list[str] = []
    for field in dataclasses.fields(self):
      val: Any = getattr(self, field.name)  # getattr is fine with frozen/slots
      parts.append(f'{field.name}={val!r}')
    return f'{cls}({", ".join(parts)})'

  @final
  @property
  def _json_dict(self) -> dict[str, Any]:
    """Dictionary representation of the object suitable for JSON conversion.

    Returns:
      dict[str, Any]: representation of the object suitable for JSON conversion

    Raises:
      ImplementationError: object has types that are not supported in JSON

    """
    self_dict: dict[str, Any] = dataclasses.asdict(self)
    for field in dataclasses.fields(self):
      # check the type is OK
      if field.type not in _JSON_DATACLASS_TYPES:
        raise ImplementationError(
          f'Unsupported JSON field {field.name!r}/{field.type} not in {_JSON_DATACLASS_TYPES}'
        )
      # convert types that we accept but JSON does not
      if field.type == 'bytes':
        self_dict[field.name] = BytesToEncoded(self_dict[field.name])
    return self_dict

  @final
  @property
  def json(self) -> str:
    """JSON representation of the object, tightly packed, not for humans.

    Returns:
      str: JSON representation of the object, tightly packed

    """
    return json.dumps(self._json_dict, separators=(',', ':'))

  @final
  @property
  def formatted_json(self) -> str:
    """JSON representation of the object formatted for humans.

    Returns:
      str: JSON representation of the object formatted for humans

    """
    return json.dumps(self._json_dict, indent=4, sort_keys=True)

  @final
  @classmethod
  def _FromJSONDict(cls, json_dict: dict[str, Any], /) -> Self:
    """Create object from JSON representation.

    Args:
      json_dict (dict[str, Any]): JSON dict

    Returns:
      a CryptoKey object ready for use

    Raises:
      InputError: unexpected type/fields
      ImplementationError: unsupported JSON field

    """
    # check we got exactly the fields we needed
    cls_fields: set[str] = {f.name for f in dataclasses.fields(cls)}
    json_fields: set[str] = set(json_dict)
    if cls_fields != json_fields:
      raise InputError(f'JSON data decoded to unexpected fields: {cls_fields=} / {json_fields=}')
    # reconstruct the types we meddled with inside self._json_dict
    for field in dataclasses.fields(cls):
      if field.type not in _JSON_DATACLASS_TYPES:
        raise ImplementationError(
          f'Unsupported JSON field {field.name!r}/{field.type} not in {_JSON_DATACLASS_TYPES}'
        )
      if field.type == 'bytes':
        json_dict[field.name] = EncodedToBytes(json_dict[field.name])
    # build the object
    return cls(**json_dict)

  @final
  @classmethod
  def FromJSON(cls, json_data: str, /) -> Self:
    """Create object from JSON representation.

    Args:
      json_data (str): JSON string

    Returns:
      a CryptoKey object ready for use

    Raises:
      InputError: unexpected type/fields

    """
    # get the dict back
    json_dict: dict[str, Any] = json.loads(json_data)
    if not isinstance(json_dict, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
      raise InputError(f'JSON data decoded to unexpected type: {type(json_dict)}')
    return cls._FromJSONDict(json_dict)

  @final
  @property
  def blob(self) -> bytes:
    """Serial (bytes) representation of the object.

    Returns:
      bytes, pickled, representation of the object

    """
    return self.Blob()

  @final
  def Blob(self, /, *, key: Encryptor | None = None, silent: bool = True) -> bytes:
    """Get serial (bytes) representation of the object with more options, including encryption.

    Args:
      key (Encryptor, optional): if given will key.Encrypt() data before saving
      silent (bool, optional): if True (default) will not log

    Returns:
      bytes, pickled, representation of the object

    """
    return Serialize(self._json_dict, compress=-2, key=key, silent=silent, pickler=PickleJSON)

  @final
  @property
  def encoded(self) -> str:
    """Base-64 representation of the object.

    Returns:
      str, pickled, base64, representation of the object

    """
    return self.Encoded()

  @final
  def Encoded(self, /, *, key: Encryptor | None = None, silent: bool = True) -> str:
    """Base-64 representation of the object with more options, including encryption.

    Args:
      key (Encryptor, optional): if given will key.Encrypt() data before saving
      silent (bool, optional): if True (default) will not log

    Returns:
      str, pickled, base64, representation of the object

    """
    return CryptoInputType.BASE64 + BytesToEncoded(self.Blob(key=key, silent=silent))

  @final
  @property
  def hex(self) -> str:
    """Hexadecimal representation of the object.

    Returns:
      str, pickled, hexadecimal, representation of the object

    """
    return self.Hex()

  @final
  def Hex(self, /, *, key: Encryptor | None = None, silent: bool = True) -> str:
    """Hexadecimal representation of the object with more options, including encryption.

    Args:
      key (Encryptor, optional): if given will key.Encrypt() data before saving
      silent (bool, optional): if True (default) will not log

    Returns:
      str, pickled, hexadecimal, representation of the object

    """
    return CryptoInputType.HEX + BytesToHex(self.Blob(key=key, silent=silent))

  @final
  @property
  def raw(self) -> str:
    """Raw escaped binary representation of the object.

    Returns:
      str, pickled, raw escaped binary, representation of the object

    """
    return self.Raw()

  @final
  def Raw(self, /, *, key: Encryptor | None = None, silent: bool = True) -> str:
    """Raw escaped binary representation of the object with more options, including encryption.

    Args:
      key (Encryptor, optional): if given will key.Encrypt() data before saving
      silent (bool, optional): if True (default) will not log

    Returns:
      str, pickled, raw escaped binary, representation of the object

    """
    return CryptoInputType.RAW + BytesToRaw(self.Blob(key=key, silent=silent))

  @final
  @classmethod
  def Load(cls, data: str | bytes, /, *, key: Decryptor | None = None, silent: bool = True) -> Self:
    """Load (create) object from serialized bytes or string.

    Args:
      data (str | bytes): if bytes is assumed from CryptoKey.blob/Blob(), and
          if string is assumed from CryptoKey.encoded/Encoded()
      key (Decryptor, optional): if given will key.Encrypt() data before saving
      silent (bool, optional): if True (default) will not log

    Returns:
      a CryptoKey object ready for use

    Raises:
      InputError: decode error

    """
    # if this is a string, then we suppose it is base64
    if isinstance(data, str):
      data = BytesFromInput(data)
    # we now have bytes and we suppose it came from CryptoKey.blob()/CryptoKey.CryptoBlob()
    try:
      json_dict: dict[str, Any] = DeSerialize(
        data=data, key=key, silent=silent, unpickler=UnpickleJSON
      )
      return cls._FromJSONDict(json_dict)
    except Exception as err:
      raise InputError(f'input decode error: {err}') from err


@runtime_checkable
class Encryptor(Protocol):
  """Abstract interface for a class that has encryption.

  Contract:
    - If algorithm accepts a `nonce` or `tag` these have to be handled internally by the
      implementation and appended to the `ciphertext`/`signature`.
    - If AEAD is supported, `associated_data` (AAD) must be authenticated. If not supported
      then `associated_data` different from None must raise InputError.

  Notes:
    The interface is deliberately minimal: byte-in / byte-out.
    Metadata like nonce/tag may be:
      - returned alongside `ciphertext`/`signature`, or
      - bundled/serialized into `ciphertext`/`signature` by the implementation.

  """

  @abstract.abstractmethod
  def Encrypt(self, plaintext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Encrypt `plaintext` and return `ciphertext`.

    Args:
      plaintext (bytes): Data to encrypt.
      associated_data (bytes, optional): Optional AAD for AEAD modes; must be
          provided again on decrypt

    Returns:
      bytes: Ciphertext; if a nonce/tag is needed for decryption, the implementation
      must encode it within the returned bytes (or document how to retrieve it)

    Raises:
      InputError: invalid inputs
      CryptoError: internal crypto failures

    """


@runtime_checkable
class Decryptor(Protocol):
  """Abstract interface for a class that has decryption (see contract/notes in Encryptor)."""

  @abstract.abstractmethod
  def Decrypt(self, ciphertext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Decrypt `ciphertext` and return the original `plaintext`.

    Args:
      ciphertext (bytes): Data to decrypt (including any embedded nonce/tag if applicable)
      associated_data (bytes, optional): Optional AAD (must match what was used during encrypt)

    Returns:
      bytes: Decrypted plaintext bytes

    Raises:
      InputError: invalid inputs
      CryptoError: internal crypto failures, authentication failure, key mismatch, etc

    """


@runtime_checkable
class Verifier(Protocol):
  """Abstract interface for asymmetric signature verify. (see contract/notes in Encryptor)."""

  @abstract.abstractmethod
  def Verify(
    self, message: bytes, signature: bytes, /, *, associated_data: bytes | None = None
  ) -> bool:
    """Verify a `signature` for `message`. True if OK; False if failed verification.

    Args:
      message (bytes): Data that was signed (including any embedded nonce/tag if applicable)
      signature (bytes): Signature data to verify (including any embedded nonce/tag if applicable)
      associated_data (bytes, optional): Optional AAD (must match what was used during signing)

    Returns:
      True if signature is valid, False otherwise

    Raises:
      InputError: invalid inputs
      CryptoError: internal crypto failures, authentication failure, key mismatch, etc

    """


@runtime_checkable
class Signer(Protocol):
  """Abstract interface for asymmetric signing. (see contract/notes in Encryptor)."""

  @abstract.abstractmethod
  def Sign(self, message: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Sign `message` and return the `signature`.

    Args:
      message (bytes): Data to sign.
      associated_data (bytes, optional): Optional AAD for AEAD modes; must be
          provided again on decrypt

    Returns:
      bytes: Signature; if a nonce/tag is needed for decryption, the implementation
      must encode it within the returned bytes (or document how to retrieve it)

    Raises:
      InputError: invalid inputs
      CryptoError: internal crypto failures

    """


def Serialize(
  python_obj: Any,  # noqa: ANN401
  /,
  *,
  file_path: str | None = None,
  compress: int | None = 3,
  key: Encryptor | None = None,
  silent: bool = False,
  pickler: abc.Callable[[Any], bytes] = PickleGeneric,
) -> bytes:
  """Serialize a Python object into a BLOB, optionally compress / encrypt / save to disk.

  Data path is:

    `obj` => [pickler] => (compress) => (encrypt) => (save to `file_path`) => return

  At every step of the data path the data will be measured, in bytes.
  Every data conversion will be timed. The measurements/times will be logged (once).

  Compression levels / speed can be controlled by `compress`. Use this as reference:

  | Level    | Speed       | Compression ratio       | Typical use case                        |
  | -------- | ------------| ------------------------| --------------------------------------- |
  | -5 to -1 | Fastest     | Poor (better than none) | Real-time / very latency-sensitive      |
  | 0…3      | Very fast   | Good ratio              | Default CLI choice, safe baseline       |
  | 4…6      | Moderate    | Better ratio            | Good compromise for general persistence |
  | 7…10     | Slower      | Marginally better ratio | Only if storage space is precious       |
  | 11…15    | Much slower | Slight gains            | Large archives, not for runtime use     |
  | 16…22    | Very slow   | Tiny gains              | Archival-only, multi-GB datasets        |

  Args:
    python_obj (Any): serializable Python object
    file_path (str, optional): full path to optionally save the data to
    compress (int | None, optional): Compress level before encrypting/saving; -22 ≤ compress ≤ 22;
        None is no compression; default is 3, which is fast, see table above for other values
    key (Encryptor, optional): if given will key.Encrypt() data before saving
    silent (bool, optional): if True will not log; default is False (will log)
    pickler (Callable[[Any], bytes], optional): if not given, will just be the `pickle` module;
        if given will be a method to convert any Python object to its `bytes` representation;
        PickleGeneric is the default, but another useful value is PickleJSON

  Returns:
    bytes: serialized binary data corresponding to obj + (compression) + (encryption)

  """
  messages: list[str] = []
  with Timer('Serialization complete', emit_log=False) as tm_all:
    # pickle
    with Timer('PICKLE', emit_log=False) as tm_pickle:
      obj: bytes = pickler(python_obj)
    if not silent:
      messages.append(f'    {tm_pickle}, {HumanizedBytes(len(obj))}')
    # compress, if needed
    if compress is not None:
      compress = max(compress, -22)
      compress = min(compress, 22)
      with Timer(f'COMPRESS@{compress}', emit_log=False) as tm_compress:
        obj = zstandard.ZstdCompressor(level=compress).compress(obj)
      if not silent:
        messages.append(f'    {tm_compress}, {HumanizedBytes(len(obj))}')
    # encrypt, if needed
    if key is not None:
      with Timer('ENCRYPT', emit_log=False) as tm_crypto:
        obj = key.Encrypt(obj, associated_data=_PICKLE_AAD)
      if not silent:
        messages.append(f'    {tm_crypto}, {HumanizedBytes(len(obj))}')
    # optionally save to disk
    if file_path is not None:
      with Timer('SAVE', emit_log=False) as tm_save:
        pathlib.Path(file_path).write_bytes(obj)
      if not silent:
        messages.append(f'    {tm_save}, to {file_path!r}')
  # log and return
  if not silent:
    logging.info(f'{tm_all}; parts:\n{"\n".join(messages)}')
  return obj


def DeSerialize(  # noqa: C901
  *,
  data: bytes | None = None,
  file_path: str | None = None,
  key: Decryptor | None = None,
  silent: bool = False,
  unpickler: abc.Callable[[bytes], Any] = UnpickleGeneric,
) -> Any:  # noqa: ANN401
  """Load (de-serializes) a BLOB back to a Python object, optionally decrypting / decompressing.

  Data path is:

    `data` or `file_path` => (decrypt) => (decompress) => [unpickler] => return object

  At every step of the data path the data will be measured, in bytes.
  Every data conversion will be timed. The measurements/times will be logged (once).
  Compression versus no compression will be automatically detected.

  Args:
    data (bytes | None, optional): if given, use this as binary data string (input);
        if you use this option, `file_path` will be ignored
    file_path (str | None, optional): if given, use this as file path to load binary data
        string (input); if you use this option, `data` will be ignored. Defaults to None.
    key (Decryptor | None, optional): if given will key.Decrypt() data before decompressing/loading.
        Defaults to None.
    silent (bool, optional): if True will not log; default is False (will log). Defaults to False.
    unpickler (Callable[[bytes], Any], optional): if not given, will just be the `pickle` module;
        if given will be a method to convert a `bytes` representation back to a Python object;
        UnpickleGeneric is the default, but another useful value is UnpickleJSON.
        Defaults to UnpickleGeneric.

  Returns:
    De-Serialized Python object corresponding to data

  Raises:
    InputError: invalid inputs
    CryptoError: internal crypto failures, authentication failure, key mismatch, etc

  """  # noqa: DOC502
  # test inputs
  if (data is None and file_path is None) or (data is not None and file_path is not None):
    raise InputError('you must provide only one of either `data` or `file_path`')
  if file_path and not pathlib.Path(file_path).exists():
    raise InputError(f'invalid file_path: {file_path!r}')
  if data and len(data) < 4:  # noqa: PLR2004
    raise InputError('invalid data: too small')
  # start the pipeline
  obj: bytes = data or b''
  messages: list[str] = [f'DATA: {HumanizedBytes(len(obj))}'] if data and not silent else []
  with Timer('De-Serialization complete', emit_log=False) as tm_all:
    # optionally load from disk
    if file_path:
      assert not obj, 'should never happen: if we have a file obj should be empty'  # noqa: S101
      with Timer('LOAD', emit_log=False) as tm_load:
        obj = pathlib.Path(file_path).read_bytes()
      if not silent:
        messages.append(f'    {tm_load}, {HumanizedBytes(len(obj))}, from {file_path!r}')
    # decrypt, if needed
    if key is not None:
      with Timer('DECRYPT', emit_log=False) as tm_crypto:
        obj = key.Decrypt(obj, associated_data=_PICKLE_AAD)
      if not silent:
        messages.append(f'    {tm_crypto}, {HumanizedBytes(len(obj))}')
    # decompress: we try to detect compression to determine if we must call zstandard
    if (
      len(obj) >= 4  # noqa: PLR2004
      and (
        ((magic := int.from_bytes(obj[:4], 'little')) == _ZSTD_MAGIC_FRAME)
        or (_ZSTD_MAGIC_SKIPPABLE_MIN <= magic <= _ZSTD_MAGIC_SKIPPABLE_MAX)
      )
    ):
      with Timer('DECOMPRESS', emit_log=False) as tm_decompress:
        obj = zstandard.ZstdDecompressor().decompress(obj)
      if not silent:
        messages.append(f'    {tm_decompress}, {HumanizedBytes(len(obj))}')
    elif not silent:
      messages.append('    (no compression detected)')
    # create the actual object = unpickle
    with Timer('UNPICKLE', emit_log=False) as tm_unpickle:
      python_obj: Any = unpickler(obj)
    if not silent:
      messages.append(f'    {tm_unpickle}')
  # log and return
  if not silent:
    logging.info(f'{tm_all}; parts:\n{"\n".join(messages)}')
  return python_obj


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class PublicBid512(CryptoKey):
  """Public commitment to a (cryptographically secure) bid that can be revealed/validated later.

  Bid is computed as: public_hash = Hash512(public_key || private_key || secret_bid)

  Everything is bytes. The public part is (public_key, public_hash) and the private
  part is (private_key, secret_bid). The whole computation can be checked later.

  No measures are taken here to prevent timing attacks (probably not a concern).

  Attributes:
    public_key (bytes): 512-bits random value
    public_hash (bytes): SHA-512 hash of (public_key || private_key || secret_bid)

  """

  public_key: bytes
  public_hash: bytes

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs

    """
    if len(self.public_key) != 64 or len(self.public_hash) != 64:  # noqa: PLR2004
      raise InputError(f'invalid public_key or public_hash: {self}')

  def __str__(self) -> str:
    """Safe string representation of the PublicBid.

    Returns:
      string representation of PublicBid

    """
    return (
      'PublicBid512('
      f'public_key={BytesToEncoded(self.public_key)}, '
      f'public_hash={BytesToHex(self.public_hash)})'
    )

  def VerifyBid(self, private_key: bytes, secret: bytes, /) -> bool:
    """Verify a bid. True if OK; False if failed verification.

    Args:
      private_key (bytes): 512-bits private key
      secret (bytes): Any number of bytes (≥1) to bid on (e.g., UTF-8 encoded string)

    Returns:
      True if bid is valid, False otherwise

    """
    try:
      # creating the PrivateBid object will validate everything; InputError we allow to propagate
      PrivateBid512(
        public_key=self.public_key,
        public_hash=self.public_hash,
        private_key=private_key,
        secret_bid=secret,
      )
      return True  # if we got here, all is good  # noqa: TRY300
    except CryptoError:
      return False  # bid does not match the public commitment

  @classmethod
  def Copy(cls, other: PublicBid512, /) -> Self:
    """Initialize a public bid by taking the public parts of a public/private bid.

    Args:
        other (PublicBid512): the bid to copy from

    Returns:
        Self: an initialized PublicBid512

    """
    return cls(public_key=other.public_key, public_hash=other.public_hash)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class PrivateBid512(PublicBid512):
  """Private bid that can be revealed and validated against a public commitment (see PublicBid).

  Attributes:
    private_key (bytes): 512-bits random value
    secret_bid (bytes): Any number of bytes (≥1) to bid on (e.g., UTF-8 encoded string)

  """

  private_key: bytes
  secret_bid: bytes

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
      CryptoError: bid does not match the public commitment

    """
    super(PrivateBid512, self).__post_init__()
    if len(self.private_key) != 64 or len(self.secret_bid) < 1:  # noqa: PLR2004
      raise InputError(f'invalid private_key or secret_bid: {self}')
    if self.public_hash != Hash512(self.public_key + self.private_key + self.secret_bid):
      raise CryptoError(f'inconsistent bid: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the PrivateBid.

    Returns:
      string representation of PrivateBid without leaking secrets

    """
    return (
      'PrivateBid512('
      f'{super(PrivateBid512, self).__str__()}, '
      f'private_key={ObfuscateSecret(self.private_key)}, '
      f'secret_bid={ObfuscateSecret(self.secret_bid)})'
    )

  @classmethod
  def New(cls, secret: bytes, /) -> Self:
    """Make the `secret` into a new bid.

    Args:
      secret (bytes): Any number of bytes (≥1) to bid on (e.g., UTF-8 encoded string)

    Returns:
      PrivateBid object ready for use (use PublicBid.Copy() to get the public part)

    Raises:
      InputError: invalid inputs

    """
    # test inputs
    if len(secret) < 1:
      raise InputError(f'invalid secret length: {len(secret)}')
    # generate random values
    public_key: bytes = RandBytes(64)  # 512 bits
    private_key: bytes = RandBytes(64)  # 512 bits
    # build object
    return cls(
      public_key=public_key,
      public_hash=Hash512(public_key + private_key + secret),
      private_key=private_key,
      secret_bid=secret,
    )


def _FlagNames(a: argparse.Action, /) -> list[str]:
  # Positional args have empty 'option_strings'; otherwise use them (e.g., ['-v','--verbose'])
  if a.option_strings:
    return list(a.option_strings)
  if a.nargs:
    if isinstance(a.metavar, str) and a.metavar:
      # e.g., nargs=2, metavar='FILE'
      return [a.metavar]
    if isinstance(a.metavar, tuple):
      # e.g., nargs=2, metavar=('FILE1', 'FILE2')
      return list(a.metavar)
  # Otherwise, it's a positional arg with no flags, so return the destination name
  return [a.dest]


def _ActionIsSubparser(a: argparse.Action, /) -> bool:
  return isinstance(a, argparse._SubParsersAction)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def _FormatDefault(a: argparse.Action, /) -> str:
  if a.default is argparse.SUPPRESS:
    return ''
  if isinstance(a.default, bool):
    return ' (default: on)' if a.default else ''
  if a.default in {None, '', 0, False}:  # noqa: B033
    return ''
  return f' (default: {a.default})'


def _FormatChoices(a: argparse.Action, /) -> str:
  return f' choices: {list(a.choices)}' if getattr(a, 'choices', None) else ''  # type:ignore


def _FormatType(a: argparse.Action, /) -> str:
  t: Any | None = getattr(a, 'type', None)
  if t is None:
    return ''
  # Show clean type names (int, str, float); for callables, just say 'custom'
  return f' type: {t.__name__ if hasattr(t, "__name__") else "custom"}'


def _FormatNArgs(a: argparse.Action, /) -> str:
  return f' nargs: {a.nargs}' if getattr(a, 'nargs', None) not in {None, 0} else ''


def _RowsForActions(actions: abc.Sequence[argparse.Action], /) -> list[tuple[str, str]]:
  rows: list[tuple[str, str]] = []
  for a in actions:
    if _ActionIsSubparser(a):
      continue
    # skip the built-in help action; it's implied
    if getattr(a, 'help', '') == argparse.SUPPRESS or isinstance(a, argparse._HelpAction):  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
      continue
    flags: str = ', '.join(_FlagNames(a))
    meta: str = ''.join(
      (_FormatType(a), _FormatNArgs(a), _FormatChoices(a), _FormatDefault(a))
    ).strip()
    desc: str = (a.help or '').strip()
    if meta:
      desc = f'{desc} [{meta}]' if desc else f'[{meta}]'
    rows.append((flags, desc))
  return rows


def _MarkdownTable(
  rows: abc.Sequence[tuple[str, str]], headers: tuple[str, str] = ('Option/Arg', 'Description'), /
) -> str:
  if not rows:
    return ''
  out: list[str] = ['| ' + headers[0] + ' | ' + headers[1] + ' |', '|---|---|']
  for left, right in rows:
    out.append(f'| `{left}` | {right} |')
  return '\n'.join(out)


def _WalkSubcommands(
  parser: argparse.ArgumentParser, path: list[str] | None = None, /
) -> list[tuple[list[str], argparse.ArgumentParser, Any]]:
  path = path or []
  items: list[tuple[list[str], argparse.ArgumentParser, Any]] = []
  name: str
  sp: argparse.ArgumentParser
  for action in parser._actions:  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    if _ActionIsSubparser(action):
      for name, sp in action.choices.items():  # type:ignore
        items.append(([*path, name], sp, action))  # pyright: ignore[reportUnknownArgumentType]
        items.extend(_WalkSubcommands(sp, [*path, name]))  # pyright: ignore[reportUnknownArgumentType]
  return items


def _HelpText(sub_parser: argparse.ArgumentParser, parent_sub_action: Any, /) -> str:  # noqa: ANN401
  if parent_sub_action is not None:
    for choice_action in parent_sub_action._choices_actions:  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
      if choice_action.dest == sub_parser.prog.split()[-1]:
        return choice_action.help or ''
  return ''


def GenerateCLIMarkdown(  # noqa: C901
  prog: str, parser: argparse.ArgumentParser, /, *, description: str = ''
) -> str:
  """Return a Markdown doc section that reflects the current _BuildParser() tree.

  Will treat epilog strings as examples, splitting on '$$' to get multiple examples.

  Args:
    prog (str): name of app, eg. 'transcrypto' or 'transcrypto.py'
    parser (argparse.ArgumentParser): parser to use for data
    description (str, optional): app description to use as intro

  Returns:
    str: markdown

  Raises:
    InputError: invalid app name

  """
  prog, description = prog.strip(), description.strip()
  if not prog or prog not in parser.prog:
    raise InputError(f'invalid prog/parser.prog: {prog=}, {parser.prog=}')
  lines: list[str] = ['']
  # Header + global flags
  lines.extend(
    (
      '<!-- cspell:disable -->',
      '<!-- auto-generated; do not edit -->\n',
      f'# `{prog}` Command-Line Interface\n',
      description + '\n',
      'Invoke with:\n',
      '```bash',
      f'{parser.prog} <command> [sub-command] [options...]',
      '```\n',
    )
  )
  # Global options table
  global_rows: list[tuple[str, str]] = _RowsForActions(parser._actions)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
  if global_rows:
    lines.extend(('## Global Options\n', _MarkdownTable(global_rows), ''))
  # Top-level commands summary
  lines.append('## Top-Level Commands\n')
  # Find top-level subparsers to list available commands
  top_subs: list[argparse.Action] = [a for a in parser._actions if _ActionIsSubparser(a)]  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
  for action in top_subs:
    for name, sp in action.choices.items():  # type: ignore[union-attr]
      description = str(sp.description)  # pyright: ignore[reportUnknownArgumentType, reportUnknownMemberType]
      format_usage = str(sp.format_usage())  # pyright: ignore[reportUnknownArgumentType, reportUnknownMemberType]
      help_text: str = (
        description or ' '.join(i.strip() for i in format_usage.splitlines())
      ).strip()
      short: str = (sp.help if hasattr(sp, 'help') else '') or ''  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType, reportUnknownMemberType]
      help_text = short or help_text  # pyright: ignore[reportUnknownVariableType]
      help_text = help_text.replace('usage: ', '').strip()  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType]
      lines.append(f'- **`{name}`** — `{help_text}`')
  lines.append('')
  if parser.epilog:
    lines.extend(('```bash', parser.epilog, '```\n'))
  # Detailed sections per (sub)command
  for path, sub_parser, parent_sub_action in _WalkSubcommands(parser):
    if len(path) == 1:
      lines.append('---\n')  # horizontal rule between top-level commands
    header: str = ' '.join(path)
    lines.append(f'##{"" if len(path) == 1 else "#"} `{header}`')  # (header level 3 or 4)
    # Usage block
    help_text = _HelpText(sub_parser, parent_sub_action)
    if help_text:
      lines.append(f'\n{help_text}')
    usage: str = sub_parser.format_usage().replace('usage: ', '').strip()
    lines.extend(('\n```bash', str(usage), '```\n'))
    # Options/args table
    rows: list[tuple[str, str]] = _RowsForActions(sub_parser._actions)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    if rows:
      lines.extend((_MarkdownTable(rows), ''))
    # Examples (if any) - stored in epilog argument
    epilog: str = sub_parser.epilog.strip() if sub_parser.epilog else ''
    if epilog:
      lines.extend(('**Example:**\n', '```bash'))
      lines.extend(f'$ {parser.prog} {epilog_line.strip()}' for epilog_line in epilog.split('$$'))
      lines.append('```\n')
  # join all lines as the markdown string
  return ('\n'.join(lines)).strip()
