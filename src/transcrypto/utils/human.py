# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto human-readable formatting library."""

from __future__ import annotations

import math
from collections import abc

from transcrypto.utils import base, stats

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


def HumanizedBytes(inp_sz: float, /) -> str:  # noqa: PLR0911
  """Convert a byte count into a human-readable string using binary prefixes (powers of 1024).

  Scales the input size by powers of 1024, returning a value with the
  appropriate IEC binary unit suffix: `B`, `KiB`, `MiB`, `GiB`, `TiB`, `PiB`, `EiB`.

  Args:
    inp_sz (int | float): Size in bytes. Must be non-negative.

  Returns:
    str: Formatted size string with up to two decimal places for units above bytes.

  Raises:
    base.InputError: If `inp_sz` is negative.

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
    raise base.InputError(f'input should be >=0 and got {inp_sz}')
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
    base.InputError: If `inp_sz` is not finite.

  """  # noqa: RUF002
  if not math.isfinite(inp_sz):
    raise base.InputError(f'input should finite; got {inp_sz!r}')
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
    base.InputError: If `inp_secs` is negative or not finite.

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
    raise base.InputError(f'input should be >=0 and got {inp_secs}')
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


def _SigFigs(x: float, /, *, n: int = 6) -> str:
  """Format a float to n significant figures.

  Args:
    x (float): The number to format.
    n (int, optional): Number of significant figures. Defaults to 6.

  Returns:
    str: Formatted number string.

  """
  if x == 0:
    return '0'
  if not math.isfinite(x):
    return str(x)
  # Calculate the magnitude to determine formatting
  magnitude: int = math.floor(math.log10(abs(x)))
  # Use scientific notation for very small or very large numbers
  if magnitude < -4 or magnitude >= 9:  # noqa: PLR2004
    return f'{x:.{n - 1}e}'
  # For numbers close to 1, use fixed point
  decimal_places: int = max(0, n - 1 - magnitude)
  return f'{x:.{decimal_places}f}'


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
  n, mean, _, error, ci, conf = stats.MeasurementStats(data, confidence=confidence)
  f: abc.Callable[[float], str] = lambda x: (
    ('*0' if clip_negative and x < 0.0 else _SigFigs(x))
    if parser is None
    else (f'*{parser(0.0)}' if clip_negative and x < 0.0 else parser(x))
  )
  if n == 1:
    return f'{f(mean)}{unit} ±? @1'
  pct: int = round(conf * 100)
  return f'{f(mean)}{unit} ± {f(error)}{unit} [{f(ci[0])}{unit} … {f(ci[1])}{unit}]{pct}%CI@{n}'
