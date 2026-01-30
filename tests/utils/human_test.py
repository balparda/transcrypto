# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/human.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/human_test.py
"""

from __future__ import annotations

import math
from collections import abc

import pytest

from transcrypto.utils import base, human


@pytest.mark.parametrize(
  ('value', 'message'),
  [
    (0, '0 B'),  # bytes < 1024
    (512, '512 B'),
    (51.2, '51.200 B'),
    (1024, '1.000 KiB'),  # exact KiB
    (1536, '1.500 KiB'),  # mid KiB
    (1024**2, '1.000 MiB'),  # exact MiB
    (5 * 1024**2, '5.000 MiB'),
    (1024**3, '1.000 GiB'),  # exact GiB
    (3 * 1024**3, '3.000 GiB'),
    (1024**4, '1.000 TiB'),  # exact TiB
    (7 * 1024**4, '7.000 TiB'),
    (1024**5, '1.000 PiB'),  # exact PiB
    (2 * 1024**5, '2.000 PiB'),
    (1024**6, '1.000 EiB'),  # exact EiB
    (8 * 1024**6, '8.000 EiB'),  # > EiB
  ],
)
def test_HumanizedBytes(value: int, message: str) -> None:
  """Test."""
  assert human.HumanizedBytes(value) == message


@pytest.mark.parametrize(
  ('value', 'message', 'unit', 'unit_message'),
  [
    # <1000 integer, no unit / with unit
    (0, '0', 'Hz', '0 Hz'),
    (999, '999', 'V', '999 V'),
    # <1000 float, 4 decimal places
    (0.5, '500.000 m', 'Hz', '500.000 mHz'),
    (999.999, '999.999', 'Hz', '999.999 Hz'),
    # k range
    (-1000, '-1.000 k', 'Hz', '-1.000 kHz'),
    (1500, '1.500 k', 'Hz', '1.500 kHz'),
    # M range
    (1000**2, '1.000 M', 'Hz', '1.000 MHz'),
    (2500000, '2.500 M', 'Hz', '2.500 MHz'),
    # G range
    (1000**3, '1.000 G', 'Hz', '1.000 GHz'),
    (5 * 1000**3, '5.000 G', 'Hz', '5.000 GHz'),
    # T range
    (-(1000**4), '-1.000 T', 'Hz', '-1.000 THz'),
    (7 * 1000**4, '7.000 T', 'Hz', '7.000 THz'),
    # P range
    (1000**5, '1.000 P', 'Hz', '1.000 PHz'),
    (3 * 1000**5, '3.000 P', 'Hz', '3.000 PHz'),
    # E range and above
    (-(1000**6), '-1.000 E', 'Hz', '-1.000 EHz'),
    (9 * 1000**6, '9.000 E', 'Hz', '9.000 EHz'),
    # small ranges
    (0.05, '50.000 m', 'Hz', '50.000 mHz'),
    (0.00005, '50.000 µ', 'Hz', '50.000 µHz'),  # noqa: RUF001
    (-0.00000005, '-50.000 n', 'Hz', '-50.000 nHz'),
    (0.00000000005, '50.000 p', 'Hz', '50.000 pHz'),
    (-0.00000000000005, '-50.000 f', 'Hz', '-50.000 fHz'),
    (0.00000000000000005, '50.000 a', 'Hz', '50.000 aHz'),
  ],
)
def test_HumanizedDecimal(value: float, message: str, unit: str, unit_message: str) -> None:
  """Test."""
  assert human.HumanizedDecimal(value) == message
  assert human.HumanizedDecimal(value, unit=unit) == unit_message


@pytest.mark.parametrize(
  ('value', 'message'),
  [
    # zero
    (0, '0.000 s'),
    # microseconds
    (0.0000005, '0.500 µs'),  # noqa: RUF001
    (0.0005, '500.000 µs'),  # noqa: RUF001
    (0.000999, '999.000 µs'),  # noqa: RUF001
    # milliseconds
    (0.001, '1.000 ms'),
    (0.5, '500.000 ms'),
    (0.999, '999.000 ms'),
    # seconds
    (1, '1.000 s'),
    (59.99, '59.990 s'),  # edge just under a minute
    (42, '42.000 s'),
    # minutes
    (60, '1.000 min'),
    (3599, '59.983 min'),  # just under an hour
    # hours
    (3600, '1.000 h'),
    (86399, '24.000 h'),  # just under a day
    # days
    (86400, '1.000 d'),
    (172800, '2.000 d'),
  ],
)
def test_HumanizedSeconds(value: float, message: str) -> None:
  """Test."""
  assert human.HumanizedSeconds(value) == message


def test_Humanized_fail() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='input should be >=0'):
    human.HumanizedBytes(-1)
  with pytest.raises(base.InputError, match='input should be >=0'):
    human.HumanizedSeconds(-1)
  # NaN
  with pytest.raises(base.InputError, match='input should finite'):
    human.HumanizedDecimal(math.nan)
  with pytest.raises(base.InputError, match='input should be >=0'):
    human.HumanizedSeconds(math.nan)
  # infinity
  with pytest.raises(base.InputError, match='input should finite'):
    human.HumanizedDecimal(math.inf)
  with pytest.raises(base.InputError, match='input should be >=0'):
    human.HumanizedSeconds(math.inf)


@pytest.mark.parametrize(
  ('value', 'expected'),
  [
    (0, '0'),  # zero returns '0'
    (0.0, '0'),  # zero float also returns '0'
    (math.inf, 'inf'),  # non-finite
    (-math.inf, '-inf'),  # negative inf
    (math.nan, 'nan'),  # NaN
  ],
)
def test_SigFigs_edge_cases(value: float, expected: str) -> None:
  """Test _SigFigs handles edge cases correctly."""
  assert human._SigFigs(value) == expected


@pytest.mark.parametrize(
  ('value', 'expected'),
  [
    # Small integers (magnitude 0-1)
    (1, '1.00000'),
    (5, '5.00000'),
    (42, '42.0000'),
    (999, '999.000'),
    # Larger integers (magnitude 2-8)
    (1234, '1234.00'),
    (12345, '12345.0'),
    (123456, '123456'),
    (1234567, '1234567'),
    (12345678, '12345678'),
    (123456789, '123456789'),  # magnitude 8, still fixed point
    # Very large numbers -> scientific notation (magnitude >= 9)
    (1234567890, '1.23457e+09'),
    (9.87654321e12, '9.87654e+12'),
    # Simple floats
    (1.5, '1.50000'),
    (math.pi, '3.14159'),
    (42.195, '42.1950'),
    (123.456, '123.456'),
    # Small floats (magnitude -1 to -4, still fixed point)
    (0.5, '0.500000'),
    (0.123456, '0.123456'),
    (0.0123456, '0.0123456'),
    (0.00123456, '0.00123456'),
    (0.000123456, '0.000123456'),  # magnitude -4, still fixed point
    # Very small floats -> scientific notation (magnitude < -4)
    (0.0000123456, '1.23456e-05'),
    (1.23456e-10, '1.23456e-10'),
    # Negative numbers (same rules apply)
    (-42, '-42.0000'),
    (-math.pi, '-3.14159'),
    (-0.00123456, '-0.00123456'),
    (-1.23456e-10, '-1.23456e-10'),
    (-9.87654e12, '-9.87654e+12'),
  ],
)
def test_SigFigs_regular_cases(value: float, expected: str) -> None:
  """Test _SigFigs formats regular numbers with 6 significant figures."""
  assert human._SigFigs(value) == expected


def test_HumanizedMeasurements_failures() -> None:
  """Tests."""
  # no data → should bubble up InputError from MeasurementStats
  with pytest.raises(base.InputError):
    human.HumanizedMeasurements([])


@pytest.mark.parametrize(
  ('data', 'kwargs'),
  [
    ([42], {}),  # single value
    ([1, 2, 3], {}),  # defaults
    ([1, 2, 3], {'unit': 'ms'}),  # with unit
    ([1, 2, 3], {'parser': lambda x: f'{x:.1f}'}),  # custom parser  # type:ignore
    ([-1.0, -2.0, -3.0], {'clip_negative': True}),  # negatives clipped
    ([1, 2, 3, 4], {'confidence': 0.99}),  # alternate confidence
  ],
)
def test_HumanizedMeasurements_success(
  data: list[int | float], kwargs: dict[str, str | bool | float]
) -> None:
  """Tests."""
  result: str
  result = human.HumanizedMeasurements(data, **kwargs)  # type:ignore
  # Always contains '@n'
  assert f'@{len(data)}' in result
  # Always contains ±
  assert '±' in result
  # Contains confidence percent for n > 1
  if len(data) > 1:
    conf: int = round(kwargs.get('confidence', 0.95) * 100)  # type:ignore
    assert f'{conf}%CI' in result


@pytest.mark.parametrize(
  ('data', 'unit', 'parser', 'confidence', 'out'),
  [
    ([42], '', None, 0.95, '42.0000 ±? @1'),
    ([0.0000042], 'Hz', None, 0.95, '4.20000e-06Hz ±? @1'),
    ([42000000000000000], 'Hz', human.HumanizedDecimal, 0.95, '42.000 PHz ±? @1'),
    (
      [42000000000000000],
      '',
      lambda x: human.HumanizedDecimal(x, unit='Hz'),  # pyright: ignore
      0.95,
      '42.000 PHz ±? @1',
    ),
    (
      [1.1, 1.2, 1.3, 1.3, 1.2, 1, 0.8, 1.3],
      '',
      None,
      0.95,
      '1.15000 ± 0.148211 [1.00179 … 1.29821]95%CI@8',
    ),
    (
      [0.0000011, 0.0000012, 0.0000013, 0.0000013, 0.0000012, 0.000001, 0.0000008, 0.0000013],
      'Hz',
      None,
      0.95,
      '1.15000e-06Hz ± 1.48211e-07Hz [1.00179e-06Hz … 1.29821e-06Hz]95%CI@8',
    ),
    (
      [0.0000011, 0.0000012, 0.0000013, 0.0000013, 0.0000012, 0.000001, 0.0000008, 0.0000013],
      'WH',
      human.HumanizedDecimal,
      0.95,
      '1.150 µWH ± 148.211 nWH [1.002 µWH … 1.298 µWH]95%CI@8',  # noqa: RUF001
    ),
    (
      [
        12100000,
        12300000,
        12900000,
        12500000,
        12400000,
        12400000,
        13000000,
        11500000,
        12100000,
        12200000,
        12600000,
        12600000,
      ],
      'Hz',
      human.HumanizedDecimal,
      0.95,
      '12.383 MHz ± 252.458 kHz [12.131 MHz … 12.636 MHz]95%CI@12',
    ),
    (
      [
        12100000,
        12300000,
        12900000,
        12500000,
        12400000,
        12400000,
        13000000,
        11500000,
        12100000,
        12200000,
        12600000,
        12600000,
      ],
      '',
      lambda x: human.HumanizedDecimal(x, unit='Hz'),  # pyright: ignore
      0.95,
      '12.383 MHz ± 252.458 kHz [12.131 MHz … 12.636 MHz]95%CI@12',
    ),
    (
      [
        12100000,
        12300000,
        12900000,
        12500000,
        12400000,
        12400000,
        13000000,
        11500000,
        12100000,
        12200000,
        12600000,
        12600000,
      ],
      '',
      lambda x: human.HumanizedDecimal(x, unit='Hz'),  # pyright: ignore
      0.99,
      '12.383 MHz ± 356.242 kHz [12.027 MHz … 12.740 MHz]99%CI@12',
    ),
    (
      [
        12100000,
        12300000,
        12500000,
        12400000,
        12400000,
        13000000,
        11500000,
        12100000,
        12200000,
        12600000,
        12600000,
      ],
      'Hz',
      human.HumanizedDecimal,
      0.98,
      '12.336 MHz ± 316.816 kHz [12.020 MHz … 12.653 MHz]98%CI@11',
    ),
    (
      [
        12100000,
        12300000,
        12400000,
        12400000,
        13000000,
        11500000,
        12100000,
        12200000,
        12600000,
        12600000,
      ],
      'Hz',
      human.HumanizedDecimal,
      0.98,
      '12.320 MHz ± 353.900 kHz [11.966 MHz … 12.674 MHz]98%CI@10',
    ),
    (
      [-12100000, -12300000, -13000000, -11500000, -12100000, -12200000, -12600000, -12600000],
      'Hz',
      human.HumanizedDecimal,
      0.98,
      '-12.300 MHz ± 474.018 kHz [-12.774 MHz … -11.826 MHz]98%CI@8',
    ),
  ],
)
def test_HumanizedMeasurements_validation(
  data: list[int | float],
  unit: str,
  parser: abc.Callable[[float], str] | None,
  confidence: float,
  out: str,
) -> None:
  """Tests."""
  assert (
    human.HumanizedMeasurements(
      data, unit=unit, parser=parser, confidence=confidence, clip_negative=False
    )
    == out
  )
