#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""base.py unittest."""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import dataclasses
import itertools
import logging
import math
# import pdb
import pathlib
import sys
import tempfile
from typing import Any, Callable
from unittest import mock

import pytest
import typeguard

from src.transcrypto import base, aes

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = base.__version__  # tests inherit version from module


def test_bytes_conversions() -> None:
  """Test."""
  bb: bytes = 'xyz'.encode('utf-8')
  assert base.BytesToHex(bb) == '78797a'
  assert base.BytesToInt(bb) == 7895418
  assert base.BytesToEncoded(bb) == 'eHl6'
  assert base.HexToBytes('78797a') == bb
  assert base.IntToBytes(7895418) == bb
  assert base.IntToEncoded(7895418) == 'eHl6'
  assert base.EncodedToBytes('eHl6') == bb
  assert base.PadBytesTo(bb, 8) == bb
  assert base.PadBytesTo(bb, 16) == bb
  assert base.PadBytesTo(bb, 24) == bb
  assert base.PadBytesTo(bb, 32) == b'\x00xyz'
  assert base.PadBytesTo(bb, 40) == b'\x00\x00xyz'
  assert base.PadBytesTo(b'\x01\x00', 40) == b'\x00\x00\x00\x01\x00'
  padded: bytes = base.PadBytesTo(bb, 64)
  assert padded == b'\x00\x00\x00\x00\x00xyz'
  assert base.BytesToHex(padded) == '000000000078797a'
  assert base.BytesToInt(padded) == 7895418
  assert base.BytesToEncoded(padded) == 'AAAAAAB4eXo='  # cspell:disable-line
  assert base.HexToBytes('000000000078797a') == padded
  assert base.EncodedToBytes('AAAAAAB4eXo=') == padded  # cspell:disable-line


@pytest.mark.parametrize('value, message', [
    (0, '0 B'),                    # bytes < 1024
    (512, '512 B'),
    (51.2, '51.200 B'),
    (1024, '1.000 KiB'),           # exact KiB
    (1536, '1.500 KiB'),           # mid KiB
    (1024 ** 2, '1.000 MiB'),      # exact MiB
    (5 * 1024 ** 2, '5.000 MiB'),
    (1024 ** 3, '1.000 GiB'),      # exact GiB
    (3 * 1024 ** 3, '3.000 GiB'),
    (1024 ** 4, '1.000 TiB'),      # exact TiB
    (7 * 1024 ** 4, '7.000 TiB'),
    (1024 ** 5, '1.000 PiB'),      # exact PiB
    (2 * 1024 ** 5, '2.000 PiB'),
    (1024 ** 6, '1.000 EiB'),      # exact EiB
    (8 * 1024 ** 6, '8.000 EiB'),  # > EiB
])
def test_HumanizedBytes(value: int, message: str) -> None:
  """Test."""
  assert base.HumanizedBytes(value) == message


@pytest.mark.parametrize('value, message, unit, unit_message', [
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
    (1000 ** 2, '1.000 M', 'Hz', '1.000 MHz'),
    (2500000, '2.500 M', 'Hz', '2.500 MHz'),
    # G range
    (1000 ** 3, '1.000 G', 'Hz', '1.000 GHz'),
    (5 * 1000 ** 3, '5.000 G', 'Hz', '5.000 GHz'),
    # T range
    (-1000 ** 4, '-1.000 T', 'Hz', '-1.000 THz'),
    (7 * 1000 ** 4, '7.000 T', 'Hz', '7.000 THz'),
    # P range
    (1000**5, '1.000 P', 'Hz', '1.000 PHz'),
    (3 * 1000 ** 5, '3.000 P', 'Hz', '3.000 PHz'),
    # E range and above
    (-1000**6, '-1.000 E', 'Hz', '-1.000 EHz'),
    (9 * 1000 ** 6, '9.000 E', 'Hz', '9.000 EHz'),
    # small ranges
    (0.05, '50.000 m', 'Hz', '50.000 mHz'),
    (0.00005, '50.000 µ', 'Hz', '50.000 µHz'),
    (-0.00000005, '-50.000 n', 'Hz', '-50.000 nHz'),
    (0.00000000005, '50.000 p', 'Hz', '50.000 pHz'),
    (-0.00000000000005, '-50.000 f', 'Hz', '-50.000 fHz'),
    (0.00000000000000005, '50.000 a', 'Hz', '50.000 aHz'),
])
def test_HumanizedDecimal(value: int | float, message: str, unit: str, unit_message: str) -> None:
  """Test."""
  assert base.HumanizedDecimal(value) == message
  assert base.HumanizedDecimal(value, unit=unit) == unit_message


@pytest.mark.parametrize('value, message', [
    # zero
    (0, '0.000 s'),
    # microseconds
    (0.0000005, '0.500 µs'),
    (0.0005, '500.000 µs'),
    (0.000999, '999.000 µs'),
    # milliseconds
    (0.001, '1.000 ms'),
    (0.5, '500.000 ms'),
    (0.999, '999.000 ms'),
    # seconds
    (1, '1.000 s'),
    (59.99, '59.990 s'),   # edge just under a minute
    (42, '42.000 s'),
    # minutes
    (60, '1.000 min'),
    (3599, '59.983 min'),  # just under an hour
    # hours
    (3600, '1.000 h'),
    (86399, '24.000 h'),   # just under a day
    # days
    (86400, '1.000 d'),
    (172800, '2.000 d'),
])
def test_HumanizedSeconds(value: int | float, message: str) -> None:
  """Test."""
  assert base.HumanizedSeconds(value) == message


def test_Humanized_fail() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedBytes(-1)
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedSeconds(-1)
  # NaN
  with pytest.raises(base.InputError, match='input should finite'):
    base.HumanizedDecimal(math.nan)
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedSeconds(math.nan)
  # infinity
  with pytest.raises(base.InputError, match='input should finite'):
    base.HumanizedDecimal(math.inf)
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedSeconds(math.inf)


def test_measurement_stats_failures() -> None:
  """Tests."""
  # no data
  with pytest.raises(base.InputError, match='no data'):
    base.MeasurementStats([])
  # invalid confidence
  with pytest.raises(base.InputError, match='invalid confidence'):
    base.MeasurementStats([1, 2, 3], confidence=0.0)
  with pytest.raises(base.InputError, match='invalid confidence'):
    base.MeasurementStats([1, 2, 3], confidence=1.1)


@pytest.mark.parametrize(
    'data, confidence',
    [
        ([42], 0.95),                  # trivial one-sample case
        ([1, 2, 3], 0.95),             # small sample
        ([1.0, 1.5, 2.0, 2.5], 0.99),  # floats + higher confidence
    ]
)
def test_measurement_stats_success(
    data: list[int | float], confidence: float) -> None:
  """Tests."""
  n: int
  mean: float
  sem: float
  error: float
  ci: tuple[float, float]
  conf: float
  n, mean, sem, error, ci, conf = base.MeasurementStats(data, confidence=confidence)
  assert math.isclose(conf, confidence, rel_tol=1e-12)
  assert n == len(data)
  if n == 1:
    # For single sample, SEM/error = inf, CI = (-inf, inf)
    assert sem == math.inf
    assert error == math.inf
    assert ci[0] == -math.inf and ci[1] == math.inf
  else:
    # For multi-sample, finite numbers
    assert math.isfinite(mean)
    assert math.isfinite(sem)
    assert math.isfinite(error)
    assert ci[0] <= mean <= ci[1]


def test_HumanizedMeasurements_failures() -> None:
  """Tests."""
  # no data → should bubble up InputError from MeasurementStats
  with pytest.raises(base.InputError):
    base.HumanizedMeasurements([])


@pytest.mark.parametrize(
    'data, kwargs',
    [  # type:ignore
        ([42], {}),                                     # single value
        ([1, 2, 3], {}),                                # defaults
        ([1, 2, 3], {'unit': 'ms'}),                    # with unit
        ([1, 2, 3], {'parser': lambda x: f'{x:.1f}'}),  # custom parser  # type:ignore
        ([-1.0, -2.0, -3.0], {'clip_negative': True}),  # negatives clipped
        ([1, 2, 3, 4], {'confidence': 0.99}),           # alternate confidence
    ]
)
def test_HumanizedMeasurements_success(
    data: list[int | float], kwargs: dict[str, str | bool | float]) -> None:
  """Tests."""
  result: str
  result = base.HumanizedMeasurements(data, **kwargs)  # type:ignore
  # Always contains '@n'
  assert f'@{len(data)}' in result
  # Always contains ±
  assert '±' in result
  # Contains confidence percent for n > 1
  if len(data) > 1:
    conf = int(round(kwargs.get('confidence', 0.95) * 100))  # type:ignore
    assert f'{conf}%CI' in result


@pytest.mark.parametrize(
    'data, unit, parser, confidence, out',
    [  # type:ignore
        ([42], '', None, 0.95, '42.0 ±? @1'),
        ([0.0000042], 'Hz', None, 0.95, '4.2e-06Hz ±? @1'),
        ([42000000000000000], 'Hz', base.HumanizedDecimal, 0.95, '42.000 PHz ±? @1'),
        ([42000000000000000], '', lambda x: base.HumanizedDecimal(x, unit='Hz'), 0.95,  # type:ignore
         '42.000 PHz ±? @1'),
        ([1.1, 1.2, 1.3, 1.3, 1.2, 1, 0.8, 1.3], '', None, 0.95,
         '1.1500000000000001 ± 0.14821066855207451 [1.0017893314479256 … 1.2982106685520747]95%CI@8'),
        ([0.0000011, 0.0000012, 0.0000013, 0.0000013, 0.0000012, 0.000001, 0.0000008, 0.0000013],
         'Hz', None, 0.95,
         '1.15e-06Hz ± 1.4821066855207454e-07Hz [1.0017893314479255e-06Hz … '
         '1.2982106685520745e-06Hz]95%CI@8'),
        ([0.0000011, 0.0000012, 0.0000013, 0.0000013, 0.0000012, 0.000001, 0.0000008, 0.0000013],
         'WH', base.HumanizedDecimal, 0.95,
         '1.150 µWH ± 148.211 nWH [1.002 µWH … 1.298 µWH]95%CI@8'),
        ([12100000, 12300000, 12900000, 12500000, 12400000, 12400000, 13000000, 11500000, 12100000,
          12200000, 12600000, 12600000], 'Hz', base.HumanizedDecimal, 0.95,
         '12.383 MHz ± 252.458 kHz [12.131 MHz … 12.636 MHz]95%CI@12'),
        ([12100000, 12300000, 12900000, 12500000, 12400000, 12400000, 13000000, 11500000, 12100000,
          12200000, 12600000, 12600000], '', lambda x: base.HumanizedDecimal(x, unit='Hz'), 0.95,  # type:ignore
         '12.383 MHz ± 252.458 kHz [12.131 MHz … 12.636 MHz]95%CI@12'),
        ([12100000, 12300000, 12900000, 12500000, 12400000, 12400000, 13000000, 11500000, 12100000,
          12200000, 12600000, 12600000], '', lambda x: base.HumanizedDecimal(x, unit='Hz'), 0.99,  # type:ignore
         '12.383 MHz ± 356.242 kHz [12.027 MHz … 12.740 MHz]99%CI@12'),
        ([12100000, 12300000, 12500000, 12400000, 12400000, 13000000, 11500000, 12100000, 12200000,
          12600000, 12600000], 'Hz', base.HumanizedDecimal, 0.98,
         '12.336 MHz ± 316.816 kHz [12.020 MHz … 12.653 MHz]98%CI@11'),
        ([12100000, 12300000, 12400000, 12400000, 13000000, 11500000, 12100000, 12200000, 12600000,
          12600000], 'Hz', base.HumanizedDecimal, 0.98,
         '12.320 MHz ± 353.900 kHz [11.966 MHz … 12.674 MHz]98%CI@10'),
        ([-12100000, -12300000, -13000000, -11500000, -12100000, -12200000, -12600000, -12600000],
         'Hz', base.HumanizedDecimal, 0.98,
         '-12.300 MHz ± 474.018 kHz [-12.774 MHz … -11.826 MHz]98%CI@8'),
    ]
)
def test_HumanizedMeasurements_validation(
    data: list[int | float], unit: str, parser: Callable[[float], str] | None,
    confidence: float, out: str) -> None:
  """Tests."""
  assert base.HumanizedMeasurements(
      data, unit=unit, parser=parser, confidence=confidence, clip_negative=False) == out


def _mock_perf(monkeypatch: pytest.MonkeyPatch, values: list[float]) -> None:
  """Install a perf_counter that yields from `values`."""
  it = iter(values)
  monkeypatch.setattr(base.time, 'perf_counter', lambda: next(it))


def test_Timer_str_unstarted() -> None:
  """Test."""
  t = base.Timer('T')
  assert str(t) == 'T: <UNSTARTED>'


def test_Timer_str_partial(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test."""
  # Start at 100.00; __str__ calls perf_counter again (100.12) → delta 0.12 s
  _mock_perf(monkeypatch, [100.00, 100.12])
  t = base.Timer('P')
  t.Start()
  assert str(t) == 'P: <PARTIAL> 120.000 ms'


def test_Timer_start_twice_forbidden(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test."""
  _mock_perf(monkeypatch, [1.0])
  t = base.Timer('X')
  t.Start()
  with pytest.raises(base.Error, match='Re-starting timer is forbidden'):
    t.Start()


def test_Timer_stop_unstarted_forbidden() -> None:
  """Test."""
  t = base.Timer('X')
  with pytest.raises(base.Error, match='Stopping an unstarted timer'):
    t.Stop()


def test_Timer_negative_elapsed(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test."""
  _mock_perf(monkeypatch, [1.0, 0.5])
  t = base.Timer('X')
  t.Start()
  with pytest.raises(base.Error, match='negative/zero delta'):
    t.Stop()


def test_Timer_stop_twice_forbidden(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
  """Test."""
  # Start=1.0, Stop=2.5  → elapsed=1.5
  _mock_perf(monkeypatch, [1.0, 2.5])
  caplog.set_level(logging.INFO)
  t = base.Timer('X')
  t.Start()
  t.Stop()
  # A second Stop should error
  with pytest.raises(base.Error, match='Re-stopping timer is forbidden'):
    t.Stop()
  # Final string reflects final (not partial)
  assert str(t) == 'X: 1.500 s'
  # Logged exactly once
  msgs = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['X: 1.500 s']


def test_Timer_context_manager_logs_and_optionally_prints(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str]) -> None:
  """Test."""
  # Enter=10.00, Exit=10.25 → 0.25 s
  _mock_perf(monkeypatch, [10.00, 10.25])
  caplog.set_level(logging.INFO)
  with base.Timer('CTX', emit_print=True):
    pass
  # Logged
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['CTX: 250.000 ms']
  # Printed (because emit_print=True in __exit__)
  out = capsys.readouterr().out.strip()
  assert out == 'CTX: 250.000 ms'


def test_Timer_context_manager_exception_still_times_and_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
  """Test."""
  # Enter=5.0, Exit=5.3 → 0.3 s even if exception occurs
  _mock_perf(monkeypatch, [5.0, 5.3])
  caplog.set_level(logging.INFO)

  with pytest.raises(base.Error):
    with base.Timer('ERR'):
      raise base.Error('boom')
  # Stop was called; message logged
  msgs = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['ERR: 300.000 ms']


def test_Timer_decorator_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
  """Test."""
  # Start=1.00, Stop=1.40 → 0.40 s
  _mock_perf(monkeypatch, [1.00, 1.40])
  caplog.set_level(logging.INFO)

  @base.Timer('DEC')
  def _f(a: int, b: int) -> int:
    return a + b

  assert _f(2, 3) == 5
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['DEC: 400.000 ms']


def test_Timer_decorator_emit_print_true_prints_and_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str]) -> None:
  """Test."""
  # Start=2.00, Stop=2.01 → 0.01 s
  _mock_perf(monkeypatch, [2.00, 2.01])
  caplog.set_level(logging.INFO)

  @base.Timer('PRINT', emit_print=True)
  def _g() -> str:
    return 'ok'

  assert _g() == 'ok'
  # Logs (Stop) and prints (in __exit__)
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['PRINT: 10.000 ms']
  out: str = capsys.readouterr().out.strip()
  assert out == 'PRINT: 10.000 ms'


def test_Timer_decorator_exception_propagates_and_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
  """Test."""
  # Start=3.0, Stop=3.2 → 0.2 s even when raising
  _mock_perf(monkeypatch, [3.0, 3.2])
  caplog.set_level(logging.INFO)

  @base.Timer('ERR')
  def _h() -> None:
    raise base.Error('nope')

  with pytest.raises(base.Error, match='nope'):
    _h()
  msgs: list[str] = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['ERR: 200.000 ms']


@pytest.mark.stochastic
def test_RandBits() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='n_bits must be ≥ 8'):
    base.RandBits(7)
  gn: set[int] = set()
  for _ in range(50):
    gn.add(base.RandBits(10))
  assert len(gn) > 30  # has a chance of 1 in 531,000 to fail
  gn = set()
  for _ in range(20):
    gn.add(base.RandBits(10000))
  assert len(gn) == 20  # has a chance of 1 in 10**3008 to fail


@pytest.mark.stochastic
@pytest.mark.slow
def test_RandBits_bit_length_and_bias() -> None:
  """Test."""
  for n_bits in (8, 17, 64, 4096):
    xs: list[int] = [base.RandBits(n_bits) for _ in range(4000)]
    assert all(x.bit_length() == n_bits for x in xs)
    # check a few low bits for ~0.5 frequency
    for k in (0, 1, 2, 3):
      ones: int = sum((x >> k) & 1 for x in xs)
      p: float = ones / len(xs)
      assert 0.45 <= p <= 0.55  # has a chance of 1 in 10**8 to fail


@pytest.mark.stochastic
def test_RandInt() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='min_int must be ≥ 0, and < max_int'):
    base.RandInt(-1, 1)
  with pytest.raises(base.InputError, match='min_int must be ≥ 0, and < max_int'):
    base.RandInt(2, 1)
  with pytest.raises(base.InputError, match='min_int must be ≥ 0, and < max_int'):
    base.RandInt(2, 2)
  gn: set[int] = set()
  for _ in range(200):
    gn.add(base.RandInt(10, 20))
  assert min(gn) == 10
  assert max(gn) == 20
  assert len(gn) == 11  # chance of failure of 1 in 17.26 million


@pytest.mark.stochastic
@pytest.mark.slow
def test_RandInt_uniform_small_range() -> None:
  """Test."""
  N: int = 30000
  counts: collections.Counter[int] = collections.Counter(base.RandInt(10, 20) for _ in range(N))
  # each should be close to N/11
  for c in counts.values():
    assert abs(c - N / 11) < 0.1 * N / 11  # chance of failure of 1 in 10 million


@pytest.mark.stochastic
def test_RandShuffle() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='seq must have 2 or more elements'):
    base.RandShuffle([])
  with pytest.raises(base.InputError, match='seq must have 2 or more elements'):
    base.RandShuffle([2])
  seq: list[int] = [i + 1 for i in range(100)]  # sorted list [1, 2, 3, ... 100]
  for _ in range(10):
    seq_copy: list[int] = seq.copy()
    base.RandShuffle(seq_copy)
    assert seq != seq_copy  # chance of failure in any of 10 tests is 1 in 10**156


@pytest.mark.stochastic
def test_RandShuffle_preserves_multi_set() -> None:
  """Test."""
  seq: list[int] = [1, 2, 2, 3, 4]
  before: collections.Counter[int] = collections.Counter(seq)
  base.RandShuffle(seq)
  assert collections.Counter(seq) == before
  assert len(seq) == 5


@pytest.mark.stochastic
def test_RandShuffle_n2_visits_both_orders() -> None:
  """Test."""
  seq: list[int] = [1, 2, 3]
  seen: set[tuple[int, ...]] = set()
  for _ in range(200):
    s: list[int] = seq[:]  # copy
    base.RandShuffle(s)
    seen.add(tuple(s))
  assert seen == {
      (1, 2, 3), (3, 2, 1), (2, 3, 1),
      (2, 1, 3), (1, 3, 2), (3, 1, 2)}  # chance of failure is 1 in 10**40


@pytest.mark.stochastic
def test_RandShuffle_small_n_uniformity() -> None:
  """Test."""
  base_list: list[int] = [1, 2, 3]
  perms: list[tuple[int, ...]] = list(itertools.permutations(base_list))
  counts: dict[tuple[int, ...], int] = {p: 0 for p in perms}
  N: int = 6000
  for _ in range(N):
    s: list[int] = base_list[:]
    base.RandShuffle(s)
    counts[tuple(s)] += 1
  # each of 6 perms should be close to N/6
  for c in counts.values():
    assert abs(c - N / 6) < 0.2 * (N / 6)  # chance of failure in any of 6 deviates is 1 in 10**11


@pytest.mark.stochastic
def test_RandBytes() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='n_bytes must be ≥ 1'):
    base.RandBytes(0)
  assert len(base.RandBytes(1)) == 1
  assert len(base.RandBytes(1000)) == 1000
  assert len(set(base.RandBytes(32) for _ in range(100))) == 100  # chance of failure is 1 in 10**74


@pytest.mark.stochastic
def test_RandBits_RandInt_RandShuffle_parallel_smoke() -> None:
  """Test."""
  with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    xs: list[int] = list(ex.map(lambda _: base.RandBits(256), range(200)))     # type:ignore
    ys: list[int] = list(ex.map(lambda _: base.RandInt(0, 1000), range(200)))  # type:ignore
    zs: list[bytes] = list(ex.map(lambda _: base.RandBytes(32), range(200)))   # type:ignore
    seq: list[int] = list(range(50))
    # shuffle some independent copies
    list(ex.map(lambda _: base.RandShuffle(seq[:]), range(50)))  # type:ignore
  assert len(set(xs)) == len(xs)
  assert all(0 <= y <= 1000 for y in ys)  # chance of failure in any of 200 draws is 1 in 10**73
  assert len(set(zs)) == len(zs)


@pytest.mark.parametrize('n', [1, 17, 10 ** 12])
def test_GCD_same_number(n: int) -> None:
  """Test."""
  assert base.GCD(n, n) == n
  g, x, y = base.ExtendedGCD(n, n)
  assert g == n == n * (x + y)  # because x or y will be 0


@pytest.mark.parametrize('a, b, gcd, x, y', [
    (0, 1, 1, 0, 1),
    (1, 0, 1, 1, 0),
    (1, 2, 1, 1, 0),
    (2, 1, 1, 0, 1),
    (12, 18, 6, -1, 1),
    (3, 7, 1, -2, 1),
    (7, 3, 1, 1, -2),
    (100, 24, 4, 1, -4),
    (100, 0, 100, 1, 0),
    (24, 100, 4, -4, 1),
    (367613542, 2136213, 59, 15377, -2646175),
    (2354153438, 65246322, 2, 4133449, -149139030),
    (7238649876345, 36193249381725, 7238649876345, 1, 0),
])
def test_GCD(a: int, b: int, gcd: int, x: int, y: int) -> None:
  """Test."""
  assert base.GCD(a, b) == gcd
  assert base.ExtendedGCD(a, b) == (gcd, x, y)
  assert gcd == a * x + b * y


@pytest.mark.parametrize('a, b', [
    (-1, 1),
    (1, -1),
    (0, 0),
])
def test_GCD_negative(a: int, b: int) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='negative input'):
    base.GCD(a, b)
  with pytest.raises(base.InputError, match='negative input'):
    base.ExtendedGCD(a, b)


def test_NegativeZero() -> None:
  """Test."""
  assert base.GCD(-0, 5) == 5  # Python’s -0 is 0
  g, x, y = base.ExtendedGCD(-0, 5)
  assert g == 5 and 5 * y == 5 and not x
  assert 0 == -0


@pytest.mark.parametrize('data, hash256, hash512', [

    # values copied from <https://www.di-mgt.com.au/sha_testvectors.html>

    pytest.param(
        '',
        'e3b0c44298fc1c14 9afbf4c8996fb924 27ae41e4649b934c a495991b7852b855',
        'cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce'
        '47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e',
        id='empty'),

    pytest.param(
        'abc',
        'ba7816bf8f01cfea 414140de5dae2223 b00361a396177a9c b410ff61f20015ad',
        'ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a'
        '2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f',
        id='abc'),

    pytest.param(
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',  # cspell:disable-line
        '248d6a61d20638b8 e5c026930c3e6039 a33ce45964ff2167 f6ecedd419db06c1',
        '204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335'
        '96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445',
        id='NIST-long-1'),

    pytest.param(
        'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi'
        'jklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
        'cf5b16a778af8380 036ce59e7b049237 0b249b11e8f07a51 afac45037afee9d1',
        '8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018'
        '501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909',
        id='NIST-long-2'),

    pytest.param(
        'a' * 1000000,
        'cdc76e5c9914fb92 81a1c7e284d73e67 f1809a48a497200e 046d39ccc7112cd0',
        'e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb'
        'de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b',
        id='a*1_000_000'),

])
def test_Hash(data: str, hash256: str, hash512: str) -> None:
  """Test."""
  bytes_data: bytes = data.encode('utf-8')
  # raw SHA-256
  h1: bytes = base.Hash256(bytes_data)
  assert len(h1) == 32
  assert base.BytesToHex(h1) == hash256.replace(' ', '')
  # raw SHA-512
  h2: bytes = base.Hash512(bytes_data)
  assert len(h2) == 64
  assert base.BytesToHex(h2) == hash512.replace(' ', '')
  # save data to temp file
  with tempfile.NamedTemporaryFile() as temp_file:
    temp_file.write(bytes_data)
    temp_file.flush()
    file_path: str = temp_file.name
    # SHA-256 file
    h3: bytes = base.FileHash(file_path)
    assert len(h3) == 32
    assert base.BytesToHex(h3) == hash256.replace(' ', '')
    # SHA-512 file
    h4: bytes = base.FileHash(file_path, digest='sha512')
    assert len(h4) == 64
    assert base.BytesToHex(h4) == hash512.replace(' ', '')
    # invalid digest type, but file exits
    with pytest.raises(base.InputError, match='unrecognized digest'):
      base.FileHash(file_path, digest='sha100')


def test_FileHash_missing_file() -> None:
  """Test."""
  with pytest.raises(base.InputError, match=r'file .* not found for hashing'):
    base.FileHash('/path/to/surely/not/exist-123')


@typeguard.suppress_type_checks
def test_ObfuscateSecret() -> None:
  """Test."""
  assert base.ObfuscateSecret('abc') == 'ddaf35a1…'
  assert base.ObfuscateSecret(b'abcd') == 'd8022f20…'
  assert base.ObfuscateSecret(123) == 'c2d03c6e…'
  with pytest.raises(base.InputError, match=r'invalid type for data.*float'):
    base.ObfuscateSecret(123.4)  # type:ignore


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class _ToyCrypto(base.CryptoKey):
  """Toy class."""

  key: bytes
  secret: str
  modulus: int

  def __str__(self) -> str:
    """String."""
    return (f'_ToyCrypto(key={base.ObfuscateSecret(self.key)}, '
            f'secret={base.ObfuscateSecret(self.secret)}, '
            f'modulus={base.ObfuscateSecret(self.modulus)})')


def test_CryptoKey_base() -> None:
  """Test."""
  crypto = _ToyCrypto(key=b'abc', secret='cba', modulus=123)
  key = aes.AESKey(key256=b'x' * 32)
  assert str(crypto) == '_ToyCrypto(key=ddaf35a1…, secret=3b1d17bf…, modulus=c2d03c6e…)'
  assert str(crypto) == repr(crypto)
  assert crypto._DebugDump() == '_ToyCrypto(key=b\'abc\', secret=\'cba\', modulus=123)'
  assert crypto.blob == (
      b'(\xb5/\xfd C\x19\x02\x00\x80\x04\x958\x00\x00\x00\x00\x00\x00\x00\x8c\x0ftests.base_test'  # cspell:disable-line
      b'\x94\x8c\n_ToyCrypto\x94\x93\x94)\x81\x94]\x94(C\x03abc\x94\x8c\x03cba\x94K{eb.')
  assert crypto.blob == crypto.Blob()        # Blob() with no options should be the same as blob
  assert crypto.encoded == crypto.Encoded()  # Encoded() with no options should be same as encoded
  assert _ToyCrypto.Load(crypto.blob) == crypto
  assert crypto.encoded == (
      'KLUv_SBDGQIAgASVOAAAAAAAAACMD3Rlc3RzLmJhc2VfdGVzdJSMCl9Ub3lDcnlwdG-Uk5QpgZRdlCh'  # cspell:disable-line
      'DA2FiY5SMA2NiYZRLe2ViLg==')
  assert _ToyCrypto.Load(crypto.encoded) == crypto
  blob_crypto: bytes = crypto.Blob(key=key)
  assert _ToyCrypto.Load(blob_crypto, key=key) == crypto
  encoded_crypto: str = crypto.Encoded(key=key)
  assert _ToyCrypto.Load(encoded_crypto, key=key) == crypto
  with typeguard.suppress_type_checks():
    with pytest.raises(base.InputError, match=r'serialized data is not a CryptoKey.*dict'):
      _ToyCrypto.Load(base.Serialize({1: 2, 3: 4}, compress=None))  # binary is a dict


@pytest.fixture
def sample_obj() -> dict[str, Any]:
  """Sample object fixture."""
  # moderately nested object to exercise pickle well
  return {
      'nums': list(range(50)),
      'nested': {'a': 1, 'b': b'bytes', 'c': None},
      'text': 'zstd 🍰 compression test',
  }


def test_serialize_deserialize_no_compress_no_encrypt(
    sample_obj: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
  """Test."""
  blob: bytes = base.Serialize(sample_obj, compress=None)
  # should NOT look like zstd: DeSerialize should skip decompression path
  obj2 = base.DeSerialize(data=blob)
  assert obj2 == sample_obj


def test_serialize_deserialize_with_compress_negative_clamped(
    sample_obj: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
  """Test."""
  # request a very fast negative level; function clamps to >= -22 then compresses
  blob: bytes = base.Serialize(sample_obj, compress=-100)  # expect clamp to -22 internally
  # Verify magic-detected zstd path and successful round-trip
  obj2 = base.DeSerialize(data=blob)
  assert obj2 == sample_obj


def test_serialize_deserialize_with_compress_high_clamped(
    sample_obj: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
  """Test."""
  # request above max; function clamps to 22
  blob: bytes = base.Serialize(sample_obj, compress=99)
  obj2 = base.DeSerialize(data=blob)
  assert obj2 == sample_obj


def test_serialize_deserialize_with_encrypt_ok(
    sample_obj: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
  """Test."""
  key = aes.AESKey(key256=b'x' * 32)
  blob: bytes = base.Serialize(sample_obj, compress=3, key=key)
  # must supply same key (and same AAD inside implementation)
  obj2 = base.DeSerialize(data=blob, key=key)
  assert obj2 == sample_obj


def test_serialize_save_and_load_from_file(
    tmp_path: pathlib.Path, sample_obj: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
  """Test."""
  p: pathlib.Path = tmp_path / 'payload.bin'
  blob: bytes = base.Serialize(sample_obj, compress=3, file_path=str(p))
  assert p.exists() and p.stat().st_size == len(blob)
  obj2 = base.DeSerialize(file_path=str(p))
  assert obj2 == sample_obj


def test_deserialize_exclusivity_both_args(tmp_path: pathlib.Path) -> None:
  """Test."""
  p: pathlib.Path = tmp_path / 'x.bin'
  p.write_bytes(b'data')
  with pytest.raises(base.InputError, match='you must provide only one of either'):
    base.DeSerialize(data=b'data', file_path=str(p))


def test_deserialize_invalid_calls() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='you must provide only one of either'):
    base.DeSerialize()
  with pytest.raises(base.InputError, match='invalid file_path'):
    base.DeSerialize(file_path='/definitely/not/here.bin')
  with pytest.raises(base.InputError, match='invalid data: too small'):
    base.DeSerialize(data=b'\x00\x01\x02')


def test_deserialize_wrong_key_raises(
    sample_obj: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
  """Test."""
  key_ok = aes.AESKey(key256=b'x' * 32)
  key_bad = aes.AESKey(key256=b'y' * 32)
  blob: bytes = base.Serialize(sample_obj, compress=3, key=key_ok)
  with pytest.raises(base.CryptoError):
    base.DeSerialize(data=blob, key=key_bad)


def test_deserialize_corrupted_zstd_raises(
    sample_obj: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
  """Test."""
  # create a valid zstd-compressed blob
  blob: bytes = base.Serialize(sample_obj, compress=3)
  # corrupt a byte beyond the first 4 (to keep magic intact)
  mutable = bytearray(blob)
  if len(mutable) <= 10:
    pytest.skip('blob too small to corrupt safely for this test')
  mutable[10] ^= 0xFF
  corrupted = bytes(mutable)
  # DeSerialize should detect zstd via magic, attempt to decompress, and zstd should error
  with pytest.raises(base.zstandard.ZstdError):
    base.DeSerialize(data=corrupted)


def test_deserialize_no_compression_detected_branch(
    sample_obj: dict[str, Any]) -> None:  # pylint: disable=redefined-outer-name
  """Test."""
  # Craft a blob that is NOT zstd: disable compression
  blob: bytes = base.Serialize(sample_obj, compress=None)
  # This exercises the "(no compression detected)" branch
  obj2 = base.DeSerialize(data=blob)
  assert obj2 == sample_obj


@pytest.mark.parametrize('secret, public_hash, bid_str', [
    pytest.param(
        b'a',
        '711f48ea38b803f8d2026846e7a8fb637879e818f60f768594bc91f061f23c00'
        '4187183c2d8c81c3b67feb534e5cad90b3d9eae9488a525dd037eccac9512f2f',
        'PrivateBid512(PublicBid512(public_key=eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4'
        'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==, public_hash=711f48ea38b803f8d2026846e7a8fb637879e818f6'
        '0f768594bc91f061f23c004187183c2d8c81c3b67feb534e5cad90b3d9eae9488a525dd037eccac9512f2f), '
        'private_key=81e396cb…, secret_bid=1f40fc92…)',
        id='a'),
    pytest.param(
        b'secret',
        'ab13b41fe50fef61483f2ce495ca5af1e173245811ef8610023d61b0d12d3f52'
        'd9c1b92388fec771dc4601bc36c4ddffe713e64532c01eb8936e29e06d10f936',
        'PrivateBid512(PublicBid512(public_key=eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4'
        'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==, public_hash=ab13b41fe50fef61483f2ce495ca5af1e173245811'
        'ef8610023d61b0d12d3f52d9c1b92388fec771dc4601bc36c4ddffe713e64532c01eb8936e29e06d10f936), '
        'private_key=81e396cb…, secret_bid=bd2b1aaf…)',
        id='secret'),
    pytest.param(
        b'longer secret value with spaces',
        '5f25720c817a89c446e51ce56e64643aa5343cb1898904ea0e45b8ad5f4caabc'
        'aba091fb7e122bfff8d8b54855fcaa27e0f962d98c8eebae3a7765393c0fdf6a',
        'PrivateBid512(PublicBid512(public_key=eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4'
        'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==, public_hash=5f25720c817a89c446e51ce56e64643aa5343cb189'
        '8904ea0e45b8ad5f4caabcaba091fb7e122bfff8d8b54855fcaa27e0f962d98c8eebae3a7765393c0fdf6a), '
        'private_key=81e396cb…, secret_bid=826df62c…)',
        id='longer secret value with spaces'),
])
@mock.patch('src.transcrypto.base.RandBytes', autospec=True)
def test_Bid_with_mock(
    randbytes: mock.MagicMock, secret: bytes, public_hash: str, bid_str: str) -> None:
  """Test."""
  randbytes.side_effect = [b'x' * 64, b'y' * 64]
  priv: base.PrivateBid512 = base.PrivateBid512.New(secret)
  pub: base.PublicBid512 = base.PublicBid512.Copy(priv)
  assert base.BytesToHex(pub.public_hash) == public_hash
  priv_s = str(priv)
  assert priv_s == bid_str
  assert priv_s == repr(priv) and str(pub) == repr(pub)
  assert pub.VerifyBid(b'y' * 64, secret)
  assert not pub.VerifyBid(b'y' * 64, secret + b'x')
  assert not pub.VerifyBid(b'z' * 64, secret)
  assert randbytes.call_args_list == [mock.call(64), mock.call(64)]


@pytest.mark.stochastic
@pytest.mark.parametrize('secret', [
    b'a',
    b'secret',
    b'longer secret value with spaces',
])
def test_Bid(secret: bytes) -> None:
  """Test."""
  priv1: base.PrivateBid512 = base.PrivateBid512.New(secret)
  priv2: base.PrivateBid512 = base.PrivateBid512.New(secret)
  pub: base.PublicBid512 = base.PublicBid512.Copy(priv1)
  assert pub.VerifyBid(priv1.private_key, secret)
  assert not pub.VerifyBid(priv1.private_key, secret + b'x')
  assert not pub.VerifyBid(priv2.private_key, secret)
  assert priv1.public_key != priv2.public_key  # this could fail with probability 1 in 2**512...
  assert priv1.private_key != priv2.private_key
  assert priv1.public_hash != priv2.public_hash
  assert priv2.VerifyBid(priv2.private_key, secret)


def test_Bid_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid public_key or public_hash'):
    base.PublicBid512(public_key=b'key', public_hash=b'hash')
  with pytest.raises(base.InputError, match='invalid private_key or secret_bid'):
    base.PrivateBid512(
        public_key=b'k' * 64, public_hash=b'h' * 64, private_key=b'priv', secret_bid=b'secret')
  with pytest.raises(base.CryptoError, match='inconsistent bid'):
    base.PrivateBid512(
        public_key=b'k' * 64, public_hash=b'h' * 64, private_key=b'p' * 64, secret_bid=b'secret')
  with pytest.raises(base.InputError, match='invalid secret length'):
    base.PrivateBid512.New(b'')


def test_rows_for_actions_metadata_branches() -> None:
  """Build a synthetic parser to trigger _FlagNames/_Format* metadata paths."""
  p = argparse.ArgumentParser(add_help=False)
  # Positional arg with nargs=2 and tuple metavar → exercises tuple branch in _FlagNames
  p.add_argument('pos', nargs=2, metavar=('FILE1', 'FILE2'))
  p.add_argument('pos2', nargs=2, metavar='FILE3')  # also test single string metavar
  # Boolean default True (store_true normally False) → _FormatDefault(bool True)
  p.add_argument('--switch', action='store_true', default=True, help='flag with default true')
  # Choices → _FormatChoices
  p.add_argument('--color', choices=['red', 'blue'], help='choose color')
  # Type=int and default value → _FormatType + _FormatDefault
  p.add_argument('--num', type=int, default=7, help='number')
  rows: list[tuple[str, str]] = base._RowsForActions(p._actions)  # type: ignore[attr-defined]
  # Flatten for easy search
  flat: str = '\n'.join(f'{l} :: {r}' for (l, r) in rows)
  # Tuple metavar shows both names
  assert 'FILE1, FILE2' in flat and 'FILE3' in flat
  # store_true default on
  assert '(default: on)' in flat
  # choices listed
  assert 'choices: [\'red\', \'blue\']' in flat or 'choices: ["red", "blue"]' in flat
  # type int appears
  assert 'type: int' in flat
  # default numeric prints
  assert '(default: 7)' in flat


def test_markdown_table_helper() -> None:
  """Tiny check of _MarkdownTable formatting."""
  table: str = base._MarkdownTable([('A', 'alpha'), ('B', 'beta')])
  assert table.splitlines()[0].startswith('| Option/Arg |')
  assert '`A`' in table and 'alpha' in table
  assert base._MarkdownTable([]) == ''  # empty input → empty output


def test_rows_for_actions_cover_suppress_custom_and_help() -> None:
  """Drive _RowsForActions metadata branches: SUPPRESS, custom type, help action."""
  # Keep add_help=True to include the built-in -h/--help action (exercises isinstance(_HelpAction))
  p = argparse.ArgumentParser()
  # Arg with default=SUPPRESS → exercises that early-return in _FormatDefault
  p.add_argument('--maybe', default=argparse.SUPPRESS, help='maybe suppressed default')

  # Custom callable without __name__ → forces 'type: custom' in _FormatType
  class _CallableNoName:  # pragma: no cover - cover is for transcrypto lines, not this helper  # pylint: disable=too-few-public-methods
    def __call__(self, s: str) -> str:
      return s

  p.add_argument('--weird', type=_CallableNoName(), help='custom callable type')
  # Also add one standard store_true to hit bool-default branch
  p.add_argument('--flag', action='store_true', default=False, help='bool default false')
  rows: list[tuple[str, str]] = base._RowsForActions(p._actions)  # type: ignore[attr-defined]
  text: str = '\n'.join(f'{l} :: {r}' for (l, r) in rows)
  # SUPPRESS default should not render a "(default: ...)" string
  assert '--maybe' in text and '(default:' not in text.split('--maybe', 1)[1].splitlines()[0]
  # Custom callable should show "type: custom"
  assert 'type: custom' in text
  # Built-in help action is skipped by _RowsForActions; make sure other rows exist
  assert any('--flag' in l for (l, _r) in rows)


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
