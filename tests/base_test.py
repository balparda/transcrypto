#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""base.py unittest."""

import collections
import concurrent.futures
import itertools
import logging
import math
import pdb
import sys
import tempfile
from typing import Generator

import pytest

from src.transcrypto import base

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
  assert base.BytesToEncoded(padded) == 'AAAAAAB4eXo='
  assert base.HexToBytes('000000000078797a') == padded
  assert base.EncodedToBytes('AAAAAAB4eXo=') == padded


@pytest.mark.parametrize('value, message', [
    (0, '0 B'),                   # bytes < 1024
    (512, '512 B'),
    (1024, '1.00 KiB'),           # exact KiB
    (1536, '1.50 KiB'),           # mid KiB
    (1024 ** 2, '1.00 MiB'),      # exact MiB
    (5 * 1024 ** 2, '5.00 MiB'),
    (1024 ** 3, '1.00 GiB'),      # exact GiB
    (3 * 1024 ** 3, '3.00 GiB'),
    (1024 ** 4, '1.00 TiB'),      # exact TiB
    (7 * 1024 ** 4, '7.00 TiB'),
    (1024 ** 5, '1.00 PiB'),      # exact PiB
    (2 * 1024 ** 5, '2.00 PiB'),
    (1024 ** 6, '1.00 EiB'),      # exact EiB
    (8 * 1024 ** 6, '8.00 EiB'),  # > EiB
])
def test_HumanizedBytes(value: int, message: str) -> None:
  """Test."""
  assert base.HumanizedBytes(value) == message
  
  
@pytest.mark.parametrize('value, message, unit, unit_message', [
    # <1000 integer, no unit / with unit
    (0, '0', 'Hz', '0 Hz'),
    (999, '999', 'V', '999 V'),
    # <1000 float, 4 decimal places
    (0.5, '0.5000', 'Hz', '0.5000 Hz'),
    (999.9999, '999.9999', 'Hz', '999.9999 Hz'),
    # k range
    (1000, '1.00 k', 'Hz', '1.00 kHz'),
    (1500, '1.50 k', 'Hz', '1.50 kHz'),
    # M range
    (1000 ** 2, '1.00 M', 'Hz', '1.00 MHz'),
    (2500000, '2.50 M', 'Hz', '2.50 MHz'),
    # G range
    (1000 ** 3, '1.00 G', 'Hz', '1.00 GHz'),
    (5 * 1000 ** 3, '5.00 G', 'Hz', '5.00 GHz'),
    # T range
    (1000 ** 4, '1.00 T', 'Hz', '1.00 THz'),
    (7 * 1000 ** 4, '7.00 T', 'Hz', '7.00 THz'),
    # P range
    (1000**5, '1.00 P', 'Hz', '1.00 PHz'),
    (3 * 1000 ** 5, '3.00 P', 'Hz', '3.00 PHz'),
    # E range and above
    (1000**6, '1.00 E', 'Hz', '1.00 EHz'),
    (9 * 1000 ** 6, '9.00 E', 'Hz', '9.00 EHz'),
])
def test_HumanizedDecimal(value: int | float, message: str, unit: str, unit_message: str) -> None:
  """Test."""
  assert base.HumanizedDecimal(value) == message
  assert base.HumanizedDecimal(value, unit) == unit_message
  
  
@pytest.mark.parametrize('value, message', [
    # zero
    (0, '0.00 s'),
    # microseconds
    (0.0000005, '0.500 µs'),
    (0.0005, '500.000 µs'),
    (0.000999, '999.000 µs'),
    # milliseconds
    (0.001, '1.000 ms'),
    (0.5, '500.000 ms'),
    (0.999, '999.000 ms'),
    # seconds
    (1, '1.00 s'),
    (59.99, '59.99 s'),   # edge just under a minute
    (42, '42.00 s'),
    # minutes
    (60, '1.00 min'),
    (3599, '59.98 min'),  # just under an hour
    # hours
    (3600, '1.00 h'),
    (86399, '24.00 h'),   # just under a day
    # days
    (86400, '1.00 d'),
    (172800, '2.00 d'),
])
def test_HumanizedSeconds(value: int | float, message: str) -> None:
  """Test."""
  assert base.HumanizedSeconds(value) == message


def test_Humanized_fail() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedBytes(-1)
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedDecimal(-1)
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedSeconds(-1)
  # NaN
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedDecimal(math.nan)
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedSeconds(math.nan)
  # infinity
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedDecimal(math.inf)
  with pytest.raises(base.InputError, match='input should be >=0'):
    base.HumanizedSeconds(math.inf)


def test_RandBits() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='n_bits must be ≥ 8'):
    base.RandBits(7)
  gn: set[int] = set()
  for _ in range(50):
    gn.add(base.RandBits(8))
  assert len(gn) > 30  # has a chance of 1 in 531,000 to fail
  gn = set()
  for _ in range(20):
    gn.add(base.RandBits(10000))
  assert len(gn) == 20  # has a chance of 1 in 10**3008 to fail


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


def test_RandInt_uniform_small_range() -> None:
  """Test."""
  N: int = 30000
  counts = collections.Counter(base.RandInt(10, 20) for _ in range(N))
  # each should be close to N/11
  for c in counts.values():
    assert abs(c - N/11) < 0.1 * N/11  # chance of failure of 1 in 10 million


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


def test_RandShuffle_preserves_multiset() -> None:
  """Test."""
  seq: list[int] = [1, 2, 2, 3, 4]
  before = collections.Counter(seq)
  base.RandShuffle(seq)
  assert collections.Counter(seq) == before
  assert len(seq) == 5


def test_RandShuffle_n2_visits_both_orders() -> None:
  """Test."""
  seq: list[int] = [1, 2]
  seen: set[int] = set()
  for _ in range(200):
    s: list[int] = seq[:]  # copy
    base.RandShuffle(s)
    seen.add(tuple(s))
  assert seen == {(1, 2), (2, 1)}  # chance of failure is 1 in 10**60


def test_RandShuffle_small_n_uniformity() -> None:
  """Test."""
  base_list: list[int] = [1, 2, 3]
  perms: list[int] = list(itertools.permutations(base_list))
  counts: dict[int, int] = {p: 0 for p in perms}
  N: int = 6000
  for _ in range(N):
    s: list[int] = base_list[:]
    base.RandShuffle(s)
    counts[tuple(s)] += 1
  # each of 6 perms should be close to N/6
  for c in counts.values():
    assert abs(c - N/6) < 0.2 * (N/6)  # chance of failure in any of 6 deviates is 1 in 10**11
    
    
def test_RandBytes() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='n_bytes must be ≥ 1'):
    base.RandBytes(0)
  assert len(base.RandBytes(1)) == 1
  assert len(base.RandBytes(1000)) == 1000
  assert len(set(base.RandBytes(32) for _ in range(100))) == 100  # chance of failure is 1 in 10**74


def test_RandBits_RandInt_RandShuffle_parallel_smoke() -> None:
  """Test."""
  with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    xs = list(ex.map(lambda _: base.RandBits(256), range(200)))
    ys = list(ex.map(lambda _: base.RandInt(0, 1000), range(200)))
    zs = list(ex.map(lambda _: base.RandBytes(32), range(200)))
    seq = list(range(50))
    # shuffle some independent copies
    list(ex.map(lambda _: base.RandShuffle(seq[:]), range(50)))
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
        'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
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


def _mock_perf(monkeypatch, values):
  """Install a perf_counter that yields from `values`."""
  it = iter(values)
  monkeypatch.setattr(base.time, 'perf_counter', lambda: next(it))


def test_Timer_str_unstarted() -> None:
  t = base.Timer('T')
  assert str(t) == 'T: <UNSTARTED>'


def test_Timer_str_partial(monkeypatch) -> None:
  # Start at 100.00; __str__ calls perf_counter again (100.12) → delta 0.12 s
  _mock_perf(monkeypatch, [100.00, 100.12])
  t = base.Timer('P')
  t.Start()
  assert str(t) == 'P: <PARTIAL> 120.000 ms'


def test_Timer_start_twice_forbidden(monkeypatch) -> None:
  _mock_perf(monkeypatch, [1.0])
  t = base.Timer('X')
  t.Start()
  with pytest.raises(base.Error, match='Re-starting timer is forbidden'):
    t.Start()


def test_Timer_stop_unstarted_forbidden() -> None:
  t = base.Timer('X')
  with pytest.raises(base.Error, match='Stopping an unstarted timer'):
    t.Stop()


def test_Timer_stop_twice_forbidden(monkeypatch, caplog) -> None:
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
  assert str(t) == 'X: 1.50 s'
  # Logged exactly once
  msgs = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['X: 1.50 s']


def test_Timer_context_manager_logs_and_optionally_prints(monkeypatch, caplog, capsys) -> None:
  # Enter=10.00, Exit=10.25 → 0.25 s
  _mock_perf(monkeypatch, [10.00, 10.25])
  caplog.set_level(logging.INFO)
  with base.Timer('CTX', emit_print=True):
    pass
  # Logged
  msgs = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['CTX: 250.000 ms']
  # Printed (because emit_print=True in __exit__)
  out = capsys.readouterr().out.strip()
  assert out == 'CTX: 250.000 ms'


def test_Timer_context_manager_exception_still_times_and_logs(monkeypatch, caplog) -> None:
  # Enter=5.0, Exit=5.3 → 0.3 s even if exception occurs
  _mock_perf(monkeypatch, [5.0, 5.3])
  caplog.set_level(logging.INFO)
  
  class Boom(Exception): ...
  
  with pytest.raises(Boom):
    with base.Timer('ERR'):
      raise Boom('boom')
  # Stop was called; message logged
  msgs = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['ERR: 300.000 ms']


def test_Timer_decorator_logs(monkeypatch, caplog) -> None:
  # Start=1.00, Stop=1.40 → 0.40 s
  _mock_perf(monkeypatch, [1.00, 1.40])
  caplog.set_level(logging.INFO)

  @base.Timer('DEC')
  def f(a, b):
    return a + b

  assert f(2, 3) == 5
  msgs = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['DEC: 400.000 ms']


def test_Timer_decorator_emit_print_true_prints_and_logs(monkeypatch, caplog, capsys) -> None:
  # Start=2.00, Stop=2.01 → 0.01 s
  _mock_perf(monkeypatch, [2.00, 2.01])
  caplog.set_level(logging.INFO)

  @base.Timer('PRINT', emit_print=True)
  def g():
    return 'ok'

  assert g() == 'ok'
  # Logs (Stop) and prints (in __exit__)
  msgs = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['PRINT: 10.000 ms']
  out = capsys.readouterr().out.strip()
  assert out == 'PRINT: 10.000 ms'


def test_Timer_decorator_exception_propagates_and_logs(monkeypatch, caplog) -> None:
  # Start=3.0, Stop=3.2 → 0.2 s even when raising
  _mock_perf(monkeypatch, [3.0, 3.2])
  caplog.set_level(logging.INFO)

  class Oops(Exception): ...

  @base.Timer('DECERR')
  def h():
    raise Oops('nope')

  with pytest.raises(Oops, match='nope'):
    h()
  msgs = [rec.getMessage() for rec in caplog.records]
  assert msgs == ['DECERR: 200.000 ms']


def test_Timer_label_validation() -> None:
  with pytest.raises(base.InputError, match='Empty label'):
    base.Timer('   ')


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
