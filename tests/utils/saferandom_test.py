# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/saferandom.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/saferandom_test.py
"""

from __future__ import annotations

import collections
import concurrent.futures
import itertools

import pytest

from transcrypto.core import base


@pytest.mark.stochastic
def test_RandBits() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='n_bits must be ≥ 8'):
    base.RandBits(7)
  gn: set[int] = set()
  gn.update(base.RandBits(10) for _ in range(50))
  assert len(gn) > 30  # has a chance of 1 in 531,000 to fail
  gn = set()
  gn.update(base.RandBits(10000) for _ in range(20))
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
  gn.update(base.RandInt(10, 20) for _ in range(200))
  assert min(gn) == 10
  assert max(gn) == 20
  assert len(gn) == 11  # chance of failure of 1 in 17.26 million


@pytest.mark.stochastic
@pytest.mark.slow
def test_RandInt_uniform_small_range() -> None:
  """Test."""
  n: int = 30000
  counts: collections.Counter[int] = collections.Counter(base.RandInt(10, 20) for _ in range(n))
  # each should be close to N/11
  for c in counts.values():
    assert abs(c - n / 11) < 0.1 * n / 11  # chance of failure of 1 in 10 million


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
    s: list[int] = seq.copy()  # copy
    base.RandShuffle(s)
    seen.add(tuple(s))
  assert seen == {
    (1, 2, 3),
    (3, 2, 1),
    (2, 3, 1),
    (2, 1, 3),
    (1, 3, 2),
    (3, 1, 2),
  }  # chance of failure is 1 in 10**40


@pytest.mark.stochastic
def test_RandShuffle_small_n_uniformity() -> None:
  """Test."""
  base_list: list[int] = [1, 2, 3]
  perms: list[tuple[int, ...]] = list(itertools.permutations(base_list))
  counts: dict[tuple[int, ...], int] = dict.fromkeys(perms, 0)
  n: int = 6000
  for _ in range(n):
    s: list[int] = base_list.copy()
    base.RandShuffle(s)
    counts[tuple(s)] += 1
  # each of 6 perms should be close to N/6
  for c in counts.values():
    assert abs(c - n / 6) < 0.2 * (n / 6)  # chance of failure in any of 6 deviates is 1 in 10**11


@pytest.mark.stochastic
def test_RandBytes() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='n_bytes must be ≥ 1'):
    base.RandBytes(0)
  assert len(base.RandBytes(1)) == 1
  assert len(base.RandBytes(1000)) == 1000
  assert len({base.RandBytes(32) for _ in range(100)}) == 100  # chance of failure is 1 in 10**74


@pytest.mark.stochastic
def test_RandBits_RandInt_RandShuffle_parallel_smoke() -> None:
  """Test."""
  with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    xs: list[int] = list(ex.map(lambda _: base.RandBits(256), range(200)))  # pyright: ignore
    ys: list[int] = list(ex.map(lambda _: base.RandInt(0, 1000), range(200)))  # pyright: ignore
    zs: list[bytes] = list(ex.map(lambda _: base.RandBytes(32), range(200)))  # pyright: ignore
    seq: list[int] = list(range(50))
    # shuffle some independent copies
    list(ex.map(lambda _: base.RandShuffle(seq[:]), range(50)))  # pyright: ignore
  assert len(set(xs)) == len(xs)
  assert all(0 <= y <= 1000 for y in ys)  # chance of failure in any of 200 draws is 1 in 10**73
  assert len(set(zs)) == len(zs)
