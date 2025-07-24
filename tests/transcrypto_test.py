#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""transcrypto.py unittest."""

# import pdb
import sys

import pytest

from src.transcrypto import transcrypto

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: tuple[int, int, int] = transcrypto.__version__  # tests inherit version from module


@pytest.mark.parametrize('a, b, gcd, x, y', [
    (0, 0, 0, 1, 0),
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
  assert transcrypto.GCD(a, b) == gcd
  assert transcrypto.ExtendedGCD(a, b) == (gcd, x, y)
  assert gcd == a * x + b * y


@pytest.mark.parametrize('a, b', [
    (-1, 1),
    (1, -1),
])
def test_GCD_negative(a: int, b: int) -> None:
  """Test."""
  with pytest.raises(transcrypto.InputError, match='negative input'):
    transcrypto.GCD(a, b)
  with pytest.raises(transcrypto.InputError, match='negative input'):
    transcrypto.ExtendedGCD(a, b)


@pytest.mark.parametrize('x, m, y', [
    (1, 2, 1),
    (1, 3, 1),
    (2, 3, 2),
    (1, 5, 1),
    (2, 5, 3),
    (3, 5, 2),
    (4, 5, 4),
    (1975, 2 ** 100 + 277, 1048138445657062588680565232826),
    (1976, 2 ** 100 + 277, 1207988906998864353754196425225),
    (2, 2 ** 100 + 331, 633825300114114700748351602854),
    (3, 2 ** 100 + 331, 422550200076076467165567735236),
])
def test_ModInv(x: int, m: int, y: int) -> None:
  """Test."""
  assert transcrypto.ModInv(x, m) == y
  assert transcrypto.ModInv(y, m) == x
  assert (x * y) % m == 1  # check the inverse!


@pytest.mark.parametrize('m', [
    19,
    277,
    1279,
])
def test_ModInv_prime(m: int) -> None:
  """Test."""
  for x in range(1, m):
    y: int = transcrypto.ModInv(x, m)
    assert (x * y) % m == 1  # check the inverse!
    assert transcrypto.ModInv(y, m) == x


@pytest.mark.parametrize('x, y, m, r', [
    # do NOT use x or y > 2500 or so!!
    (0, 0, 1, 0),
    (0, 1, 1, 0),
    (1, 0, 1, 0),
    (1, 1, 1, 0),
    (1, 0, 2, 1),
    (1, 1, 2, 1),
    (2, 2, 2, 0),
    (10, 20, 30, 10),
    (10, 20, 29, 7),
    (20, 10, 13, 4),
    (348, 539, 391, 70),
    (981, 23, 10456, 9309),
    (34, 56, 345789, 304744),
    (2311, 1211, 45678432235, 8849181271),
])
def test_ModExp(x: int, y: int, m: int, r: int) -> None:
  """Test."""
  assert transcrypto.ModExp(x, y, m) == r
  assert (x ** y) % m == r  # also do the computation the hard way


@pytest.mark.parametrize('x, y, m, r', [
    # these numbers are too big to do x ** y directly!
    (34872647, 374534539, 3948756, 2070395),
    (1207614871049878763207, 223048756209847502394, 28768492847692874658, 1649654472198726157),
    (2348765827649287467346, 958374983283487269884, 32879468547653764583, 25996930834540700292),
])
def test_ModExp_big(x: int, y: int, m: int, r: int) -> None:
  """Test."""
  assert transcrypto.ModExp(x, y, m) == r


@pytest.mark.parametrize('x, y', [
    (-1, 1),
    (1, -1),
])
def test_ModExp_negative(x: int, y: int) -> None:
  """Test."""
  with pytest.raises(transcrypto.InputError, match='negative input'):
    transcrypto.ModExp(x, y, 1)


def test_ModExp_ModInv_invalid() -> None:
  """Test."""
  with pytest.raises(transcrypto.InputError, match='invalid input'):
    transcrypto.ModInv(-1, 1)
  with pytest.raises(transcrypto.InputError, match='invalid input'):
    transcrypto.ModInv(3, 2)
  with pytest.raises(transcrypto.ModularDivideError, match=r'null.*with gcd=3'):
    transcrypto.ModInv(0, 3)
  with pytest.raises(transcrypto.ModularDivideError, match=r'invalid.*with gcd=227'):
    transcrypto.ModInv(227, 227 * 229)


@pytest.mark.parametrize('m', [
    -1,
    0,
])
def test_ModExp_ModInv_module(m: int) -> None:
  """Test."""
  with pytest.raises(transcrypto.InputError, match='invalid module'):
    transcrypto.ModInv(0, m)
  with pytest.raises(transcrypto.InputError, match='invalid module'):
    transcrypto.ModExp(1, 1, m)


@pytest.mark.parametrize('n, witnesses, p', [
    # incorrect result because (2**340)%341==1 so 2 is a false witness for 341 (not a prime =11*31)
    # <https://en.wikipedia.org/wiki/Fermat_pseudoprime>
    (341, {2}, True),   # incorrect: 2 is a false witness
    (341, {3}, False),  # correct:   3 is not a false witness
    # 2/3/29/30 are all false witnesses for 8911 (=7*19*67)
    (8911, {2, 3, 29, 30}, True),  # incorrect
    (8911, {5257}, False),         # correct
])
def test_FermatIsPrime(n: int, witnesses: set[int], p: bool) -> None:
  """Test."""
  assert transcrypto.FermatIsPrime(n, witnesses=witnesses) == p


def test_FermatIsPrime_invalid() -> None:
  """Test."""
  with pytest.raises(transcrypto.InputError, match='invalid number'):
    transcrypto.FermatIsPrime(0)
  with pytest.raises(transcrypto.InputError, match='out of bounds safety'):
    transcrypto.FermatIsPrime(11, safety=0)
  with pytest.raises(transcrypto.InputError, match='out of bounds witness'):
    transcrypto.FermatIsPrime(11, witnesses={1, 5})
  with pytest.raises(transcrypto.InputError, match='out of bounds witness'):
    transcrypto.FermatIsPrime(11, witnesses={5, 10})


@pytest.mark.parametrize('n, witnesses', [
    (2 ** 10, {2}),
    (2 ** 20, {31, 73}),
    (2 ** 30, {2, 7, 61}),
    (2 ** 40, {2, 3, 5, 7, 11}),
    (2 ** 45, {2, 3, 5, 7, 11, 13, 17}),
    (2 ** 55, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}),
    (2 ** 75, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41}),
    (2 ** 82, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
               79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137}),
    (2 ** 100, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
                79, 83, 89, 97, 101, 103, 107}),
    (2 ** 200, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43}),
    (2 ** 400, {2, 3, 5, 7, 11, 13, 17, 19}),
    (2 ** 800, {2, 3, 5, 7}),
    (2 ** 1600, {2, 3, 5}),
    (2 ** 1800, {2, 3}),
])
def test_MillerRabinWitnesses(n: int, witnesses: set[int]) -> None:
  """Test."""
  assert transcrypto._MillerRabinWitnesses(n) == witnesses


def test_MillerRabinSR() -> None:
  """Test."""
  for n in range(5, 10000, 2):
    s, r = transcrypto._MillerRabinSR(n)
    assert (2 ** s) * r + 1 == n
  assert transcrypto._MillerRabinSR(110874049911279458869074460673) == (50, 98475938435953)


@pytest.mark.parametrize('n, witnesses, p', [
    (341, {2}, False),   # correct here when incorrect in Fermat
    # incorrect result because (2**2046)%2047==1 so 2 is a false witness for 2047 (not a prime =23*89)
    # <https://en.wikipedia.org/wiki/Strong_pseudoprime>
    (2047, {2}, True),   # incorrect: 2 is a false witness
    (2047, {3}, False),  # correct:   3 is not a false witness
    # 3 is a false witnesses for 8911 (=7*19*67)
    (8911, {3}, True),   # incorrect
    (8911, {7}, False),  # correct
])
def test_MillerRabinIsPrime_limits(n: int, witnesses: set[int], p: bool) -> None:
  """Test."""
  assert transcrypto.MillerRabinIsPrime(n, witnesses=witnesses) == p


def test_COMPOSITE_60() -> None:
  """Test."""
  for n in transcrypto.FIRST_60_PRIMES:
    assert not transcrypto.COMPOSITE_60 % n


def test_IsPrime_basic() -> None:
  """Test."""
  for n in range(1, 283):
    assert transcrypto.MillerRabinIsPrime(n) == (n in transcrypto.FIRST_60_PRIMES)
    assert transcrypto.FermatIsPrime(n) == (n in transcrypto.FIRST_60_PRIMES)


@pytest.mark.parametrize('n, p', [
    (8911, False),   # strong pseudo-prime
    (9881, False),   # strong pseudo-prime
    (2 ** 16 + 1, True),  # 65537, largest Fermat prime
    (97567, False),  # strong pseudo-prime
    (79381, False),  # strong pseudo-prime
    (3825123056546413051, False),
    (3317044064679887385961983, False),
    (2 ** 113 - 1, False),
    (2 ** 127 - 1, True),   # Mersenne prime
    (2 ** 131 - 1, False),
    (2 ** 1279 - 1, True),  # Mersenne prime
])
def test_MillerRabinIsPrime(n: int, p: bool) -> None:
  """Test."""
  assert transcrypto.MillerRabinIsPrime(n) == p


def test_MillerRabinIsPrime_MillerRabinWitnesses_MillerRabinSR_invalid() -> None:
  """Test."""
  with pytest.raises(transcrypto.InputError, match='invalid number'):
    transcrypto.MillerRabinIsPrime(0)
  with pytest.raises(transcrypto.InputError, match='out of bounds witness'):
    transcrypto.MillerRabinIsPrime(11, witnesses={1, 5})
  with pytest.raises(transcrypto.InputError, match='out of bounds witness'):
    transcrypto.MillerRabinIsPrime(11, witnesses={5, 10})
  with pytest.raises(transcrypto.InputError, match='invalid number'):
    transcrypto._MillerRabinWitnesses(4)
  for n in (4, 6, 110):
    with pytest.raises(transcrypto.InputError, match='invalid odd number'):
      transcrypto._MillerRabinSR(n)


def test_PrimeGenerator() -> None:
  """Test."""
  with pytest.raises(transcrypto.InputError, match='invalid number'):
    next(transcrypto.PrimeGenerator(-1))
  for i, n in enumerate(transcrypto.PrimeGenerator(0)):
    if i >= 60:
      break
    assert n == transcrypto.FIRST_60_PRIMES_SORTED[i]
  g = transcrypto.PrimeGenerator(2 ** 100)
  assert next(g) == 2 ** 100 + 277
  assert next(g) == 2 ** 100 + 331


def test_MersennePrimesGenerator() -> None:
  """Test."""
  mersenne: list[int] = []
  for i, n in enumerate(transcrypto.MersennePrimesGenerator(0)):
    mersenne.append(n[0])
    if i > 12:
      break
  assert mersenne == transcrypto.FIRST_49_MERSENNE_SORTED[:14]


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
