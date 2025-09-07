#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""modmath.py unittest."""

from __future__ import annotations

# import pdb
import sys
from unittest import mock

import gmpy2  # type:ignore
import pytest

from src.transcrypto import base, modmath

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = modmath.__version__  # tests inherit version from module


@pytest.mark.parametrize('x, m, y', [
    (1, 2, 1),
    (3, 2, 1),
    (1, 3, 1),
    (2, 3, 2),
    (-1, 3, 2),
    (1, 5, 1),
    (2, 5, 3),
    (3, 5, 2),
    (4, 5, 4),
    (-1, 5, 4),
    (1975, 2 ** 100 + 277, 1048138445657062588680565232826),
    (-1975, 2 ** 100 + 277, 219512154571166812816137972827),
    (1976, 2 ** 100 + 277, 1207988906998864353754196425225),
    (2, 2 ** 100 + 331, 633825300114114700748351602854),
    (3, 2 ** 100 + 331, 422550200076076467165567735236),
])
def test_ModInv(x: int, m: int, y: int) -> None:
  """Test."""
  assert modmath.ModInv(x, m) == y
  assert modmath.ModInv(y, m) == x % m
  assert (x * y) % m == 1  # check the inverse!


@pytest.mark.slow
@pytest.mark.parametrize('m', [
    19,
    277,
    1279,
])
def test_ModInv_prime(m: int) -> None:
  """Test."""
  for x in range(1, m):
    y: int = modmath.ModInv(x, m)
    assert (x * y) % m == 1  # check the inverse!
    assert modmath.ModInv(y, m) == x


def test_ModInv_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid modulus'):
    modmath.ModInv(1, 1)
  with pytest.raises(modmath.ModularDivideError, match=r'null inverse'):
    modmath.ModInv(0, 3)
  with pytest.raises(modmath.ModularDivideError, match=r'null inverse'):
    modmath.ModInv(5, 5)
  with pytest.raises(modmath.ModularDivideError, match=r'invalid.*with gcd=227'):
    modmath.ModInv(227, 227 * 229)


@pytest.mark.parametrize('x, y, m, z', [
    (1, 1, 2, 1),
    (-1, 1, 2, 1),
    (1, -1, 2, 1),
    (1, 1, 3, 1),
    (1, 2, 3, 2),
    (0, 2, 3, 0),
    (1975, 19937, 2 ** 100 + 277, 800634817579067293155764998023),
    (1976, 19937, 2 ** 100 + 277, 1015417569626564856392754686978),
    (1975, 19938, 2 ** 100 + 277, 1068201310785158098833689966806),
    (1975, -19938, 2 ** 100 + 277, 199449289443071302663013238847),
    (-1975, 19938, 2 ** 100 + 277, 199449289443071302663013238847),
    (2, 3, 2 ** 100 + 331, 845100400152152934331135470472),
    (-2, 3, 2 ** 100 + 331, 422550200076076467165567735235),
    (2, -3, 2 ** 100 + 331, 422550200076076467165567735235),
    (199, 271, 2 ** 100 + 331, 963601563273119028443988414671),
    (0, 271, 2 ** 100 + 331, 0),
])
def test_ModDiv(x: int, y: int, m: int, z: int) -> None:
  """Test."""
  assert modmath.ModDiv(x, y, m) == z
  if x:
    assert modmath.ModDiv(y, x, m) == modmath.ModInv(z, m)  # pylint: disable=arguments-out-of-order
  assert (z * y) % m == x % m  # check the division!


@pytest.mark.parametrize('a1, m1, a2, m2, x', [
    (10, 3, 22, 5, 7),
    (-2, 3, -3, 5, 7),
    (11, 19, 3, 17, 258),
    (-1, 19, -1, 17, 322),
    (19937, 57885161, 110503, 74207281, 213159153259226),
    (9689, 57885161, 1279, 74207281, 3232352135479142),
])
def test_CRTPair(a1: int, m1: int, a2: int, m2: int, x: int) -> None:
  """Test."""
  assert modmath.CRTPair(a1, m1, a2, m2) == x
  assert modmath.CRTPair(a2, m2, a1, m1) == x    # pylint: disable=arguments-out-of-order
  # check the relationships
  assert x % m1 == a1 % m1
  assert x % m2 == a2 % m2


def test_CRTPair_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid moduli'):
    modmath.CRTPair(1, 1, 1, 3)
  with pytest.raises(base.InputError, match='invalid moduli'):
    modmath.CRTPair(1, 3, 1, 1)
  with pytest.raises(base.InputError, match='invalid moduli'):
    modmath.CRTPair(1, 3, 1, 3)
  with pytest.raises(modmath.ModularDivideError, match='moduli not co-prime'):
    modmath.CRTPair(1, 3, 1, 6)


def test_ModDiv_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid modulus'):
    modmath.ModDiv(1, 1, 0)
  with pytest.raises(modmath.ModularDivideError, match='divide by zero'):
    modmath.ModDiv(1, 0, 2)


@pytest.mark.parametrize('x, y, m, r', [
    # do NOT use x or y > 2500 or so!!
    (0, 0, 2, 1),
    (0, 1, 2, 0),
    (1, 0, 2, 1),
    (1, 1, 2, 1),
    (2, 2, 2, 0),
    (10, 1, 30, 10),
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
  assert modmath.ModExp(x, y, m) == pow(x, y, m) == gmpy2.powmod(x, y, m) == r  # type:ignore  # pylint:disable=no-member
  assert (x ** y) % m == r  # also do the computation the hard way


@pytest.mark.parametrize('x, y, m, r', [
    # these numbers are too big to do x ** y directly!
    (34872647, 374534539, 3948756, 2070395),
    (1207614871049878763207, 223048756209847502394, 28768492847692874658, 1649654472198726157),
    (2348765827649287467346, 958374983283487269884, 32879468547653764583, 25996930834540700292),
])
def test_ModExp_big(x: int, y: int, m: int, r: int) -> None:
  """Test."""
  assert modmath.ModExp(x, y, m) == r


def test_ModExp_negative() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='negative exponent'):
    modmath.ModExp(1, -1, 2)


@pytest.mark.parametrize('m', [
    -1,
    0,
    1,
])
def test_ModExp_ModInv_modulus(m: int) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid modulus'):
    modmath.ModInv(0, m)
  with pytest.raises(base.InputError, match='invalid modulus'):
    modmath.ModExp(1, 1, m)


@pytest.mark.parametrize('x, p, m, y', [
    (1, [0], 19937, 0),   # f(x) = 0
    (1, [1], 19937, 1),   # f(x) = 1
    (11, [1], 19937, 1),  # f(x) = 1
    (-1, [1], 19937, 1),  # f(x) = 1
    (1, [1, 1], 19937, 2),         # f(x) = x + 1
    (11, [1, 1], 19937, 12),       # f(x) = x + 1
    (1, [1, 2, 1], 19937, 4),      # f(x) = x**2 + 2*x + 1
    (11, [1, 2, 1], 19937, 144),   # f(x) = x**2 + 2*x + 1
    (-11, [1, 2, 1], 19937, 100),  # f(x) = x**2 + 2*x + 1
    (1, [1, 2, 1, 2, 1, 2, 1], 19937, 10),      # f(x) = x**6 + 2*x**5 + x**4 + 2*x**3 + x**2 + 2*x + 1
    (11, [1, 2, 1, 2, 1, 2, 1], 19937, 17725),  # f(x) = x**6 + 2*x**5 + x**4 + 2*x**3 + x**2 + 2*x + 1
    (127, [10, 30, 20, 12, 31], 19937, 12928),
    (128, [10, 30, 20, 12, 31], 19937, 12574),
    (-128, [10, 30, 20, 12, 31], 19937, 14171),
    (128, [-10, 30, -20, 12, -31], 19937, 5766),
    (128, [10, -2 ** 120, 2 ** 400, -12, 31], 19937, 10686),
])
def test_ModPolynomial(x: int, p: list[int], m: int, y: int) -> None:
  """Test."""
  assert modmath.ModPolynomial(x, p, m) == y


def test_ModPolynomial_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='no polynomial'):
    modmath.ModPolynomial(1, [], 2)
  with pytest.raises(base.InputError, match='invalid modulus'):
    modmath.ModPolynomial(1, [1, 1], 0)


@pytest.mark.parametrize('x, p, m, y', [
    (1, {2: 2, 3: 3}, 5, 1),
    (1, {-1: -1, 3: 3}, 5, 1),
    (9, {1: 1, 3: 3}, 5, 4),
    (-1, {1: 1, 3: 3}, 5, 4),
    (23746, {23: 435435435, 45: 7639467, 38476928476: 28374}, 127, 64),
    (23747, {23: 435435435, 45: 7639467, 38476928476: 28374}, 127, 23),
    (23746, {23: 435435435, 45: 7639467, 38476928477: 28374}, 127, 87),
])
def test_ModLagrangeInterpolate(x: int, p: dict[int, int], m: int, y: int) -> None:
  """Test."""
  assert modmath.ModLagrangeInterpolate(x, p, m) == y


@pytest.mark.parametrize('x, p, m, mess', [
    (1, {2: 2, 3: 3}, 1, 'invalid modulus'),
    (1, {}, 5, 'invalid points'),
    (1, {2: 2}, 5, 'invalid points'),
    (1, {4: 2, -1: 1}, 5, 'invalid points'),
])
def test_ModLagrangeInterpolate_invalid(x: int, p: dict[int, int], m: int, mess: str) -> None:
  """Test."""
  with pytest.raises(base.InputError, match=mess):
    modmath.ModLagrangeInterpolate(x, p, m)


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
  assert modmath.FermatIsPrime(n, witnesses=witnesses) == p


def test_FermatIsPrime_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid number'):
    modmath.FermatIsPrime(0)
  with pytest.raises(base.InputError, match='out of bounds safety'):
    modmath.FermatIsPrime(11, safety=0)
  with pytest.raises(base.InputError, match='out of bounds witness'):
    modmath.FermatIsPrime(11, witnesses={1, 5})
  with pytest.raises(base.InputError, match='out of bounds witness'):
    modmath.FermatIsPrime(11, witnesses={5, 10})


@pytest.mark.parametrize('n, witnesses', [
    pytest.param(2 ** 10, {2}, id='2**10'),
    pytest.param(2 ** 20, {31, 73}, id='2**20'),
    pytest.param(2 ** 30, {2, 7, 61}, id='2**30'),
    pytest.param(2 ** 40, {2, 3, 5, 7, 11}, id='2**40'),
    pytest.param(2 ** 45, {2, 3, 5, 7, 11, 13, 17}, id='2**45'),
    pytest.param(2 ** 55, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}, id='2**55'),
    pytest.param(2 ** 75, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41}, id='2**75'),
    pytest.param(
        2 ** 82, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
                  79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137}, id='2**82'),
    pytest.param(
        2 ** 100, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
                   79, 83, 89, 97, 101, 103, 107}, id='2**100'),
    pytest.param(2 ** 200, {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43}, id='2**200'),
    pytest.param(2 ** 400, {2, 3, 5, 7, 11, 13, 17, 19}, id='2**400'),
    pytest.param(2 ** 800, {2, 3, 5, 7}, id='2**800'),
    pytest.param(2 ** 1600, {2, 3, 5}, id='2**1600'),
    pytest.param(2 ** 1800, {2, 3}, id='2**1800'),
])
def test_MillerRabinWitnesses(n: int, witnesses: set[int]) -> None:
  """Test."""
  assert modmath._MillerRabinWitnesses(n) == witnesses


def test_MillerRabinSR() -> None:
  """Test."""
  for n in range(5, 10000, 2):
    s, r = modmath._MillerRabinSR(n)
    assert (2 ** s) * r + 1 == n
  assert modmath._MillerRabinSR(110874049911279458869074460673) == (50, 98475938435953)


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
  assert modmath.MillerRabinIsPrime(n, witnesses=witnesses) == p


@pytest.mark.slow
@pytest.mark.stochastic
def test_IsPrime_basic() -> None:
  """Test."""
  for n in range(1, 283):
    assert modmath.MillerRabinIsPrime(n) == (n in modmath.FIRST_5K_PRIMES)
    assert modmath.FermatIsPrime(n) == (n in modmath.FIRST_5K_PRIMES)
  for n in range(285, 1500):
    assert modmath.MillerRabinIsPrime(n) == (n in modmath.FIRST_5K_PRIMES)
    assert modmath.FermatIsPrime(n, safety=15) == (n in modmath.FIRST_5K_PRIMES)


@pytest.mark.parametrize('n, p', [
    pytest.param(8911, False),        # strong pseudo-prime
    pytest.param(9881, False),        # strong pseudo-prime
    pytest.param(2 ** 16 + 1, True),  # 65537, largest Fermat prime
    pytest.param(97567, False),       # strong pseudo-prime
    pytest.param(79381, False),       # strong pseudo-prime
    pytest.param(3825123056546413051, False),
    pytest.param(3317044064679887385961983, False),
    pytest.param(2 ** 113 - 1, False, id='2**113-1'),
    pytest.param(2 ** 127 - 1, True, id='2**127-1'),    # Mersenne prime
    pytest.param(2 ** 131 - 1, False, id='2**131-1'),
    pytest.param(2 ** 1279 - 1, True, id='2**1279-1'),  # Mersenne prime
])
def test_MillerRabinIsPrime(n: int, p: bool) -> None:
  """Test."""
  assert modmath.MillerRabinIsPrime(n) == p


def test_MillerRabinIsPrime_MillerRabinWitnesses_MillerRabinSR_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid number'):
    modmath.MillerRabinIsPrime(0)
  with pytest.raises(base.InputError, match='out of bounds witness'):
    modmath.MillerRabinIsPrime(11, witnesses={1, 5})
  with pytest.raises(base.InputError, match='out of bounds witness'):
    modmath.MillerRabinIsPrime(11, witnesses={5, 10})
  with pytest.raises(base.InputError, match='invalid number'):
    modmath._MillerRabinWitnesses(4)
  for n in (4, 6, 110):
    with pytest.raises(base.InputError, match='invalid odd number'):
      modmath._MillerRabinSR(n)


@pytest.mark.slow
def test_PrimeGenerator() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='negative number'):
    next(modmath.PrimeGenerator(-1))
  for i, n in enumerate(modmath.PrimeGenerator(0)):
    if i >= 5000:
      break
    assert n == modmath.FIRST_5K_PRIMES_SORTED[i]
  g: modmath.Generator[int, None, None] = modmath.PrimeGenerator(2 ** 100)
  assert next(g) == 2 ** 100 + 277
  assert next(g) == 2 ** 100 + 331


@mock.patch('src.transcrypto.base.RandBits', autospec=True)
def test_NBitRandomPrimes(mock_bits: mock.MagicMock) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid n:'):
    modmath.NBitRandomPrimes(7)
  mock_bits.side_effect = [12345, 194, 194, 210, 150]
  assert modmath.NBitRandomPrimes(8).pop() == 197
  assert modmath.NBitRandomPrimes(8, n_primes=3) == {151, 197, 211}
  assert mock_bits.call_args_list == [mock.call(8)] * 5


@pytest.mark.slow
@pytest.mark.stochastic
def test_NBitRandomPrimes_multiple() -> None:
  """Test."""
  pr1: set[int] = modmath.NBitRandomPrimes(200, serial=False, n_primes=20)
  pr2: set[int] = modmath.NBitRandomPrimes(200, serial=True, n_primes=20)
  assert len(pr1) == len(pr2) == 20
  pr1 = pr1.union(pr2)
  assert len(pr1) == 40 and all(modmath.IsPrime(p) for p in pr1)


def test_MersennePrimesGenerator() -> None:
  """Test."""
  mersenne: list[int] = []
  for i, n in enumerate(modmath.MersennePrimesGenerator(0)):
    mersenne.append(n[0])
    if i > 12:
      break
  assert mersenne == modmath.FIRST_49_MERSENNE_SORTED[:14]


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
