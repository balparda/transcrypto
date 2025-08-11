#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto modular math library."""

import math
# import pdb
from typing import Generator, Optional, Reversible

from . import base

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


_FIRST_60_PRIMES: set[int] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
}
_FIRST_60_PRIMES_SORTED: list[int] = sorted(_FIRST_60_PRIMES)
_COMPOSITE_60: int = math.prod(_FIRST_60_PRIMES_SORTED)
_PRIME_60: int = _FIRST_60_PRIMES_SORTED[-1]
assert len(_FIRST_60_PRIMES) == 60 and _PRIME_60 == 281, f'should never happen: {_PRIME_60=}'
_FIRST_49_MERSENNE: set[int] = {  # <https://oeis.org/A000043>
    2, 3, 5, 7, 13, 17, 19, 31, 61, 89,
    107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
    9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049,
    216091, 756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011,
    24036583, 25964951, 30402457, 32582657, 37156667, 42643801, 43112609, 57885161, 74207281,
}
_FIRST_49_MERSENNE_SORTED: list[int] = sorted(_FIRST_49_MERSENNE)
assert len(_FIRST_49_MERSENNE) == 49 and _FIRST_49_MERSENNE_SORTED[-1] == 74207281, f'should never happen: {_FIRST_49_MERSENNE_SORTED[-1]}'

_MAX_PRIMALITY_SAFETY = 100  # this is an absurd number, just to have a max


class ModularDivideError(base.Error):
  """Divide-by-zero-like exception (TransCrypto)."""


def ModInv(x: int, m: int, /) -> int:
  """Modular inverse of `x` mod `m`: a `y` such that (x * y) % m == 1 if GCD(x, m) == 1.

  Args:
    x (int): integer to invert
    m (int): modulus, m ≥ 2

  Returns:
    positive integer `y` such that (x * y) % m == 1
    this only exists if GCD(x, m) == 1, so to guarantee an inverse `m` must be prime

  Raises:
    InputError: invalid modulus or x
    ModularDivideError: divide-by-zero, i.e., GCD(x, m) != 1 or x == 0
  """
  # test inputs
  if m < 2:
    raise base.InputError(f'invalid modulus: {m=}')
  # easy special cases: 0 and 1
  reduced_x: int = x % m
  if not reduced_x:  # "division by 0"
    raise ModularDivideError(f'null inverse {x=} mod {m=}')
  if reduced_x == 1:  # trivial degenerate case
    return 1
  # compute actual extended GCD and see if we will have an inverse
  gcd, y, w = base.ExtendedGCD(reduced_x, m)
  if gcd != 1:
    raise ModularDivideError(f'invalid inverse {x=} mod {m=} with {gcd=}')
  assert y and w and y >= -m, f'should never happen: {x=} mod {m=} -> {w=} ; {y=}'
  return y if y >= 0 else (y + m)


def ModDiv(x: int, y: int, m: int, /) -> int:
  """Modular division of `x`/`y` mod `m`, if GCD(y, m) == 1.

  Args:
    x (int): integer
    y (int): integer
    m (int): modulus, m ≥ 2

  Returns:
    positive integer `z` such that (z * y) % m == x
    this only exists if GCD(y, m) == 1, so to guarantee an inverse `m` must be prime

  Raises:
    InputError: invalid modulus or x or y
    ModularDivideError: divide-by-zero, i.e., GCD(y, m) != 1 or y == 0
  """
  # test inputs
  if m < 2:
    raise base.InputError(f'invalid modulus: {m=}')
  if not y:  # "division by 0"
    raise ModularDivideError(f'divide by zero {x=} / {y=} mod {m=}')
  # do the math
  if not x:
    return 0
  return ((x % m) * ModInv(y % m, m)) % m


def CRTPair(a1: int, m1: int, a2: int, m2: int) -> int:
  """Chinese Remainder Theorem Pair: given co-prime `m1`/`m2`, solve a1 = x % m1 and a2 = x % m2.

  <https://en.wikipedia.org/wiki/Chinese_remainder_theorem>

  Finds the unique integer x in [0, m1 * m2) satisfying

      x ≡ a1 (mod m1)
      x ≡ a2 (mod m2)

  The solution is guaranteed to exist and be unique because the moduli are assumed to
  be positive, ≥ 2, and pairwise co-prime, gcd(m1, m2) == 1.

  Args:
    a1 (int): residue for the first congruence
    m1 (int): modulus 1, m ≥ 2 and co-prime with m2, i.e. gcd(m1, m2) == 1
    a2 (int): residue for the second congruence
    m2 (int): modulus 2, m ≥ 2 and co-prime with m1, i.e. gcd(m1, m2) == 1

  Returns:
    the least non-negative solution `x` such that a1 = x % m1 and a2 = x % m2 and 0 ≤ x < m1 * m2

  Raises:
    InputError: invalid inputs
    ModularDivideError: moduli are not co-prime, i.e. gcd(m1, m2) != 1
  """
  # test inputs
  if m1 < 2 or m2 < 2 or m1 == m2:
    raise base.InputError(f'invalid moduli: {m1=} / {m2=}')
  # compute
  a1 %= m1
  a2 %= m2
  try:
    n1: int = ModInv(m1, m2)
    n2: int = ModInv(m2, m1)
  except ModularDivideError as err:
    raise ModularDivideError(f'moduli not co-prime: {m1=} / {m2=}') from err
  return (a1 * m2 * n2 + a2 * m1 * n1) % (m1 * m2)


def ModExp(x: int, y: int, m: int, /) -> int:
  """Modular exponential: returns (x ** y) % m efficiently (can handle huge values).

  0 ** 0 mod m = 1 (by convention)

  Args:
    x (int): integer
    y (int): integer, y ≥ 0
    m (int): modulus, m ≥ 2

  Returns:
    (x ** y) mod m

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if m < 2:
    raise base.InputError(f'invalid modulus: {m=}')
  if y < 0:
    raise base.InputError(f'negative exponent: {y=}')
  # trivial cases
  x %= m
  if not y or x == 1:
    return 1 % m
  if not x:
    return 0  # 0**0==1 was already taken care of by previous condition
  if y == 1:
    return x
  # now both x > 1 and y > 1
  z: int = 1
  while y:
    y, odd = divmod(y, 2)
    if odd:
      z = (z * x) % m
    x = (x * x) % m
  return z


def ModPolynomial(x: int, polynomial: Reversible[int], m: int, /) -> int:
  """Evaluates polynomial `poly` (coefficient iterable) at `x` modulus `m`.

  Evaluate a polynomial at `x` under a modulus `m` using Horner's rule. Horner rewrites:
      a_0 + a_1 x + a_2 x^2 + … + a_n x^n
    = (…((a_n x + a_{n-1}) x + a_{n-2}) … ) x + a_0
  This uses exactly n multiplies and n adds, and lets us take `% m` at each
  step so intermediate numbers never explode.

  Args:
    x (int): The evaluation point
    polynomial (Reversible[int]): Iterable of coefficients a_0, a_1, …, a_n
        (constant term first); it must be reversible because Horner's rule consumes
        coefficients from highest degree downwards
    m (int): modulus, m ≥ 2; if you expect multiplicative inverses elsewhere it should be prime

  Returns:
    f(x) mod m

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if not polynomial:
    raise base.InputError(f'no polynomial: {polynomial=}')
  if m < 2:
    raise base.InputError(f'invalid modulus: {m=}')
  # loop over polynomial coefficients
  total: int = 0
  x %= m  # takes care of negative numbers and also x >= m
  for coefficient in reversed(polynomial):
    total = (total * x + coefficient) % m
  return total


def ModLagrangeInterpolate(x: int, points: dict[int, int], m: int, /) -> int:
  """Find the f(x) solution for the given `x` and {x: y} `points` modulus prime `m`.

  Given `points` will define a polynomial of up to len(points) order.
  Evaluate (interpolate) the unique polynomial of degree ≤ (n-1) that passes
  through the given points (x_i, y_i), and return f(x) mod a prime `m`.

  Lagrange interpolation writes the polynomial as:
      f(X) = Σ_{i=0}^{n-1} y_i * L_i(X)
  where
      L_i(X) = Π_{j≠i} (X - x_j) / (x_i - x_j)
  are the Lagrange basis polynomials. Each L_i(x_i) = 1 and L_i(x_j)=0 for j≠i,
  so f matches every supplied point.

  In modular arithmetic we replace division by multiplication with modular
  inverses. Because `m` is prime (or at least co-prime with every denominator),
  every (x_i - x_j) has an inverse `mod m`.

  Args:
    x (int): The x-value at which to evaluate the interpolated polynomial
    points (dict[int, int]): A mapping {x_i: y_i}, with at least 2 points/entries;
        dict keeps x_i distinct, as they should be; also, `x` cannot be a key to `points`
    m (int): prime modulus, m ≥ 2; we need modular inverses, so gcd(denominator, m) must be 1

  Returns:
    y-value solution for f(x) mod m given `points` mapping

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if m < 2:
    raise base.InputError(f'invalid modulus: {m=}')
  x %= m  # takes care of negative numbers and also x >= m
  reduced_points: dict[int, int] = {k % m: v % m for k, v in points.items()}
  if len(points) < 2 or len(reduced_points) != len(points) or x in reduced_points:
    raise base.InputError(f'invalid points or duplicate x/x_i found: {x=} / {points=}')
  # compute everything term-by-term
  result: int = 0
  for xi, yi in reduced_points.items():
    # build numerator and denominator of L_i(x)
    num: int = 1  # Π (x - x_j)
    den: int = 1  # Π (xi - x_j)
    for xj in reduced_points:
      if xj == xi:
        continue
      num = (num * (x - xj)) % m
      den = (den * (xi - xj)) % m
    # add to  the result: (y_i * L_i(x)) = (y_i * num / den)
    result = (result + ModDiv(yi * num, den, m)) % m
  # done
  return result


def FermatIsPrime(
    n: int, /, *,
    safety: int = 10,
    witnesses: Optional[set[int]] = None) -> bool:
  """Primality test of `n` by Fermat's algo (n > 0). DO NOT RELY!

  Will execute Fermat's algo for non-trivial `n` (n > 3 and odd).
  <https://en.wikipedia.org/wiki/Fermat_primality_test>

  This is for didactical uses only, as it is reasonably easy for this algo to fail
  on simple cases. For example, 8911 will fail for many sets of 10 random witnesses.
  (See <https://en.wikipedia.org/wiki/Carmichael_number> to understand better.)
  Miller-Rabin below (MillerRabinIsPrime) has been tuned to be VERY reliable by default.

  Args:
    n (int): Number to test primality
    safety (int, optional): Maximum witnesses to use (only if witnesses is not given)
    witnesses (set[int], optional): If given will use exactly these witnesses, in order

  Returns:
    False if certainly not prime ; True if (probabilistically) prime

  Raises:
    InputError: invalid inputs
  """
  # test inputs and test for trivial cases: 1, 2, 3, divisible by 2
  if n < 1:
    raise base.InputError(f'invalid number: {n=}')
  if n in (2, 3):
    return True
  if n == 1 or not n % 2:
    return False
  # n is odd and >= 5 so now we generate witnesses (if needed)
  # degenerate case is: n==5, max_safety==2 => randint(2, 3) => {2, 3}
  if not witnesses:
    max_safety: int = min(n // 2, _MAX_PRIMALITY_SAFETY)
    if safety < 1:
      raise base.InputError(f'out of bounds safety: 1 <= {safety=} <= {max_safety}')
    safety = max_safety if safety > max_safety else safety
    witnesses = set()
    while len(witnesses) < safety:
      witnesses.add(base.RandInt(2, n - 2))
  # we have our witnesses: do the actual Fermat algo
  for w in sorted(witnesses):
    if not 2 <= w <= (n - 2):
      raise base.InputError(f'out of bounds witness: 2 <= {w=} <= {n - 2}')
    if ModExp(w, n - 1, n) != 1:
      # number is proved to be composite
      return False
  # we declare the number PROBABLY a prime to the limits of this test
  return True


def _MillerRabinWitnesses(n: int, /) -> set[int]:  # pylint: disable=too-many-return-statements
  """Generates a reasonable set of Miller-Rabin witnesses for testing primality of `n`.

  For n < 3317044064679887385961981 it is precise. That is more than 2**81. See:
  <https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Testing_against_small_sets_of_bases>

  For n >= 3317044064679887385961981 it is probabilistic, but computes an number of witnesses
  that should make the test fail less than once in 2**80 tries (once in 10^25). For all intent and
  purposes it "never" fails.

  Args:
    n (int): number, n ≥ 5

  Returns:
    {witness1, witness2, ...} for either "certainty" of primality or error chance < 10**25

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if n < 5:
    raise base.InputError(f'invalid number: {n=}')
  # for some "smaller" values there is research that shows these sets are always enough
  if n < 2047:
    return {2}                               # "safety" 1, but 100% coverage
  if n < 9080191:
    return {31, 73}                          # "safety" 2, but 100% coverage
  if n < 4759123141:
    return {2, 7, 61}                        # "safety" 3, but 100% coverage
  if n < 2152302898747:
    return set(_FIRST_60_PRIMES_SORTED[:5])   # "safety" 5, but 100% coverage
  if n < 341550071728321:
    return set(_FIRST_60_PRIMES_SORTED[:7])   # "safety" 7, but 100% coverage
  if n < 18446744073709551616:               # 2 ** 64
    return set(_FIRST_60_PRIMES_SORTED[:12])  # "safety" 12, but 100% coverage
  if n < 3317044064679887385961981:          # > 2 ** 81
    return set(_FIRST_60_PRIMES_SORTED[:13])  # "safety" 13, but 100% coverage
  # here n should be greater than 2 ** 81, so safety should be 34 or less
  n_bits: int = n.bit_length()
  assert n_bits >= 82, f'should never happen: {n=} -> {n_bits=}'
  safety: int = int(math.ceil(0.375 + 1.59 / (0.000590 * n_bits))) if n_bits <= 1700 else 2
  assert 1 < safety <= 34, f'should never happen: {n=} -> {n_bits=} ; {safety=}'
  return set(_FIRST_60_PRIMES_SORTED[:safety])


def _MillerRabinSR(n: int, /) -> tuple[int, int]:
  """Generates (s, r) where (2 ** s) * r == (n - 1) hold true, for odd n > 5.

  It should be always true that: s >= 1 and r >= 1 and r is odd.

  Args:
    n (int): odd number, n ≥ 5

  Returns:
    (s, r) so that (2 ** s) * r == (n - 1)

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if n < 5 or not n % 2:
    raise base.InputError(f'invalid odd number: {n=}')
  # divide by 2 until we can't anymore
  s: int = 1
  r: int = (n - 1) // 2
  while not r % 2:
    s += 1
    r //= 2
  # make sure everything checks out and return
  assert 1 <= r <= n and r % 2, f'should never happen: {n=} -> {r=}'
  return (s, r)


def MillerRabinIsPrime(
    n: int, /, *,
    witnesses: Optional[set[int]] = None) -> bool:
  """Primality test of `n` by Miller-Rabin's algo (n > 0).

  Will execute Miller-Rabin's algo for non-trivial `n` (n > 3 and odd).
  <https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test>

  Args:
    n (int): Number to test primality, n ≥ 1
    witnesses (set[int], optional): If given will use exactly these witnesses, in order

  Returns:
    False if certainly not prime ; True if (probabilistically) prime

  Raises:
    InputError: invalid inputs
  """
  # test inputs and test for trivial cases: 1, 2, 3, divisible by 2
  if n < 1:
    raise base.InputError(f'invalid number: {n=}')
  if n in (2, 3):
    return True
  if n == 1 or not n % 2:
    return False
  # n is odd and >= 5; find s and r so that (2 ** s) * r == (n - 1)
  s, r = _MillerRabinSR(n)
  # do the Miller-Rabin algo
  n_limits: tuple[int, int] = (1, n - 1)
  y: int
  for w in sorted(witnesses if witnesses else _MillerRabinWitnesses(n)):
    if not 2 <= w <= (n - 2):
      raise base.InputError(f'out of bounds witness: 2 <= {w=} <= {n - 2}')
    x: int = ModExp(w, r, n)
    if x not in n_limits:
      for _ in range(s):  # s >= 1 so will execute at least once
        y = (x * x) % n
        if y == 1 and x not in n_limits:
          return False  # number is proved to be composite
        x = y
      if x != 1:
        return False    # number is proved to be composite
  # we declare the number PROBABLY a prime to the limits of this test
  return True


def IsPrime(n: int, /) -> bool:
  """Primality test of `n` (n > 0).

  Args:
    n (int): Number to test primality, n ≥ 1

  Returns:
    False if certainly not prime ; True if (probabilistically) prime

  Raises:
    InputError: invalid inputs
  """
  # is number divisible by (one of the) first 60 primes? test should eliminate 80%+ of candidates
  if n > _PRIME_60 and base.GCD(n, _COMPOSITE_60) != 1:
    return False
  # do the (more expensive) Miller-Rabin primality test
  return MillerRabinIsPrime(n)


def PrimeGenerator(start: int, /) -> Generator[int, None, None]:
  """Generates all primes from `start` until loop is broken. Tuned for huge numbers.

  Args:
    start (int): number at which to start generating primes, start ≥ 0

  Yields:
    prime numbers (int)

  Raises:
    InputError: invalid inputs
  """
  # test inputs and make sure we start at an odd number
  if start < 0:
    raise base.InputError(f'negative number: {start=}')
  # handle start of sequence manually if needed... because we have here the only EVEN prime...
  if start <= 2:
    yield 2
    start = 3
  # we now focus on odd numbers only and loop forever
  n: int = (start if start % 2 else start + 1) - 2  # n >= 1 always
  while True:
    n += 2  # next odd number
    if IsPrime(n):
      yield n  # found a prime


def NBitRandomPrime(n_bits: int, /) -> int:
  """Generates a random prime with (guaranteed) `n_bits` binary representation length.

  Args:
    n_bits (int): Number of guaranteed bits in prime representation, n ≥ 4

  Returns:
    random prime with `n_bits` bits

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if n_bits < 4:
    raise base.InputError(f'invalid n: {n_bits=}')
  # get a random number with guaranteed bit size
  min_start: int = 2 ** (n_bits - 1)
  prime: int = 0
  while prime.bit_length() != n_bits:
    start_point: int = base.RandBits(n_bits)
    while start_point < min_start:
      # i know we could just set the bit, but IMO it is better to get another entirely
      start_point = base.RandBits(n_bits)
    prime = next(PrimeGenerator(start_point))
  return prime


def MersennePrimesGenerator(start: int, /) -> Generator[tuple[int, int, int], None, None]:
  """Generates all Mersenne prime (2 ** n - 1) exponents from 2**start until loop is broken.

  <https://en.wikipedia.org/wiki/List_of_Mersenne_primes_and_perfect_numbers>

  Args:
    start (int): exponent at which to start generating primes, start ≥ 0

  Yields:
    (exponent, mersenne_prime, perfect_number), given some exponent `n` that will be exactly:
    (n, 2 ** n - 1, (2 ** (n - 1)) * (2 ** n - 1))

  Raises:
    InputError: invalid inputs
  """
  # we now loop forever over prime exponents
  # "The exponents p corresponding to Mersenne primes must themselves be prime."
  for n in PrimeGenerator(start if start >= 1 else 1):
    mersenne: int = 2 ** n - 1
    if IsPrime(mersenne):
      yield (n, mersenne, (2 ** (n - 1)) * mersenne)  # found: also yield perfect number
