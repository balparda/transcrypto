#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto."""

import math
# import pdb
import random
from typing import Generator, Optional

__author__ = 'balparda@github.com'
__version__: tuple[int, int, int] = (1, 0, 2)  # v1.0.2, 2025-07-22


FIRST_60_PRIMES_SORTED: list[int] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
]
FIRST_60_PRIMES: set[int] = set(FIRST_60_PRIMES_SORTED)
COMPOSITE_60: int = math.prod(FIRST_60_PRIMES_SORTED)
PRIME_60: int = FIRST_60_PRIMES_SORTED[-1]  # 281

_MAX_PRIMALITY_SAFETY = 100  # this is an absurd number, just to have a max


class Error(Exception):
  """TransCrypto exception."""


def GCD(a: int, b: int, /) -> int:
  """Greatest Common Divisor for `a` and `b`, positive integers.

  Uses the Euclid method.
  """
  # test inputs
  if a < 0 or b < 0:
    raise Error(f'negative input: {a=} , {b=}')
  # algo needs to start with a >= b
  if a < b:
    a, b = b, a
  # euclid
  while b:
    r: int = a % b
    a, b = b, r
  return a


def ExtendedGCD(a: int, b: int, /) -> tuple[int, int, int]:
  """Greatest Common Divisor Extended for `a` and `b`, positive integers.

  Uses the Euclid method.

  Returns:
    (gcd, x, y) so that a * x + b * y = gcd
    x and y may be negative integers or zero but won't be both zero.
  """
  # test inputs
  if a < 0 or b < 0:
    raise Error(f'negative input: {a=} , {b=}')
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


def ModExp(x: int, y: int, m: int, /) -> int:
  """Modular exponential: returns (x ** y) % m efficiently (can handle huge values)."""
  # test inputs
  if x < 0 or y < 0:
    raise Error(f'negative input: {x=} , {y=}')
  if m < 1:
    raise Error(f'invalid module: {m=}')
  # trivial cases
  if not x:
    return 0
  if not y or x == 1:
    return 1 % m
  if y == 1:
    return x % m
  # now both x > 1 and y > 1
  z: int = 1
  while y:
    y, odd = divmod(y, 2)
    if odd:
      z = (z * x) % m
    x = (x * x) % m
  return z


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
  """
  # test inputs and test for trivial cases: 1, 2, 3, divisible by 2
  if n < 1:
    raise Error(f'invalid number: {n=}')
  if n in (2, 3):
    return True
  if n == 1 or not n % 2:
    return False
  # n is odd and >= 5 so now we generate witnesses (if needed)
  # degenerate case is: n==5, max_safety==2 => randint(2, 3) => {2, 3}
  if not witnesses:
    max_safety: int = min(n // 2, _MAX_PRIMALITY_SAFETY)
    if safety < 1:
      raise Error(f'out of bounds safety: 1 <= {safety=} <= {max_safety}')
    safety = max_safety if safety > max_safety else safety
    witnesses = set()
    while len(witnesses) < safety:
      witnesses.add(random.randint(2, n - 2))
  # we have our witnesses: do the actual Fermat algo
  for w in sorted(witnesses):
    if not 2 <= w <= (n - 2):
      raise Error(f'out of bounds witness: 2 <= {w=} <= {n - 2}')
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
  """
  # test inputs
  if n < 5:
    raise Error(f'invalid number: {n=}')
  # for some "smaller" values there is research that shows these sets are always enough
  if n < 2047:
    return {2}                               # "safety" 1, but 100% coverage
  if n < 9080191:
    return {31, 73}                          # "safety" 2, but 100% coverage
  if n < 4759123141:
    return {2, 7, 61}                        # "safety" 3, but 100% coverage
  if n < 2152302898747:
    return set(FIRST_60_PRIMES_SORTED[:5])   # "safety" 5, but 100% coverage
  if n < 341550071728321:
    return set(FIRST_60_PRIMES_SORTED[:7])   # "safety" 7, but 100% coverage
  if n < 18446744073709551616:               # 2 ** 64
    return set(FIRST_60_PRIMES_SORTED[:12])  # "safety" 12, but 100% coverage
  if n < 3317044064679887385961981:          # > 2 ** 81
    return set(FIRST_60_PRIMES_SORTED[:13])  # "safety" 13, but 100% coverage
  # here n should be greater than 2 ** 81, so safety should be 34 or less
  n_bits: int = n.bit_length()
  assert n_bits >= 82      # "should never happen"
  safety: int = int(math.ceil(0.375 + 1.59 / (0.000590 * n_bits))) if n_bits <= 1700 else 2
  assert 1 < safety <= 34  # "should never happen"
  return set(FIRST_60_PRIMES_SORTED[:safety])


def _MillerRabinSR(n: int, /) -> tuple[int, int]:
  """Generates (s, r) where (2 ** s) * r == (n - 1) hold true, for odd n > 5.

  It should be always true that: s >= 1 and r >= 1 and r is odd.
  """
  # test inputs
  if n < 5 or not n % 2:
    raise Error(f'invalid odd number: {n=}')
  # divide by 2 until we can't anymore
  s: int = 1
  r: int = (n - 1) // 2
  while not r % 2:
    s += 1
    r //= 2
  # make sure everything checks out and return
  assert 1 <= r <= n and r % 2  # "should never happen"
  return (s, r)


def MillerRabinIsPrime(
    n: int, /, *,
    witnesses: Optional[set[int]] = None) -> bool:
  """Primality test of `n` by Miller-Rabin's algo (n > 0).

  Will execute Miller-Rabin's algo for non-trivial `n` (n > 3 and odd).
  <https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test>

  Args:
    n (int): Number to test primality
    witnesses (set[int], optional): If given will use exactly these witnesses, in order

  Returns:
    False if certainly not prime ; True if (probabilistically) prime
  """
  # test inputs and test for trivial cases: 1, 2, 3, divisible by 2
  if n < 1:
    raise Error(f'invalid number: {n=}')
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
      raise Error(f'out of bounds witness: 2 <= {w=} <= {n - 2}')
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


def PrimeGenerator(start: int) -> Generator[int, None, None]:
  """Generates all primes from `start` until loop is broken. Tuned for huge numbers."""
  # test inputs and make sure we start at an odd number
  if start < 0:
    raise Error(f'invalid number: {start=}')
  # handle start of sequence manually if needed... because we have here the only EVEN prime...
  if start <= 2:
    yield 2
    start = 3
  # we now focus on odd numbers only and loop forever
  n: int = (start if start % 2 else start + 1) - 2  # n >= 1 always
  while True:
    n += 2  # next odd number
    # is number divisible by (one of the) first 60 primes? test should eliminate 80%+ of candidates
    if n > PRIME_60 and GCD(n, COMPOSITE_60) != 1:
      continue  # not prime
    # do the (more expensive) primality test
    if MillerRabinIsPrime(n):
      yield n  # found a prime


def MersennePrimesGenerator(start: int) -> Generator[tuple[int, int, int], None, None]:
  """Generates all Mersenne prime (2 ** n - 1) exponents from 2**start until loop is broken.

  <https://en.wikipedia.org/wiki/List_of_Mersenne_primes_and_perfect_numbers>

  Yields:
    (exponent, mersenne_prime, perfect_number), given some exponent `n` that will be exactly:
    (n, 2 ** n - 1, (2 ** (n - 1)) * (2 ** n - 1))
  """
  # we now loop forever over prime exponents
  # "The exponents p corresponding to Mersenne primes must themselves be prime."
  for n in PrimeGenerator(start if start >= 1 else 1):
    mersenne: int = 2 ** n - 1
    # is number divisible by (one of the) first 60 primes? test should eliminate 80%+ of candidates
    if mersenne > PRIME_60 and GCD(mersenne, COMPOSITE_60) != 1:
      continue  # not prime
    # do the (more expensive) primality test
    if MillerRabinIsPrime(mersenne):
      # found a prime, yield it plus the perfect number associated with it
      yield (n, mersenne, (2 ** (n - 1)) * mersenne)
