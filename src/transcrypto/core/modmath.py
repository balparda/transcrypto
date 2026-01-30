# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto modular math library."""

from __future__ import annotations

import concurrent.futures
import math
import multiprocessing
import os
from collections import abc

import gmpy2

from transcrypto.core import constants
from transcrypto.utils import base, saferandom

_MAX_PRIMALITY_SAFETY = 100  # this is an absurd number, just to have a max


class ModularDivideError(base.Error):
  """Divide-by-zero-like exception (TransCrypto)."""


def GCD(a: int, b: int, /) -> int:
  """Greatest Common Divisor for `a` and `b`, integers ≥0. Uses the Euclid method.

  O(log(min(a, b)))

  Args:
    a (int): integer a ≥ 0
    b (int): integer b ≥ 0 (can't be both zero)

  Returns:
    gcd(a, b)

  Raises:
    base.InputError: invalid inputs

  """
  # test inputs
  if a < 0 or b < 0 or (not a and not b):
    raise base.InputError(f'negative input or undefined gcd(0, 0): {a=} , {b=}')
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
    base.InputError: invalid inputs

  """
  # test inputs
  if a < 0 or b < 0 or (not a and not b):
    raise base.InputError(f'negative input or undefined gcd(0, 0): {a=} , {b=}')
  # algo needs to start with a >= b (but we remember if we did swap)
  swapped = False
  if a < b:
    a, b = b, a
    swapped = True
  # trivial case
  if not b:
    return (a, 0 if swapped else 1, 1 if swapped else 0)
  # euclid
  x1: int = 0
  x2: int = 1
  y1: int = 1
  y2: int = 0
  q: int
  r: int
  x: int
  y: int
  while b:
    q, r = divmod(a, b)
    x, y = x2 - q * x1, y2 - q * y1
    a, b, x1, x2, y1, y2 = b, r, x, x1, y, y1
  return (a, y2 if swapped else x2, x2 if swapped else y2)


def ModInv(x: int, m: int, /) -> int:
  """Modular inverse of `x` mod `m`: a `y` such that (x * y) % m == 1 if GCD(x, m) == 1.

  Args:
    x (int): integer to invert
    m (int): modulus, m ≥ 2

  Returns:
    positive integer `y` such that (x * y) % m == 1
    this only exists if GCD(x, m) == 1, so to guarantee an inverse `m` must be prime

  Raises:
    base.InputError: invalid modulus or x
    ModularDivideError: divide-by-zero, i.e., GCD(x, m) != 1 or x == 0

  """
  # test inputs
  if m < 2:  # noqa: PLR2004
    raise base.InputError(f'invalid modulus: {m=}')
  # easy special cases: 0 and 1
  reduced_x: int = x % m
  if not reduced_x:  # "division by 0"
    raise ModularDivideError(f'null inverse {x=} mod {m=}')
  if reduced_x == 1:  # trivial degenerate case
    return 1
  # compute actual extended GCD and see if we will have an inverse
  gcd, y, w = ExtendedGCD(reduced_x, m)
  if gcd != 1:
    raise ModularDivideError(f'invalid inverse {x=} mod {m=} with {gcd=}')
  assert y and w and y >= -m, f'should never happen: {x=} mod {m=} -> {w=} ; {y=}'  # noqa: PT018, S101
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
    base.InputError: invalid modulus or x or y
    ModularDivideError: divide-by-zero, i.e., GCD(y, m) != 1 or y == 0

  """
  # test inputs
  if m < 2:  # noqa: PLR2004
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
    base.InputError: invalid inputs
    ModularDivideError: moduli are not co-prime, i.e. gcd(m1, m2) != 1

  """
  # test inputs
  if m1 < 2 or m2 < 2 or m1 == m2:  # noqa: PLR2004
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
    base.InputError: invalid inputs

  """
  # test inputs
  if m < 2:  # noqa: PLR2004
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
  odd: int
  while y:
    y, odd = divmod(y, 2)
    if odd:
      z = (z * x) % m
    x = (x * x) % m
  return z


def ModPolynomial(x: int, polynomial: abc.Reversible[int], m: int, /) -> int:
  """Evaluate `polynomial` (coefficients iterable) at `x` modulus `m`.

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
    base.InputError: invalid inputs

  """
  # test inputs
  if not polynomial:
    raise base.InputError(f'no polynomial: {polynomial=}')
  if m < 2:  # noqa: PLR2004
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
    base.InputError: invalid inputs

  """
  # test inputs
  if m < 2:  # noqa: PLR2004
    raise base.InputError(f'invalid modulus: {m=}')
  x %= m  # takes care of negative numbers and also x >= m
  reduced_points: dict[int, int] = {k % m: v % m for k, v in points.items()}
  if len(points) < 2 or len(reduced_points) != len(points) or x in reduced_points:  # noqa: PLR2004
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


def FermatIsPrime(n: int, /, *, safety: int = 10, witnesses: set[int] | None = None) -> bool:
  """Primality test of `n` by Fermat's algo (n > 0) (UNRELIABLE!! -> use IsPrime()).

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
    base.InputError: invalid inputs

  """
  # test inputs and test for trivial cases: 1, 2, 3, divisible by 2
  if n < 1:
    raise base.InputError(f'invalid number: {n=}')
  if n in {2, 3}:
    return True
  if n == 1 or not n % 2:
    return False
  # n is odd and >= 5 so now we generate witnesses (if needed)
  # degenerate case is: n==5, max_safety==2 => randint(2, 3) => {2, 3}
  if not witnesses:
    max_safety: int = min(n // 2, _MAX_PRIMALITY_SAFETY)
    if safety < 1:
      raise base.InputError(f'out of bounds safety: 1 <= {safety=} <= {max_safety}')
    safety = min(safety, max_safety)
    witnesses = set()
    while len(witnesses) < safety:
      witnesses.add(saferandom.RandInt(2, n - 2))
  # we have our witnesses: do the actual Fermat algo
  for w in sorted(witnesses):
    if not 2 <= w <= (n - 2):  # noqa: PLR2004
      raise base.InputError(f'out of bounds witness: 2 ≤ {w=} ≤ {n - 2}')
    if gmpy2.powmod(w, n - 1, n) != 1:
      # number is proved to be composite
      return False
  # we declare the number PROBABLY a prime to the limits of this test
  return True


def _MillerRabinWitnesses(n: int, /) -> set[int]:  # noqa: PLR0911
  """Generate a reasonable set of Miller-Rabin witnesses for testing primality of `n`.

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
    base.InputError: invalid inputs

  """
  # test inputs
  if n < 5:  # noqa: PLR2004
    raise base.InputError(f'invalid number: {n=}')
  # for some "smaller" values there is research that shows these sets are always enough
  if n < 2047:  # noqa: PLR2004
    return {2}  # "safety" 1, but 100% coverage
  if n < 9080191:  # noqa: PLR2004
    return {31, 73}  # "safety" 2, but 100% coverage
  if n < 4759123141:  # noqa: PLR2004
    return {2, 7, 61}  # "safety" 3, but 100% coverage
  if n < 2152302898747:  # noqa: PLR2004
    return set(constants.FIRST_5K_PRIMES_SORTED[:5])  # "safety" 5, but 100% coverage
  if n < 341550071728321:  # noqa: PLR2004
    return set(constants.FIRST_5K_PRIMES_SORTED[:7])  # "safety" 7, but 100% coverage
  if n < 18446744073709551616:  # 2 ** 64 # noqa: PLR2004
    return set(constants.FIRST_5K_PRIMES_SORTED[:12])  # "safety" 12, but 100% coverage
  if n < 3317044064679887385961981:  # > 2 ** 81 # noqa: PLR2004
    return set(constants.FIRST_5K_PRIMES_SORTED[:13])  # "safety" 13, but 100% coverage
  # here n should be greater than 2 ** 81, so safety should be 34 or less
  n_bits: int = n.bit_length()
  assert n_bits >= 82, f'should never happen: {n=} -> {n_bits=}'  # noqa: PLR2004, S101
  safety: int = max(2, math.ceil(0.375 + 1.59 / (0.000590 * n_bits))) if n_bits <= 1700 else 2  # noqa: PLR2004
  assert 1 < safety <= 34, f'should never happen: {n=} -> {n_bits=} ; {safety=}'  # noqa: PLR2004, S101
  return set(constants.FIRST_5K_PRIMES_SORTED[:safety])


def _MillerRabinSR(n: int, /) -> tuple[int, int]:
  """Generate (s, r) where (2 ** s) * r == (n - 1) hold true, for odd n > 5.

  It should be always true that: s ≥ 1 and r ≥ 1 and r is odd.

  Args:
    n (int): odd number, n ≥ 5

  Returns:
    (s, r) so that (2 ** s) * r == (n - 1)

  Raises:
    base.InputError: invalid inputs

  """
  # test inputs
  if n < 5 or not n % 2:  # noqa: PLR2004
    raise base.InputError(f'invalid odd number: {n=}')
  # divide by 2 until we can't anymore
  s: int = 1
  r: int = (n - 1) // 2
  while not r % 2:
    s += 1
    r //= 2
  # make sure everything checks out and return
  assert 1 <= r <= n and r % 2, f'should never happen: {n=} -> {r=}'  # noqa: PT018, S101
  return (s, r)


def MillerRabinIsPrime(n: int, /, *, witnesses: set[int] | None = None) -> bool:
  """Primality test of `n` by Miller-Rabin's algo (n > 0).

  Will execute Miller-Rabin's algo for non-trivial `n` (n > 3 and odd).
  <https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test>

  Args:
    n (int): Number to test primality, n ≥ 1
    witnesses (set[int], optional): If given will use exactly these witnesses, in order

  Returns:
    False if certainly not prime ; True if (probabilistically) prime

  Raises:
    base.InputError: invalid inputs

  """
  # test inputs and test for trivial cases: 1, 2, 3, divisible by 2
  if n < 1:
    raise base.InputError(f'invalid number: {n=}')
  if n in {2, 3}:
    return True
  if n == 1 or not n % 2:
    return False
  # n is odd and >= 5; find s and r so that (2 ** s) * r == (n - 1)
  s, r = _MillerRabinSR(n)
  # do the Miller-Rabin algo
  n_limits: tuple[int, int] = (1, n - 1)
  y: int
  for w in sorted(witnesses or _MillerRabinWitnesses(n)):
    if not 2 <= w <= (n - 2):  # noqa: PLR2004
      raise base.InputError(f'out of bounds witness: 2 ≤ {w=} ≤ {n - 2}')
    x: int = int(gmpy2.powmod(w, r, n))
    if x not in n_limits:
      for _ in range(s):  # s >= 1 so will execute at least once
        y = (x * x) % n
        if y == 1 and x not in n_limits:
          return False  # number is proved to be composite
        x = y
      if x != 1:
        return False  # number is proved to be composite
  # we declare the number PROBABLY a prime to the limits of this test
  return True


def IsPrime(n: int, /) -> bool:
  """Primality test of `n` (n > 0).

  Args:
    n (int): Number to test primality, n ≥ 1

  Returns:
    False if certainly not prime ; True if (probabilistically) prime

  """
  # is number divisible by (one of the) first 20000 primes? test should eliminate 90%+ of candidates
  if n in constants.FIRST_20K_PRIMES:
    return True
  for r in constants.FIRST_20K_PRIMES_SORTED:
    if not n % r:
      return False  # we already checked: it is not one of the 20k first primes, so not prime
  # do the (much much more expensive) Miller-Rabin primality test
  return MillerRabinIsPrime(n)


def PrimeGenerator(start: int, /) -> abc.Generator[int]:
  """Generate all primes from `start` until loop is broken. Tuned for huge numbers.

  Args:
    start (int): number at which to start generating primes, start ≥ 0

  Yields:
    prime numbers (int)

  Raises:
    base.InputError: invalid inputs

  """
  # test inputs and make sure we start at an odd number
  if start < 0:
    raise base.InputError(f'negative number: {start=}')
  # handle start of sequence manually if needed... because we have here the only EVEN prime...
  if start <= 2:  # noqa: PLR2004
    yield 2
    start = 3
  # we now focus on odd numbers only and loop forever
  n: int = (start if start % 2 else start + 1) - 2  # n >= 1 always
  while True:
    n += 2  # next odd number
    if IsPrime(n):
      yield n  # found a prime


def NBitRandomPrimes(n_bits: int, /, *, serial: bool = True, n_primes: int = 1) -> set[int]:
  """Generate a random prime with (guaranteed) `n_bits` size (i.e., first bit == 1).

  The fact that the first bit will be 1 means the entropy is ~ (n_bits-1) and
  because of this we only allow for a byte or more prime bits generated. This drawback
  is negligible for the large primes a crypto library will work with, in practice.

  Method will decide if executes on one thread or many.

  $ poetry run profiler -s -n 100 -b 1000,11000,1000 -c 98 primes  # single-thread, Mac M2 Max, 2025
  1000 → 84.233 ms ± 18.853 ms [65.380 ms … 103.085 ms]98%CI@100
  2000 → 406.900 ms ± 91.575 ms [315.325 ms … 498.475 ms]98%CI@100
  3000 → 1.20 s ± 291.105 ms [907.331 ms … 1.49 s]98%CI@100
  4000 → 2.42 s ± 490.241 ms [1.93 s … 2.91 s]98%CI@100
  5000 → 4.78 s ± 1.02 s [3.76 s … 5.80 s]98%CI@100
  6000 → 7.63 s ± 1.57 s [6.06 s … 9.20 s]98%CI@100
  7000 → 13.66 s ± 3.00 s [10.66 s … 16.66 s]98%CI@100
  8000 → 20.71 s ± 5.05 s [15.67 s … 25.76 s]98%CI@100
  9000 → 33.12 s ± 7.61 s [25.51 s … 40.73 s]98%CI@100
  10000 → 52.91 s ± 11.73 s [41.18 s … 1.08 min]98%CI@100

  Rule of thumb: double the bits requires ~10x execution time

  Args:
    n_bits (int): Number of guaranteed bits in prime representation, n ≥ 8
    serial (bool, optional): True (default) will force one thread; False will allow parallelism;
       we have temporarily disabled parallelism with a default of True because it is not making
       things faster...
    n_primes (int, optional): Number of required primes in the return set[int], default is 1

  Returns:
    set[int]: `n_primes` random primes with `n_bits` bits

  Raises:
    base.InputError: invalid inputs
    base.Error: prime search failed

  """
  # test inputs
  if n_bits < 8:  # noqa: PLR2004
    raise base.InputError(f'invalid n: {n_bits=}')
  n_primes = max(n_primes, 1)
  # get number of CPUs and decide if we do parallel or not
  n_workers: int = min(4, os.cpu_count() or 1)
  pr_set: set[int] = set()
  pr: int | None = None
  if serial or n_workers <= 1 or n_bits < 200:  # noqa: PLR2004
    # do one worker
    while len(pr_set) < n_primes:
      while pr is None or pr.bit_length() != n_bits:
        pr = _PrimeSearchShard(n_bits)
      pr_set.add(pr)
      pr = None
    return pr_set
  # parallel: keep a small pool of bounded shards; stop on first hit
  multiprocessing.set_start_method('fork', force=True)
  with concurrent.futures.ProcessPoolExecutor(max_workers=n_workers) as pool:
    workers: set[concurrent.futures.Future[int | None]] = {
      pool.submit(_PrimeSearchShard, n_bits) for _ in range(n_workers)
    }
    while workers:
      done: set[concurrent.futures.Future[int | None]] = concurrent.futures.wait(
        workers, return_when=concurrent.futures.FIRST_COMPLETED
      )[0]
      for worker in done:
        workers.remove(worker)
        pr = worker.result()
        if pr is not None and pr.bit_length() == n_bits:
          pr_set.add(pr)
          pr = None
          if len(pr_set) >= n_primes:
            return pr_set
        # no hit in that shard: keep the pool full with a fresh shard
        workers.add(pool.submit(_PrimeSearchShard, n_bits))
  # can never reach this point, but leave this here; remove line from coverage
  raise base.Error(f'could not find prime with {n_bits=} bits')  # pragma: no cover


def _PrimeSearchShard(n_bits: int) -> int | None:
  """Search for a `n_bits` random prime, starting from a random point, for ~6x expected prime gap.

  Args:
    n_bits (int): Number of guaranteed bits in prime representation

  Returns:
    int | None: either the prime int or None if no prime found in this shard

  """
  shard_len: int = max(2000, 6 * int(0.693 * n_bits))  # ~6x expected prime gap ~2^k (≈ 0.693*k)
  pr: int = saferandom.RandBits(n_bits) | 1  # random position; make ODD
  count: int = 0
  while count < shard_len and pr.bit_length() == n_bits:
    if IsPrime(pr):
      return pr
    count += 1
    pr += 2
  return None


def FirstNPrimesSorted(n: int) -> abc.Generator[int]:
  """Return list of `n` first primes in a sorted list.

  Args:
      n (int): number of primes to return

  Yields:
      Generator[int]: primes

  """
  for i, pr in enumerate(PrimeGenerator(0)):
    if i >= n:
      return
    yield pr


def MersennePrimesGenerator(start: int, /) -> abc.Generator[tuple[int, int, int]]:
  """Generate all Mersenne prime (2 ** n - 1) exponents from start until loop is broken.

  <https://en.wikipedia.org/wiki/List_of_Mersenne_primes_and_perfect_numbers>

  Args:
    start (int): exponent at which to start generating primes, start ≥ 0

  Yields:
    (exponent, mersenne_prime, perfect_number), given some exponent `n` that will be exactly:
    (n, 2 ** n - 1, (2 ** (n - 1)) * (2 ** n - 1))

  """
  # we now loop forever over prime exponents
  # "The exponents p corresponding to Mersenne primes must themselves be prime."
  for n in PrimeGenerator(max(start, 1)):
    mersenne: int = 2**n - 1
    if IsPrime(mersenne):
      yield (n, mersenne, (2 ** (n - 1)) * mersenne)  # found: also yield perfect number
