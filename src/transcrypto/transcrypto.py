#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto."""

import dataclasses
import datetime
import logging
import math
# import pdb
import secrets
from typing import Collection, Generator, Optional, Reversible, Self

__author__ = 'balparda@github.com'
__version__: tuple[int, int, int] = (1, 0, 3)  # v1.0.3, 2025-07-30


FIRST_60_PRIMES: set[int] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
}
FIRST_60_PRIMES_SORTED: list[int] = sorted(FIRST_60_PRIMES)
COMPOSITE_60: int = math.prod(FIRST_60_PRIMES_SORTED)
PRIME_60: int = FIRST_60_PRIMES_SORTED[-1]
assert len(FIRST_60_PRIMES) == 60 and PRIME_60 == 281, f'should never happen: {PRIME_60=}'
FIRST_49_MERSENNE: set[int] = {  # <https://oeis.org/A000043>
    2, 3, 5, 7, 13, 17, 19, 31, 61, 89,
    107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423,
    9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049,
    216091, 756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011,
    24036583, 25964951, 30402457, 32582657, 37156667, 42643801, 43112609, 57885161, 74207281,
}
FIRST_49_MERSENNE_SORTED: list[int] = sorted(FIRST_49_MERSENNE)
assert len(FIRST_49_MERSENNE) == 49 and FIRST_49_MERSENNE_SORTED[-1] == 74207281, f'should never happen: {FIRST_49_MERSENNE_SORTED[-1]}'

_SMALL_ENCRYPTION_EXPONENT = 7
_BIG_ENCRYPTION_EXPONENT = 2 ** 16 + 1  # 65537

_MAX_PRIMALITY_SAFETY = 100  # this is an absurd number, just to have a max
_MAX_KEY_GENERATION_FAILURES = 15

MIN_TM = int(  # minimum allowed timestamp
    datetime.datetime(2000, 1, 1, 0, 0, 0).replace(tzinfo=datetime.timezone.utc).timestamp())


class Error(Exception):
  """TransCrypto exception."""


class InputError(Error):
  """Input exception (TransCrypto)."""


class ModularDivideError(Error):
  """Divide-by-zero-like exception (TransCrypto)."""


class CryptoError(Error):
  """Cryptographic exception (TransCrypto)."""


def GCD(a: int, b: int, /) -> int:
  """Greatest Common Divisor for `a` and `b`, positive integers. Uses the Euclid method.

  Args:
    a (int): integer a ≥ 0
    b (int): integer b ≥ 0

  Returns:
    gcd(a, b)

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if a < 0 or b < 0:
    raise InputError(f'negative input: {a=} , {b=}')
  # algo needs to start with a >= b
  if a < b:
    a, b = b, a
  # euclid
  while b:
    r: int = a % b
    a, b = b, r
  return a


def ExtendedGCD(a: int, b: int, /) -> tuple[int, int, int]:
  """Greatest Common Divisor Extended for `a` and `b`, positive integers. Uses the Euclid method.

  Args:
    a (int): integer a ≥ 0
    b (int): integer b ≥ 0

  Returns:
    (gcd, x, y) so that a * x + b * y = gcd
    x and y may be negative integers or zero but won't be both zero.

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if a < 0 or b < 0:
    raise InputError(f'negative input: {a=} , {b=}')
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


def ModInv(x: int, m: int, /) -> int:
  """Modular inverse of `x` modulo `m`: a `y` such that (x * y) % m == 1 if GCD(x, m) == 1.

  Args:
    x (int): integer to invert, x ≥ 0
    m (int): modulo, m ≥ 1

  Returns:
    positive integer `y` such that (x * y) % m == 1
    this only exists if GCD(x, m) == 1, so to guarantee an inverse `m` must be prime

  Raises:
    InputError: invalid modulus or x
    ModularDivideError: divide-by-zero, i.e., GCD(x, m) != 1 or x == 0
  """
  # test inputs
  if m < 1:
    raise InputError(f'invalid modulus: {m=}')
  if not 0 <= x < m:
    raise InputError(f'invalid input: {x=}')
  # easy special cases: 0 and 1
  if not x:  # "division by 0"
    gcd = m
    raise ModularDivideError(f'null inverse {x=} mod {m=} with {gcd=}')
  if x == 1:  # trivial degenerate case
    return 1
  # compute actual extended GCD and see if we will have an inverse
  gcd, y, w = ExtendedGCD(x, m)
  if gcd != 1:
    raise ModularDivideError(f'invalid inverse {x=} mod {m=} with {gcd=}')
  assert y and w and y >= -m, f'should never happen: {x=} mod {m=} -> {w=} ; {y=}'
  return y if y >= 0 else (y + m)


def ModDiv(x: int, y: int, m: int, /) -> int:
  """Modular division of `x`/`y` modulo `m`, if GCD(y, m) == 1.

  Args:
    x (int): integer, x ≥ 0
    y (int): integer, y ≥ 0
    m (int): modulo, m ≥ 1

  Returns:
    positive integer `z` such that (z * y) % m == x
    this only exists if GCD(y, m) == 1, so to guarantee an inverse `m` must be prime

  Raises:
    InputError: invalid modulus or x or y
    ModularDivideError: divide-by-zero, i.e., GCD(y, m) != 1 or y == 0
  """
  return ((x % m) * ModInv(y % m, m)) % m


def ModExp(x: int, y: int, m: int, /) -> int:
  """Modular exponential: returns (x ** y) % m efficiently (can handle huge values).

  Args:
    x (int): integer, x ≥ 0
    y (int): integer, y ≥ 0
    m (int): modulo, m ≥ 1

  Returns:
    (x ** y) mod m

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if x < 0 or y < 0:
    raise InputError(f'negative input: {x=} , {y=}')
  if m < 1:
    raise InputError(f'invalid modulus: {m=}')
  # trivial cases
  if not y or x == 1:
    return 1 % m
  if not x:
    return 0  # 0**0==1 was already taken care of by previous condition
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


def ModPolynomial(x: int, polynomial: Reversible[int], m: int, /) -> int:
  """Evaluates polynomial `poly` (coefficient iterable) at `x` modulus `m`.

  Evaluate a polynomial at `x` under a modulus `m` using Horner's rule. Horner rewrites:
      a_0 + a_1 x + a_2 x^2 + … + a_n x^n
    = (…((a_n x + a_{n-1}) x + a_{n-2}) … ) x + a_0
  This uses exactly n multiplies and n adds, and lets us take `% m` at each
  step so intermediate numbers never explode.

  Args:
    x (int) The evaluation point (x ≥ 0)
    polynomial (Reversible[int]): Iterable of coefficients a_0, a_1, …, a_n
        (constant term first); it must be reversible because Horner's rule consumes
        coefficients from highest degree downwards
    m (int): Modulus (m ≥ 1); if you expect multiplicative inverses elsewhere, should be prime

  Returns:
    f(x) mod m

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if x < 0 or not polynomial:
    raise InputError(f'negative input or no polynomial: {x=} ; {polynomial=}')
  if m < 1:
    raise InputError(f'invalid modulus: {m=}')
  # loop over polynomial coefficients
  total: int = 0
  x %= m
  for coefficient in reversed(polynomial):
    total = (total * x + coefficient) % m
  return total


def ModLagrangeInterpolate(x: int, points: dict[int, int], m: int, /) -> int:
  """Find the f(x) solution for the given `x` and {x: y} `points` modulus prime `m`.

  Given `points` will define a polynomial of up to len(points) order.
  Evaluate (interpolate) the unique polynomial of degree ≤ (n-1) that passes
  through the given points (x_i, y_i), and return f(x) modulo a prime `m`.

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
    x (int): The x-value at which to evaluate the interpolated polynomial, x ≥ 0
    points (dict[int, int]): A mapping {x_i: y_i}, where all 0 ≤ x_i < m and 0 ≤ y_i < m, minimum of 2
    m (int): Prime modulus (m ≥ 2); we need modular inverses, so gcd(denominator, m) must be 1

  Returns:
    y-value solution for f(x) mod m given `points` mapping

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if x < 0:
    raise InputError(f'negative input: {x=}')
  if m < 2:
    raise InputError(f'invalid modulus: {m=}')
  if len(points) < 2 or any(not 0 <= k < m or not 0 <= v < m for k, v in points.items()):
    raise InputError(f'invalid points: {points=}')
  # compute everything term-by-term
  x %= m
  result: int = 0
  for xi, yi in points.items():
    # build numerator and denominator of L_i(x)
    num: int = 1  # Π (x - x_j)
    den: int = 1  # Π (xi - x_j)
    for xj in points:
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
    raise InputError(f'invalid number: {n=}')
  if n in (2, 3):
    return True
  if n == 1 or not n % 2:
    return False
  # n is odd and >= 5 so now we generate witnesses (if needed)
  # degenerate case is: n==5, max_safety==2 => randint(2, 3) => {2, 3}
  if not witnesses:
    max_safety: int = min(n // 2, _MAX_PRIMALITY_SAFETY)
    if safety < 1:
      raise InputError(f'out of bounds safety: 1 <= {safety=} <= {max_safety}')
    safety = max_safety if safety > max_safety else safety
    witnesses = set()
    rand = secrets.SystemRandom()
    while len(witnesses) < safety:
      witnesses.add(rand.randint(2, n - 2))
  # we have our witnesses: do the actual Fermat algo
  for w in sorted(witnesses):
    if not 2 <= w <= (n - 2):
      raise InputError(f'out of bounds witness: 2 <= {w=} <= {n - 2}')
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
    raise InputError(f'invalid number: {n=}')
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
  assert n_bits >= 82, f'should never happen: {n=} -> {n_bits=}'
  safety: int = int(math.ceil(0.375 + 1.59 / (0.000590 * n_bits))) if n_bits <= 1700 else 2
  assert 1 < safety <= 34, f'should never happen: {n=} -> {n_bits=} ; {safety=}'
  return set(FIRST_60_PRIMES_SORTED[:safety])


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
    raise InputError(f'invalid odd number: {n=}')
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
    raise InputError(f'invalid number: {n=}')
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
      raise InputError(f'out of bounds witness: 2 <= {w=} <= {n - 2}')
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
  if n > PRIME_60 and GCD(n, COMPOSITE_60) != 1:
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
    raise InputError(f'invalid number: {start=}')
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
    raise InputError(f'invalid n: {n_bits=}')
  # get a random number with guaranteed bit size
  min_start: int = 2 ** (n_bits - 1)
  prime: int = 0
  while prime.bit_length() != n_bits:
    start_point: int = secrets.randbits(n_bits)
    while start_point < min_start:
      # i know we could just set the bit, but IMO it is better to get another entirely
      start_point = secrets.randbits(n_bits)
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


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class CryptoKey:
  """A cryptographic key."""

  def __post_init__(self) -> None:
    """Check data."""


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class RSAPublicKey(CryptoKey):
  """RSA (Rivest-Shamir-Adleman) key, with the public part of the key.

  Attributes:
    public_modulus (int): modulus (p * q), ≥ 6
    encrypt_exp (int): encryption exponent, 3 ≤ e < modulus, (e * decrypt) % ((p-1) * (q-1)) == 1
  """

  public_modulus: int
  encrypt_exp: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
    """
    super(RSAPublicKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if self.public_modulus < 6 or IsPrime(self.public_modulus):
      # only a full factors check can prove modulus is product of only 2 primes, which is impossible
      # to do for large numbers here; the private key checks the relationship though
      raise InputError(f'invalid public_modulus: {self}')
    if not 2 < self.encrypt_exp < self.public_modulus or not IsPrime(self.encrypt_exp):
      # technically, encrypt_exp < phi, but again the private key tests for this explicitly
      raise InputError(f'invalid encrypt_exp: {self}')

  def Encrypt(self, message: int, /) -> int:
    """Encrypt `message` with this public key.

    Args:
      message (int): message to encrypt, 1 ≤ m < modulus

    Returns:
      encrypted message (int, 1 ≤ m < modulus) = (m ** encrypt_exp) mod modulus

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 < message < self.public_modulus:
      raise InputError(f'invalid message: {message=}')
    # encrypt
    return ModExp(message, self.encrypt_exp, self.public_modulus)

  def VerifySignature(self, message: int, signature: int, /) -> bool:
    """Verify a signature. True if OK; False if failed verification.

    Args:
      message (int): message that was signed by key owner, 1 ≤ m < modulus
      signature (int): signature, 1 ≤ s < modulus

    Returns:
      True if signature is valid, False otherwise;
      (signature ** encrypt_exp) mod modulus == message

    Raises:
      InputError: invalid inputs
    """
    return self.Encrypt(signature) == message

  @classmethod
  def Copy(cls, other: 'RSAPublicKey', /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key."""
    return cls(public_modulus=other.public_modulus, encrypt_exp=other.encrypt_exp)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class RSAObfuscationPair(RSAPublicKey):
  """RSA (Rivest-Shamir-Adleman) obfuscation pair for a public key.

  Attributes:
    random_key (int): random value key, 2 ≤ k < modulus
    key_inverse (int): inverse for `random_key` in relation to the RSA public key, 2 ≤ i < modulus
  """

  random_key: int
  key_inverse: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
      CryptoError: modulus math is inconsistent with values
    """
    super(RSAObfuscationPair, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (not 1 < self.random_key < self.public_modulus or
        not 1 < self.key_inverse < self.public_modulus or
        self.random_key in (self.key_inverse, self.encrypt_exp, self.public_modulus)):
      raise InputError(f'invalid keys: {self}')
    if (self.random_key * self.key_inverse) % self.public_modulus != 1:
      raise CryptoError(f'inconsistent keys: {self}')

  def ObfuscateMessage(self, message: int, /) -> int:
    """Convert message to an obfuscated message to be signed by this key's owner.

    Args:
      message (int): message to obfuscate before signature, 1 ≤ m < modulus

    Returns:
      obfuscated message (int, 1 ≤ m < modulus) = (m * (random_key ** encrypt_exp)) mod modulus

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 < message < self.public_modulus:
      raise InputError(f'invalid message: {message=}')
    # encrypt
    return (message * ModExp(
        self.random_key, self.encrypt_exp, self.public_modulus)) % self.public_modulus

  def RevealOriginalSignature(self, message: int, signature: int, /) -> int:
    """Recover original signature for `message` from obfuscated `signature`.

    Args:
      message (int): original message before obfuscation, 1 ≤ m < modulus
      signature (int): signature for obfuscated message (not `message`!), 1 ≤ s < modulus

    Returns:
      original signature (int, 1 ≤ s < modulus) to `message`;
      signature * key_inverse mod modulus

    Raises:
      InputError: invalid inputs
      CryptoError: some signatures were invalid (either plain or obfuscated)
    """
    # verify that obfuscated signature is valid
    obfuscated: int = self.ObfuscateMessage(message)
    if not self.VerifySignature(obfuscated, signature):
      raise CryptoError(f'obfuscated message was not signed: {message=} ; {signature=}')
    # compute signature for original message and check it
    original: int = (signature * self.key_inverse) % self.public_modulus
    if not self.VerifySignature(message, original):
      raise CryptoError(f'failed signature recovery: {message=} ; {signature=}')
    return original

  @classmethod
  def New(cls, key: RSAPublicKey, /) -> Self:
    """New obfuscation pair for this `key`, respecting the size of the public modulus.

    Args:
      key (RSAPublicKey): public RSA key to use as base for a new RSAObfuscationPair

    Returns:
      RSAObfuscationPair object ready for use
    """
    # find a suitable random key based on the bit_length
    random_key: int = 0
    key_inverse: int = 0
    while (not random_key or not key_inverse or
           random_key == key.encrypt_exp or
           random_key == key_inverse or
           key_inverse == key.encrypt_exp):
      random_key = secrets.randbits(key.public_modulus.bit_length() - 1)
      try:
        key_inverse = ModInv(random_key, key.public_modulus)
      except ModularDivideError:
        key_inverse = 0
    # build object
    return cls(
        public_modulus=key.public_modulus, encrypt_exp=key.encrypt_exp,
        random_key=random_key, key_inverse=key_inverse)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class RSAPrivateKey(RSAPublicKey):
  """RSA (Rivest-Shamir-Adleman) private key.

  Attributes:
    modulus_p (int): prime number p, ≥ 2
    modulus_q (int): prime number q, ≥ 3 and > p
    decrypt_exp (int): decryption exponent, 2 ≤ d < modulus, (encrypt * d) % ((p-1) * (q-1)) == 1
  """

  modulus_p: int
  modulus_q: int
  decrypt_exp: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
      CryptoError: modulus math is inconsistent with values
    """
    super(RSAPrivateKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    phi: int = (self.modulus_p - 1) * (self.modulus_q - 1)
    min_prime_distance: int = 2 ** (self.public_modulus.bit_length() // 3 + 1)
    if (self.modulus_p < 2 or not IsPrime(self.modulus_p) or  # pylint: disable=too-many-boolean-expressions
        self.modulus_q < 3 or not IsPrime(self.modulus_q) or
        self.modulus_q <= self.modulus_p or
        (self.modulus_q - self.modulus_p) < min_prime_distance or
        self.encrypt_exp in (self.modulus_p, self.modulus_q) or
        self.encrypt_exp >= phi or
        self.decrypt_exp in (self.encrypt_exp, self.modulus_p, self.modulus_q, phi)):
      # encrypt_exp has to be less than phi;
      # if p − q < 2*(n**(1/4)) then solving for p and q is trivial
      raise InputError(f'invalid modulus_p or modulus_q: {self}')
    min_decrypt_length: int = self.public_modulus.bit_length() // 2 + 1
    if not (2 ** min_decrypt_length) < self.decrypt_exp < self.public_modulus:
      # if decrypt_exp < public_modulus**(1/4)/3, then decrypt_exp can be computed efficiently
      # from public_modulus and encrypt_exp so we make sure it is larger than public_modulus**(1/2)
      raise InputError(f'invalid decrypt_exp: {self}')
    if self.modulus_p * self.modulus_q != self.public_modulus:
      raise CryptoError(f'inconsistent modulus_p * modulus_q: {self}')
    if (self.encrypt_exp * self.decrypt_exp) % phi != 1:
      raise CryptoError(f'inconsistent exponents: {self}')

  def Decrypt(self, message: int, /) -> int:
    """Decrypt `message` with this private key.

    Args:
      message (int): message to encrypt, 1 ≤ m < modulus

    Returns:
      decrypted message (int, 1 ≤ m < modulus) = (m ** decrypt_exp) mod modulus

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 < message < self.public_modulus:
      raise InputError(f'invalid message: {message=}')
    # decrypt
    return ModExp(message, self.decrypt_exp, self.public_modulus)

  def Sign(self, message: int, /) -> int:
    """Sign `message` with this private key.

    Args:
      message (int): message to sign, 1 ≤ m < modulus

    Returns:
      signed message (int, 1 ≤ m < modulus) = (m ** decrypt_exp) mod modulus;
      identical to Decrypt()

    Raises:
      InputError: invalid inputs
    """
    return self.Decrypt(message)

  @classmethod
  def New(cls, bit_length: int, /) -> Self:
    """Make a new private key of `bit_length` bits (primes p & q will be half this length).

    Args:
      bit_length (int): number of bits in the modulus, ≥ 11; primes p & q will be half this length

    Returns:
      RSAPrivateKey object ready for use

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if bit_length < 11:
      raise InputError(f'invalid bit length: {bit_length=}')
    # generate primes / modulus
    failures: int = 0
    while True:
      try:
        primes: list[int] = [NBitRandomPrime(bit_length // 2), NBitRandomPrime(bit_length // 2)]
        modulus: int = primes[0] * primes[1]
        while modulus.bit_length() != bit_length or primes[0] == primes[1]:
          primes.remove(min(primes))
          primes.append(NBitRandomPrime(
              bit_length // 2 + (bit_length % 2 if modulus.bit_length() < bit_length else 0)))
          modulus = primes[0] * primes[1]
        # build object
        phi: int = (primes[0] - 1) * (primes[1] - 1)
        prime_exp: int = (_SMALL_ENCRYPTION_EXPONENT if phi <= _BIG_ENCRYPTION_EXPONENT else
                          _BIG_ENCRYPTION_EXPONENT)
        obj: Self = cls(
            modulus_p=min(primes),  # "p" is always the smaller
            modulus_q=max(primes),  # "q" is always the larger
            public_modulus=modulus,
            encrypt_exp=prime_exp,
            decrypt_exp=ModInv(prime_exp, phi),
        )
        return obj
      except (InputError, ModularDivideError) as err:
        failures += 1
        if failures >= _MAX_KEY_GENERATION_FAILURES:
          raise CryptoError(f'failed key generation {failures} times') from err
        logging.warning(err)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ShamirSharedSecretPublic(CryptoKey):
  """Shamir Shared Secret (SSS) public part (<https://en.wikipedia.org/wiki/Shamir's_secret_sharing>).

  Attributes:
    minimum (int): minimum shares needed for recovery, ≥ 2
    modulus (int): prime modulus used for share generation, prime, ≥ 2
  """

  minimum: int
  modulus: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
    """
    super(ShamirSharedSecretPublic, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (self.modulus < 2 or
        not IsPrime(self.modulus) or
        self.minimum < 2):
      raise InputError(f'invalid modulus or minimum: {self}')

  def RecoverSecret(
      self, shares: Collection['ShamirSharePrivate'], /, *, force_recover: bool = False) -> int:
    """Recover the secret from ShamirSharePrivate objects.

    Raises:
      InputError: invalid inputs
      CryptoError: secret cannot be recovered
    """
    # check that we have enough shares
    share_points: dict[int, int] = {s.share_key: s.share_value for s in shares}  # de-dup guaranteed
    if (given_shares := len(share_points)) < self.minimum:
      mess: str = f'distinct shares {given_shares} < minimum shares {self.minimum}'
      if force_recover and given_shares > 1:
        logging.error('recovering secret even though: %s', mess)
      else:
        raise CryptoError(f'unrecoverable secret: {mess}')
    # do the math
    return ModLagrangeInterpolate(0, share_points, self.modulus)

  @classmethod
  def Copy(cls, other: 'ShamirSharedSecretPublic', /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key."""
    return cls(minimum=other.minimum, modulus=other.modulus)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ShamirSharedSecretPrivate(ShamirSharedSecretPublic):
  """Shamir Shared Secret (SSS) private keys (<https://en.wikipedia.org/wiki/Shamir's_secret_sharing>).

  Attributes:
    polynomial (list[int]): prime coefficients for generation poly., each modulus.bit_length() size
  """

  polynomial: list[int]

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
    """
    super(ShamirSharedSecretPrivate, self).__post_init__()       # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (len(self.polynomial) != self.minimum - 1 or              # exactly this size
        len(set(self.polynomial)) != self.minimum - 1 or         # no duplicate
        self.modulus in self.polynomial or                       # different from modulus
        any(not IsPrime(p) or p.bit_length() != self.modulus.bit_length()
            for p in self.polynomial)):                          # all primes and the right size
      raise InputError(f'invalid polynomial: {self}')

  def Share(self, secret: int, /, *, share_key: int = 0) -> 'ShamirSharePrivate':
    """Make a new ShamirSharePrivate for the `secret`.

    Args:
      secret (int): secret message to encrypt and share, 0 ≤ s < modulus
      share_key (int, optional): if given, a random value to use, 1 ≤ r < modulus;
          else will generate randomly

    Returns:
      ShamirSharePrivate object

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 <= secret < self.modulus:
      raise InputError(f'invalid secret: {secret=}')
    if not 1 < share_key < self.modulus:
      if not share_key:  # default is zero, and that means we generate it here
        sr = secrets.SystemRandom()
        share_key = 0
        while not share_key or share_key in self.polynomial:
          share_key = sr.randint(2, self.modulus - 1)
      else:
        raise InputError(f'invalid share_key: {secret=}')
    # build object
    return ShamirSharePrivate(
        minimum=self.minimum, modulus=self.modulus,
        share_key=share_key,
        share_value=ModPolynomial(share_key, [secret] + self.polynomial, self.modulus))

  def Shares(
      self, secret: int, /, *, max_shares: int = 0) -> Generator['ShamirSharePrivate', None, None]:
    """Make any number of ShamirSharePrivate for the `secret`.

    Args:
      secret (int): secret message to encrypt and share, 0 ≤ s < modulus
      max_shares (int, optional): if given, number (≥ 2) of shares to generate; else infinite

    Yields:
      ShamirSharePrivate object

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if max_shares and max_shares < self.minimum:
      raise InputError(f'invalid max_shares: {max_shares=} < {self.minimum=}')
    # generate shares
    sr = secrets.SystemRandom()
    count: int = 0
    used_keys: set[int] = set()
    while not max_shares or count < max_shares:
      share_key: int = 0
      while not share_key or share_key in self.polynomial or share_key in used_keys:
        share_key = sr.randint(2, self.modulus - 1)
      try:
        yield self.Share(secret, share_key=share_key)
        used_keys.add(share_key)
        count += 1
      except InputError as err:
        # it could happen, for example, that the share_key will generate a value of 0
        logging.warning(err)

  def VerifyShare(self, secret: int, share: 'ShamirSharePrivate', /) -> bool:
    """Make a new ShamirSharePrivate for the `secret`.

    Args:
      secret (int): secret message to encrypt and share, 0 ≤ s < modulus
      share (ShamirSharePrivate): share to verify

    Returns:
      True if share is valid; False otherwise

    Raises:
      InputError: invalid inputs
    """
    return share == self.Share(secret, share_key=share.share_key)

  @classmethod
  def New(cls, minimum_shares: int, bit_length: int, /) -> Self:
    """Make a new public sharing prime modulus of `bit_length` bits.

    Args:
      minimum_shares (int): minimum shares needed for recovery, ≥ 2
      bit_length (int): number of bits in the primes, ≥ 10

    Returns:
      ShamirSharedSecretPrivate object ready for use

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if minimum_shares < 2:
      raise InputError(f'at least 2 shares are needed: {minimum_shares=}')
    if bit_length < 10:
      raise InputError(f'invalid bit length: {bit_length=}')
    # make the primes
    unique_primes: set[int] = set()
    while len(unique_primes) < minimum_shares:
      unique_primes.add(NBitRandomPrime(bit_length))
    # get the largest prime for the modulus
    ordered_primes: list[int] = list(unique_primes)
    modulus: int = max(ordered_primes)
    ordered_primes.remove(modulus)
    # make polynomial be a random order
    secrets.SystemRandom().shuffle(ordered_primes)
    # build object
    return cls(minimum=minimum_shares, modulus=modulus, polynomial=ordered_primes)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ShamirSharePrivate(ShamirSharedSecretPublic):
  """Shamir Shared Secret (SSS) one share (<https://en.wikipedia.org/wiki/Shamir's_secret_sharing>).

  Attributes:
    share_key (int): share secret key; a randomly picked value, 1 ≤ k < modulus
    share_value (int): share secret value, 1 ≤ v < modulus; (k, v) is a "point" of f(k)=v
  """

  share_key: int
  share_value: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
    """
    super(ShamirSharePrivate, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (not 0 < self.share_key < self.modulus or
        not 0 < self.share_value < self.modulus):
      raise InputError(f'invalid share: {self}')
