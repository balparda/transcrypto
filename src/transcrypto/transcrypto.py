#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto."""

import dataclasses
import datetime
import math
# import pdb
import secrets
from typing import Generator, Optional, Self

__author__ = 'balparda@github.com'
__version__: tuple[int, int, int] = (1, 0, 2)  # v1.0.2, 2025-07-22


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

_MAX_PRIMALITY_SAFETY = 100  # this is an absurd number, just to have a max

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
  """Greatest Common Divisor for `a` and `b`, positive integers.

  Uses the Euclid method.
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
  """Greatest Common Divisor Extended for `a` and `b`, positive integers.

  Uses the Euclid method.

  Returns:
    (gcd, x, y) so that a * x + b * y = gcd
    x and y may be negative integers or zero but won't be both zero.
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
    x (int): positive integer to invert, x >= 0
    m (int): modulo, m > 0

  Returns:
    positive integer `y` such that (x * y) % m == 1
    this only exists if GCD(x, m) == 1, so to guarantee an inverse `m` must be prime
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


def ModExp(x: int, y: int, m: int, /) -> int:
  """Modular exponential: returns (x ** y) % m efficiently (can handle huge values)."""
  # test inputs
  if x < 0 or y < 0:
    raise InputError(f'negative input: {x=} , {y=}')
  if m < 1:
    raise InputError(f'invalid modulus: {m=}')
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
    n (int): Number to test primality
    witnesses (set[int], optional): If given will use exactly these witnesses, in order

  Returns:
    False if certainly not prime ; True if (probabilistically) prime
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
    n (int): Number to test primality

  Returns:
    False if certainly not prime ; True if (probabilistically) prime
  """
  # is number divisible by (one of the) first 60 primes? test should eliminate 80%+ of candidates
  if n > PRIME_60 and GCD(n, COMPOSITE_60) != 1:
    return False
  # do the (more expensive) Miller-Rabin primality test
  return MillerRabinIsPrime(n)


def PrimeGenerator(start: int, /) -> Generator[int, None, None]:
  """Generates all primes from `start` until loop is broken. Tuned for huge numbers."""
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
  """Generates a random prime with (guaranteed) `n_bits` binary representation length."""
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

  Yields:
    (exponent, mersenne_prime, perfect_number), given some exponent `n` that will be exactly:
    (n, 2 ** n - 1, (2 ** (n - 1)) * (2 ** n - 1))
  """
  # we now loop forever over prime exponents
  # "The exponents p corresponding to Mersenne primes must themselves be prime."
  for n in PrimeGenerator(start if start >= 1 else 1):
    mersenne: int = 2 ** n - 1
    if IsPrime(mersenne):
      yield (n, mersenne, (2 ** (n - 1)) * mersenne)  # found: also yield perfect number


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class RSAKey:
  """RSA (Rivest-Shamir-Adleman) key, with the public part of the key."""
  public_modulus: int  # modulus = (p * q)
  encrypt_exp: int     # encryption exponent; encryption is: ModExp(message, encrypt_exp, public_modulus)

  def __post_init__(self) -> None:
    """Check data."""
    if self.public_modulus < 6 or IsPrime(self.public_modulus):
      raise InputError(f'invalid public_modulus: {self}')
    if not 2 < self.encrypt_exp < self.public_modulus or not IsPrime(self.encrypt_exp):
      raise InputError(f'invalid encrypt_exp: {self}')

  def Encrypt(self, message: int, /) -> int:
    """Encrypt `message` with this public key."""
    # test inputs
    if not 0 < message < self.public_modulus:
      raise InputError(f'invalid message: {message=}')
    # encrypt
    return ModExp(message, self.encrypt_exp, self.public_modulus)

  def VerifySignature(self, message: int, signature: int, /) -> bool:
    """Verify a signature. True if OK; False if failed verification."""
    return self.Encrypt(signature) == message


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class RSAObfuscationPair(RSAKey):
  """RSA (Rivest-Shamir-Adleman) obfuscation pair for a public key."""
  random_key: int      # random value key
  key_inverse: int  # inverse for `random_key` in relation to the RSA public key

  def __post_init__(self) -> None:
    """Check data."""
    super(RSAObfuscationPair, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (not 1 < self.random_key < self.public_modulus or
        not 1 < self.key_inverse < self.public_modulus or
        self.random_key in (self.key_inverse, self.encrypt_exp, self.public_modulus)):
      raise InputError(f'invalid keys: {self}')
    if (self.random_key * self.key_inverse) % self.public_modulus != 1:
      raise CryptoError(f'inconsistent keys: {self}')

  def ObfuscateMessage(self, message: int, /) -> int:
    """Convert message to an obfuscated message to be signed by this key's owner."""
    # test inputs
    if not 0 < message < self.public_modulus:
      raise InputError(f'invalid message: {message=}')
    # encrypt
    return (message * ModExp(self.random_key, self.encrypt_exp, self.public_modulus)) % self.public_modulus

  def RevealOriginalSignature(self, message: int, signature: int, /) -> int:
    """Recover original signature for `message` from obfuscated `signature`."""
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
  def New(cls, key: RSAKey, /) -> Self:
    """New obfuscation pair for this `key`."""
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
class RSAPrivateKey(RSAKey):
  """RSA (Rivest-Shamir-Adleman) private key."""
  modulus_p: int     # prime number p
  modulus_q: int     # prime number q
  decrypt_exp: int  # decryption exponent; decryption is: ModExp(message, decrypt_exp, public_modulus)

  def __post_init__(self) -> None:
    """Check data."""
    super(RSAPrivateKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (self.modulus_p < 2 or not IsPrime(self.modulus_p) or  # pylint: disable=too-many-boolean-expressions
        self.modulus_q < 2 or not IsPrime(self.modulus_q) or
        self.modulus_p == self.modulus_q or
        self.encrypt_exp in (self.modulus_p, self.modulus_q)):
      raise InputError(f'invalid modulus_p or modulus_q: {self}')
    if not 2 < self.decrypt_exp < self.public_modulus:
      raise InputError(f'invalid decrypt_exp: {self}')
    if self.modulus_p * self.modulus_q != self.public_modulus:
      raise CryptoError(f'inconsistent modulus_p * modulus_q: {self}')
    if (self.encrypt_exp * self.decrypt_exp) % ((self.modulus_p - 1) * (self.modulus_q - 1)) != 1:
      raise CryptoError(f'inconsistent exponents: {self}')

  def Decrypt(self, message: int, /) -> int:
    """Decrypt `message` with this private key."""
    # test inputs
    if not 0 < message < self.public_modulus:
      raise InputError(f'invalid message: {message=}')
    # decrypt
    return ModExp(message, self.decrypt_exp, self.public_modulus)

  def Sign(self, message: int, /) -> int:
    """Sign `message` with this private key."""
    return self.Decrypt(message)

  @classmethod
  def New(cls, bit_length: int, /) -> Self:
    """Make a new private key using `seed1`, `seed2` & `seed3` as starting points for keys."""
    # test inputs
    if bit_length < 10:
      raise InputError(f'invalid bit length: {bit_length=}')
    # generate primes / modulus
    primes: list[int] = [NBitRandomPrime(bit_length // 2), NBitRandomPrime(bit_length // 2)]
    modulus: int = primes[0] * primes[1]
    while modulus.bit_length() != bit_length or primes[0] == primes[1]:
      primes.remove(min(primes))
      primes.append(NBitRandomPrime(bit_length // 2 + (bit_length % 2 if modulus.bit_length() < bit_length else 0)))
      modulus = primes[0] * primes[1]
    # phi / generate (prime_exp, inverse) pair
    phi: int = (primes[0] - 1) * (primes[1] - 1)
    prime_exp: int = 0
    prime_exp_inv: int = 0
    while (not prime_exp or
           prime_exp_inv < 3 or
           prime_exp == prime_exp_inv or
           prime_exp in primes or
           prime_exp_inv in primes):
      prime_exp = NBitRandomPrime(bit_length // 2)
      try:
        prime_exp_inv = ModInv(prime_exp, phi)
      except ModularDivideError:
        prime_exp_inv = 0
    # build object
    return cls(
        modulus_p=min(primes),  # "p" is always the smaller
        modulus_q=max(primes),  # "q" is always the larger
        public_modulus=modulus,
        encrypt_exp=prime_exp,
        decrypt_exp=prime_exp_inv,
    )
