#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto DSA (Digital Signature Algorithm) library.

<https://en.wikipedia.org/wiki/Digital_Signature_Algorithm>

BEWARE: For now, this implementation is raw DSA, no padding, no hash!
In the future we will design a proper DSA+Hash implementation.
"""

from __future__ import annotations

import dataclasses
import logging
# import pdb
from typing import Self

from . import base
from . import modmath

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


_PRIME_MULTIPLE_SEARCH = 30
_MAX_KEY_GENERATION_FAILURES = 15


def NBitRandomDSAPrimes(p_bits: int, q_bits: int, /) -> tuple[int, int, int]:
  """Generates 2 random DSA primes p & q with `x_bits` size and (p-1)%q==0.

  Args:
    p_bits (int): Number of guaranteed bits in `p` prime representation,
        p_bits ≥ q_bits + 11
    q_bits (int): Number of guaranteed bits in `q` prime representation, ≥ 11

  Returns:
    random primes tuple (p, q, m), with p-1 a random multiple m of q, such
    that p % q == 1 and m == (p - 1) // q

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if q_bits < 11:
    raise base.InputError(f'invalid q_bits length: {q_bits=}')
  if p_bits < q_bits + 11:
    raise base.InputError(f'invalid p_bits length: {p_bits=}')
  # make q
  q = modmath.NBitRandomPrime(q_bits)
  # find range of multiples to use
  min_p, max_p = 2 ** (p_bits - 1), 2 ** p_bits - 1
  min_m, max_m = min_p // q + 2, max_p // q - 2
  assert max_m - min_m > 1000  # make sure we'll have options!
  # start searching from a random multiple
  failures: int = 0
  while True:
    # try searching starting here
    m: int = base.RandInt(min_m, max_m)
    for _ in range(_PRIME_MULTIPLE_SEARCH):
      p: int = q * m + 1
      if p >= max_p:
        break
      if modmath.IsPrime(p):
        return (p, q, m)  # found a suitable prime set!
      m += 1  # next multiple
    # after _PRIME_MULTIPLE_SEARCH we declare this range failed
    failures += 1
    if failures >= _MAX_KEY_GENERATION_FAILURES:
      raise base.CryptoError(f'failed primes generation {failures} times')
    logging.warning(f'failed primes search: {failures}')


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class DSASharedPublicKey(base.CryptoKey):
  """DSA shared public key. This key can be shared by a group.

  No measures are taken here to prevent timing attacks.

  Attributes:
    prime_modulus (int): prime modulus (p), > prime_seed
    prime_seed (int): prime seed (q), ≥ 7
    group_base (int): shared encryption group public base, 3 ≤ g < prime_modulus
  """

  prime_modulus: int
  prime_seed: int
  group_base: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
    """
    super(DSASharedPublicKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if self.prime_seed < 7 or not modmath.IsPrime(self.prime_seed):
      raise base.InputError(f'invalid prime_seed: {self}')
    if (self.prime_modulus <= self.prime_seed or
        self.prime_modulus % self.prime_seed != 1 or
        not modmath.IsPrime(self.prime_modulus)):
      raise base.InputError(f'invalid prime_modulus: {self}')
    if (not 2 < self.group_base < self.prime_modulus or
        self.group_base == self.prime_seed):
      raise base.InputError(f'invalid group_base: {self}')

  def __str__(self) -> str:
    """Safe string representation of the DSASharedPublicKey.

    Returns:
      string representation of DSASharedPublicKey
    """
    return ('DSASharedPublicKey('
            f'bits=[{self.prime_modulus.bit_length()}, {self.prime_seed.bit_length()}], '
            f'prime_modulus={base.IntToEncoded(self.prime_modulus)}, '
            f'prime_seed={base.IntToEncoded(self.prime_seed)}, '
            f'group_base={base.IntToEncoded(self.group_base)})')

  @classmethod
  def NewShared(cls, p_bits: int, q_bits: int, /) -> Self:
    """Make a new shared public key of `bit_length` bits.

    Args:
      p_bits (int): Number of guaranteed bits in `p` prime representation,
        p_bits ≥ q_bits + 11
      q_bits (int): Number of guaranteed bits in `q` prime representation, ≥ 11

    Returns:
      DSASharedPublicKey object ready for use

    Raises:
      InputError: invalid inputs
    """
    # test inputs and generate primes
    p, q, m = NBitRandomDSAPrimes(p_bits, q_bits)
    # generate random number, create object (should never fail)
    g: int = 0
    while g < 2:
      h: int = base.RandBits(p_bits - 1)
      g = modmath.ModExp(h, m, p)
    return cls(prime_modulus=p, prime_seed=q, group_base=g)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class DSAPublicKey(DSASharedPublicKey):
  """DSA public key. This is an individual public key.

  No measures are taken here to prevent timing attacks.

  Attributes:
    individual_base (int): individual encryption public base, 3 ≤ i < prime_modulus
  """

  individual_base: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
    """
    super(DSAPublicKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (not 2 < self.individual_base < self.prime_modulus or
        self.individual_base in (self.group_base, self.prime_seed)):
      raise base.InputError(f'invalid individual_base: {self}')

  def __str__(self) -> str:
    """Safe string representation of the DSAPublicKey.

    Returns:
      string representation of DSAPublicKey
    """
    return ('DSAPublicKey('
            f'{super(DSAPublicKey, self).__str__()}, '  # pylint: disable=super-with-arguments
            f'individual_base={base.IntToEncoded(self.individual_base)})')

  def _MakeEphemeralKey(self) -> tuple[int, int]:
    """Make an ephemeral key adequate to be used with El-Gamal.

    Returns:
      (key, key_inverse), where 3 ≤ k < p_seed and (k*i) % p_seed == 1
    """
    ephemeral_key: int = 0
    bit_length: int = self.prime_seed.bit_length()
    while (not 2 < ephemeral_key < self.prime_seed or
           ephemeral_key in (self.group_base, self.individual_base)):
      ephemeral_key = base.RandBits(bit_length - 1)
    return (ephemeral_key, modmath.ModInv(ephemeral_key, self.prime_seed))

  def RawVerify(self, message: int, signature: tuple[int, int], /) -> bool:
    """Verify a signature. True if OK; False if failed verification.

    BEWARE: This is raw DSA, no ECDSA/EdDSA padding, no hash, no validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message that was signed by key owner, 0 < m < prime_seed
      signature (tuple[int, int]): signature, 2 ≤ s1,s2 < prime_seed

    Returns:
      True if signature is valid, False otherwise

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 < message < self.prime_seed:
      raise base.InputError(f'invalid message: {message=}')
    if (not 2 <= signature[0] < self.prime_seed or
        not 2 <= signature[1] < self.prime_seed):
      raise base.InputError(f'invalid signature: {signature=}')
    # verify
    inv: int = modmath.ModInv(signature[1], self.prime_seed)
    a: int = modmath.ModExp(
        self.group_base, (message * inv) % self.prime_seed, self.prime_modulus)
    b: int = modmath.ModExp(
        self.individual_base, (signature[0] * inv) % self.prime_seed, self.prime_modulus)
    return ((a * b) % self.prime_modulus) % self.prime_seed == signature[0]

  @classmethod
  def Copy(cls, other: DSAPublicKey, /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key."""
    return cls(
        prime_modulus=other.prime_modulus,
        prime_seed=other.prime_seed,
        group_base=other.group_base,
        individual_base=other.individual_base)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class DSAPrivateKey(DSAPublicKey):
  """DSA private key.

  No measures are taken here to prevent timing attacks.

  Attributes:
    decrypt_exp (int): individual decryption exponent, 3 ≤ i < prime_modulus
  """

  decrypt_exp: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
      CryptoError: modulus math is inconsistent with values
    """
    super(DSAPrivateKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (not 2 < self.decrypt_exp < self.prime_seed or
        self.decrypt_exp in (self.group_base, self.individual_base)):
      raise base.InputError(f'invalid decrypt_exp: {self}')
    if modmath.ModExp(
        self.group_base, self.decrypt_exp, self.prime_modulus) != self.individual_base:
      raise base.CryptoError(f'inconsistent g**d % p == i: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the DSAPrivateKey.

    Returns:
      string representation of DSAPrivateKey without leaking secrets
    """
    return ('DSAPrivateKey('
            f'{super(DSAPrivateKey, self).__str__()}, '  # pylint: disable=super-with-arguments
            f'decrypt_exp={base.ObfuscateSecret(self.decrypt_exp)})')

  def RawSign(self, message: int, /) -> tuple[int, int]:
    """Sign `message` with this private key.

    BEWARE: This is raw DSA, no ECDSA/EdDSA padding, no hash, no validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to sign, 1 ≤ m < prime_seed

    Returns:
      signed message tuple ((int, int), 2 ≤ s1,s2 < prime_seed

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 < message < self.prime_seed:
      raise base.InputError(f'invalid message: {message=}')
    # sign
    a, b = 0, 0
    while a < 2 or b < 2:
      ephemeral_key, ephemeral_inv = self._MakeEphemeralKey()
      a = modmath.ModExp(self.group_base, ephemeral_key, self.prime_modulus) % self.prime_seed
      b = (ephemeral_inv * ((message + a * self.decrypt_exp) % self.prime_seed)) % self.prime_seed
    return (a, b)

  @classmethod
  def New(cls, shared_key: DSASharedPublicKey, /) -> Self:
    """Make a new private key based on an existing shared public key.

    Args:
      shared_key (DSASharedPublicKey): shared public key

    Returns:
      DSAPrivateKey object ready for use

    Raises:
      InputError: invalid inputs
      CryptoError: failed generation
    """
    # test inputs
    bit_length: int = shared_key.prime_seed.bit_length()
    if bit_length < 11:
      raise base.InputError(f'invalid q_bit length: {bit_length=}')
    # loop until we have an object
    failures: int = 0
    while True:
      try:
        # generate private key differing from group_base
        decrypt_exp: int = 0
        while (not 2 < decrypt_exp < shared_key.prime_seed - 1 or
               decrypt_exp == shared_key.group_base):
          decrypt_exp = base.RandBits(bit_length - 1)
        # make the object
        return cls(
            prime_modulus=shared_key.prime_modulus,
            prime_seed=shared_key.prime_seed,
            group_base=shared_key.group_base,
            individual_base=modmath.ModExp(
                shared_key.group_base, decrypt_exp, shared_key.prime_modulus),
            decrypt_exp=decrypt_exp)
      except base.InputError as err:
        failures += 1
        if failures >= _MAX_KEY_GENERATION_FAILURES:
          raise base.CryptoError(f'failed key generation {failures} times') from err
        logging.warning(err)
