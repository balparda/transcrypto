#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto El-Gamal library.

<https://en.wikipedia.org/wiki/ElGamal_encryption>
<https://en.wikipedia.org/wiki/ElGamal_signature_scheme>

ATTENTION: This is pure El-Gamal, **NOT** DSA (Digital Signature Algorithm).
For DSA, see the dsa.py library.

ALSO: ElGamal encryption is unconditionally malleable, and therefore is
not secure under chosen ciphertext attack. For example, given an encryption
`(c1,c2)` of some (possibly unknown) message `m`, one can easily construct
a valid encryption `(c1,2*c2)` of the message `2*m`.
"""

import dataclasses
import logging
# import pdb
from typing import Self

from . import base
from . import modmath

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


_MAX_KEY_GENERATION_FAILURES = 15


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ElGamalSharedPublicKey(base.CryptoKey):
  """El-Gamal shared public key. This key can be shared by a group.

  BEWARE: This is raw El-Gamal, no padding! This is **NOT** DSA!

  Attributes:
    prime_modulus (int): prime modulus, ≥ 7
    group_base (int): shared encryption group public base, 3 ≤ g < prime_modulus
  """

  prime_modulus: int
  group_base: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
    """
    super(ElGamalSharedPublicKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if self.prime_modulus < 7 or not modmath.IsPrime(self.prime_modulus):
      raise base.InputError(f'invalid prime_modulus: {self}')
    if not 2 < self.group_base < self.prime_modulus - 1:
      raise base.InputError(f'invalid group_base: {self}')

  @classmethod
  def New(cls, bit_length: int, /) -> Self:
    """Make a new shared public key of `bit_length` bits.

    Args:
      bit_length (int): number of bits in the prime modulus, ≥ 11

    Returns:
      ElGamalSharedPublicKey object ready for use

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if bit_length < 11:
      raise base.InputError(f'invalid bit length: {bit_length=}')
    # generate random prime and number, create object (should never fail)
    return cls(
        prime_modulus=modmath.NBitRandomPrime(bit_length),
        group_base=base.RandBits(bit_length - 1),
    )


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ElGamalPublicKey(ElGamalSharedPublicKey):
  """El-Gamal public key. This is an individual public key.

  BEWARE: This is raw El-Gamal, no padding! This is **NOT** DSA!

  Attributes:
    individual_base (int): individual encryption public base, 3 ≤ i < prime_modulus
  """

  individual_base: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      InputError: invalid inputs
    """
    super(ElGamalPublicKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (not 2 < self.individual_base < self.prime_modulus - 1 or
        self.individual_base == self.group_base):
      raise base.InputError(f'invalid individual_base: {self}')

  def _MakeEphemeralKey(self) -> tuple[int, int]:
    """Make an ephemeral key adequate to be used with El-Gamal.

    Returns:
      (key, key_inverse), where 2 ≤ k < modulus - 1 and
          GCD(k, modulus - 1) == 1 and (k*i) % (p-1) == 1
    """
    ephemeral_key: int = 0
    p_1: int = self.prime_modulus - 1
    bit_length: int = self.prime_modulus.bit_length()
    while (not 1 < ephemeral_key < p_1 or
           ephemeral_key in (self.group_base, self.individual_base)):
      ephemeral_key = base.RandBits(bit_length - 1)
      if base.GCD(ephemeral_key, p_1) != 1:
        ephemeral_key = 0  # we have to try again
    return (ephemeral_key, modmath.ModInv(ephemeral_key, p_1))

  def Encrypt(self, message: int, /) -> tuple[int, int]:
    """Encrypt `message` with this public key.

    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to encrypt, 1 ≤ m < modulus

    Returns:
      ciphertext message tuple ((int, int), 2 ≤ c1,c2 < modulus)

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 < message < self.prime_modulus:
      raise base.InputError(f'invalid message: {message=}')
    # encrypt
    ephemeral_key: int = self._MakeEphemeralKey()[0]
    a, b = 0, 0
    while a < 2 or b < 2:
      a = modmath.ModExp(self.group_base, ephemeral_key, self.prime_modulus)
      s: int = modmath.ModExp(self.individual_base, ephemeral_key, self.prime_modulus)
      b = (message * s) % self.prime_modulus
    return (a, b)

  def VerifySignature(self, message: int, signature: tuple[int, int], /) -> bool:
    """Verify a signature. True if OK; False if failed verification.

    We explicitly disallow `message` to be zero.

    Args:
      message (int): message that was signed by key owner, 0 < m < modulus
      signature (tuple[int, int]): signature, 2 ≤ s1 < modulus, 2 ≤ s2 < modulus-1

    Returns:
      True if signature is valid, False otherwise

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 < message < self.prime_modulus:
      raise base.InputError(f'invalid message: {message=}')
    if (not 2 <= signature[0] < self.prime_modulus or
        not 2 <= signature[1] < self.prime_modulus - 1):
      raise base.InputError(f'invalid signature: {signature=}')
    # verify
    a: int = modmath.ModExp(self.group_base, message, self.prime_modulus)
    b: int = modmath.ModExp(signature[0], signature[1], self.prime_modulus)
    c: int = modmath.ModExp(self.individual_base, signature[0], self.prime_modulus)
    return a == (b * c) % self.prime_modulus

  @classmethod
  def Copy(cls, other: 'ElGamalPublicKey', /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key."""
    return cls(
        prime_modulus=other.prime_modulus,
        group_base=other.group_base,
        individual_base=other.individual_base)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ElGamalPrivateKey(ElGamalPublicKey):
  """El-Gamal private key.
  
  BEWARE: This is raw El-Gamal, no padding! This is **NOT** DSA!

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
    super(ElGamalPrivateKey, self).__post_init__()  # pylint: disable=super-with-arguments  # needed here b/c: dataclass
    if (not 2 < self.decrypt_exp < self.prime_modulus - 1 or
        self.decrypt_exp in (self.group_base, self.individual_base)):
      raise base.InputError(f'invalid decrypt_exp: {self}')
    if modmath.ModExp(
        self.group_base, self.decrypt_exp, self.prime_modulus) != self.individual_base:
      raise base.CryptoError(f'inconsistent g**e % p == i: {self}')

  def Decrypt(self, ciphertext: tuple[int, int], /) -> int:
    """Decrypt `ciphertext` tuple with this private key.

    Args:
      ciphertext (tuple[int, int]): ciphertext to decrypt, 0 ≤ c1,c2 < modulus

    Returns:
      decrypted message (int, 1 ≤ m < modulus)

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if (not 2 <= ciphertext[0] < self.prime_modulus or
        not 2 <= ciphertext[1] < self.prime_modulus):
      raise base.InputError(f'invalid message: {ciphertext=}')
    # decrypt
    csi: int = modmath.ModExp(
        ciphertext[0], self.prime_modulus - 1 - self.decrypt_exp, self.prime_modulus)
    return (ciphertext[1] * csi) % self.prime_modulus

  def Sign(self, message: int, /) -> tuple[int, int]:
    """Sign `message` with this private key.

    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to sign, 1 ≤ m < modulus

    Returns:
      signed message tuple ((int, int), 2 ≤ s1 < modulus, 2 ≤ s2 < modulus-1)

    Raises:
      InputError: invalid inputs
    """
    # test inputs
    if not 0 < message < self.prime_modulus:
      raise base.InputError(f'invalid message: {message=}')
    # sign
    a, b, p_1 = 0, 0, self.prime_modulus - 1
    while a < 2 or b < 2:
      ephemeral_key, ephemeral_inv = self._MakeEphemeralKey()
      a = modmath.ModExp(self.group_base, ephemeral_key, self.prime_modulus)
      b = (ephemeral_inv * ((message - a * self.decrypt_exp) % p_1)) % p_1
    return (a, b)

  @classmethod
  def New(cls, shared_key: ElGamalSharedPublicKey, /) -> Self:
    """Make a new private key based on an existing shared public key.

    Args:
      shared_key (ElGamalSharedPublicKey): shared public key

    Returns:
      ElGamalPrivateKey object ready for use

    Raises:
      InputError: invalid inputs
      CryptoError: failed generation
    """
    # test inputs
    bit_length: int = shared_key.prime_modulus.bit_length()
    if bit_length < 11:
      raise base.InputError(f'invalid bit length: {bit_length=}')
    # loop until we have an object
    failures: int = 0
    while True:
      try:
        # generate private key differing from group_base
        decrypt_exp: int = 0
        while (not 2 < decrypt_exp < shared_key.prime_modulus - 1 or
               decrypt_exp == shared_key.group_base):
          decrypt_exp = base.RandBits(bit_length - 1)
        # make the object
        return cls(
            prime_modulus=shared_key.prime_modulus,
            group_base=shared_key.group_base,
            individual_base=modmath.ModExp(
                shared_key.group_base, decrypt_exp, shared_key.prime_modulus),
            decrypt_exp=decrypt_exp)
      except base.InputError as err:
        failures += 1
        if failures >= _MAX_KEY_GENERATION_FAILURES:
          raise base.CryptoError(f'failed key generation {failures} times') from err
        logging.warning(err)
