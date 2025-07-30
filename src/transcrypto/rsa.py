#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto RSA (Rivest-Shamir-Adleman) library.

<https://en.wikipedia.org/wiki/RSA_cryptosystem>
"""

import dataclasses
import logging
# import pdb
import secrets
from typing import Self

from . import base
from . import modmath

__author__ = 'balparda@github.com'
__version__: tuple[int, int, int] = base.__version__  # version comes from base!


_SMALL_ENCRYPTION_EXPONENT = 7
_BIG_ENCRYPTION_EXPONENT = 2 ** 16 + 1  # 65537

_MAX_KEY_GENERATION_FAILURES = 15


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class RSAPublicKey(base.CryptoKey):
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
    if self.public_modulus < 6 or modmath.IsPrime(self.public_modulus):
      # only a full factors check can prove modulus is product of only 2 primes, which is impossible
      # to do for large numbers here; the private key checks the relationship though
      raise base.InputError(f'invalid public_modulus: {self}')
    if not 2 < self.encrypt_exp < self.public_modulus or not modmath.IsPrime(self.encrypt_exp):
      # technically, encrypt_exp < phi, but again the private key tests for this explicitly
      raise base.InputError(f'invalid encrypt_exp: {self}')

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
      raise base.InputError(f'invalid message: {message=}')
    # encrypt
    return modmath.ModExp(message, self.encrypt_exp, self.public_modulus)

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
      raise base.InputError(f'invalid keys: {self}')
    if (self.random_key * self.key_inverse) % self.public_modulus != 1:
      raise base.CryptoError(f'inconsistent keys: {self}')

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
      raise base.InputError(f'invalid message: {message=}')
    # encrypt
    return (message * modmath.ModExp(
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
      raise base.CryptoError(f'obfuscated message was not signed: {message=} ; {signature=}')
    # compute signature for original message and check it
    original: int = (signature * self.key_inverse) % self.public_modulus
    if not self.VerifySignature(message, original):
      raise base.CryptoError(f'failed signature recovery: {message=} ; {signature=}')
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
        key_inverse = modmath.ModInv(random_key, key.public_modulus)
      except modmath.ModularDivideError:
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
    if (self.modulus_p < 2 or not modmath.IsPrime(self.modulus_p) or  # pylint: disable=too-many-boolean-expressions
        self.modulus_q < 3 or not modmath.IsPrime(self.modulus_q) or
        self.modulus_q <= self.modulus_p or
        (self.modulus_q - self.modulus_p) < min_prime_distance or
        self.encrypt_exp in (self.modulus_p, self.modulus_q) or
        self.encrypt_exp >= phi or
        self.decrypt_exp in (self.encrypt_exp, self.modulus_p, self.modulus_q, phi)):
      # encrypt_exp has to be less than phi;
      # if p − q < 2*(n**(1/4)) then solving for p and q is trivial
      raise base.InputError(f'invalid modulus_p or modulus_q: {self}')
    min_decrypt_length: int = self.public_modulus.bit_length() // 2 + 1
    if not (2 ** min_decrypt_length) < self.decrypt_exp < self.public_modulus:
      # if decrypt_exp < public_modulus**(1/4)/3, then decrypt_exp can be computed efficiently
      # from public_modulus and encrypt_exp so we make sure it is larger than public_modulus**(1/2)
      raise base.InputError(f'invalid decrypt_exp: {self}')
    if self.modulus_p * self.modulus_q != self.public_modulus:
      raise base.CryptoError(f'inconsistent modulus_p * modulus_q: {self}')
    if (self.encrypt_exp * self.decrypt_exp) % phi != 1:
      raise base.CryptoError(f'inconsistent exponents: {self}')

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
      raise base.InputError(f'invalid message: {message=}')
    # decrypt
    return modmath.ModExp(message, self.decrypt_exp, self.public_modulus)

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
      raise base.InputError(f'invalid bit length: {bit_length=}')
    # generate primes / modulus
    failures: int = 0
    while True:
      try:
        primes: list[int] = [modmath.NBitRandomPrime(bit_length // 2),
                             modmath.NBitRandomPrime(bit_length // 2)]
        modulus: int = primes[0] * primes[1]
        while modulus.bit_length() != bit_length or primes[0] == primes[1]:
          primes.remove(min(primes))
          primes.append(modmath.NBitRandomPrime(
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
            decrypt_exp=modmath.ModInv(prime_exp, phi),
        )
        return obj
      except (base.InputError, modmath.ModularDivideError) as err:
        failures += 1
        if failures >= _MAX_KEY_GENERATION_FAILURES:
          raise base.CryptoError(f'failed key generation {failures} times') from err
        logging.warning(err)
