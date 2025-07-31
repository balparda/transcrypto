#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto Shamir Shared Secret (SSS) library.

<https://en.wikipedia.org/wiki/Shamir's_secret_sharing>
"""

import dataclasses
import logging
# import pdb
import secrets
from typing import Collection, Generator, Self

from . import base
from . import modmath

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ShamirSharedSecretPublic(base.CryptoKey):
  """Shamir Shared Secret (SSS) public part.

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
        not modmath.IsPrime(self.modulus) or
        self.minimum < 2):
      raise base.InputError(f'invalid modulus or minimum: {self}')

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
        raise base.CryptoError(f'unrecoverable secret: {mess}')
    # do the math
    return modmath.ModLagrangeInterpolate(0, share_points, self.modulus)

  @classmethod
  def Copy(cls, other: 'ShamirSharedSecretPublic', /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key."""
    return cls(minimum=other.minimum, modulus=other.modulus)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ShamirSharedSecretPrivate(ShamirSharedSecretPublic):
  """Shamir Shared Secret (SSS) private keys.

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
        any(not modmath.IsPrime(p) or p.bit_length() != self.modulus.bit_length()
            for p in self.polynomial)):                          # all primes and the right size
      raise base.InputError(f'invalid polynomial: {self}')

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
      raise base.InputError(f'invalid secret: {secret=}')
    if not 1 < share_key < self.modulus:
      if not share_key:  # default is zero, and that means we generate it here
        sr = secrets.SystemRandom()
        share_key = 0
        while not share_key or share_key in self.polynomial:
          share_key = sr.randint(2, self.modulus - 1)
      else:
        raise base.InputError(f'invalid share_key: {secret=}')
    # build object
    return ShamirSharePrivate(
        minimum=self.minimum, modulus=self.modulus,
        share_key=share_key,
        share_value=modmath.ModPolynomial(share_key, [secret] + self.polynomial, self.modulus))

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
      raise base.InputError(f'invalid max_shares: {max_shares=} < {self.minimum=}')
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
      except base.InputError as err:
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
      raise base.InputError(f'at least 2 shares are needed: {minimum_shares=}')
    if bit_length < 10:
      raise base.InputError(f'invalid bit length: {bit_length=}')
    # make the primes
    unique_primes: set[int] = set()
    while len(unique_primes) < minimum_shares:
      unique_primes.add(modmath.NBitRandomPrime(bit_length))
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
  """Shamir Shared Secret (SSS) one share.

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
      raise base.InputError(f'invalid share: {self}')
