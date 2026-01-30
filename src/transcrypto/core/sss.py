# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto Shamir Shared Secret (SSS) library.

<https://en.wikipedia.org/wiki/Shamir's_secret_sharing>
"""

from __future__ import annotations

import dataclasses
import logging
from collections import abc
from typing import Self

from transcrypto.core import aes, hashes, key, modmath
from transcrypto.utils import base, saferandom

# fixed prefixes: do NOT ever change! will break all encryption and signature schemes
_SSS_ENCRYPTION_AAD_PREFIX = b'transcrypto.SSS.Sharing.1.0\x00'


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class ShamirSharedSecretPublic(key.CryptoKey):
  """Shamir Shared Secret (SSS) public part.

  No measures are taken here to prevent timing attacks.
  Malicious share injection is possible! Add MAC or digital signature in hostile settings.

  Attributes:
    minimum (int): minimum shares needed for recovery, ≥ 2
    modulus (int): prime modulus used for share generation, prime, ≥ 2

  """

  minimum: int
  modulus: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    if self.modulus < 2 or not modmath.IsPrime(self.modulus) or self.minimum < 2:  # noqa: PLR2004
      raise base.InputError(f'invalid modulus or minimum: {self}')

  def __str__(self) -> str:
    """Safe string representation of the ShamirSharedSecretPublic.

    Returns:
      string representation of ShamirSharedSecretPublic

    """
    return (
      'ShamirSharedSecretPublic('
      f'bits={self.modulus.bit_length()}, '
      f'minimum={self.minimum}, '
      f'modulus={base.IntToEncoded(self.modulus)})'
    )

  @property
  def modulus_size(self) -> int:
    """Modulus size in bytes. The number of bytes used in MakeDataShares/RecoverData."""
    return (self.modulus.bit_length() + 7) // 8

  def RawRecoverSecret(
    self, shares: abc.Collection[ShamirSharePrivate], /, *, force_recover: bool = False
  ) -> int:
    """Recover the secret from ShamirSharePrivate objects.

    BEWARE: This is raw SSS, no modern message wrapping, padding or validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    This is the information-theoretic SSS but with no authentication or binding between
    share and secret.

    Args:
      shares (Collection[ShamirSharePrivate]): shares to use to recover the secret
      force_recover (bool, optional): if True will try to recover (default: False)

    Returns:
      the integer secret if all shares are correct and in the correct number; if there are
      no "excess" shares, there can be no way to know if the recovered secret is the correct one

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: secret cannot be recovered (number of shares < `minimum`)

    """
    # check that we have enough shares by de-duping them first
    share_points: dict[int, int] = {}
    share_dict: dict[int, ShamirSharePrivate] = {}
    for share in shares:
      k: int = share.share_key % self.modulus
      v: int = share.share_value % self.modulus
      if k in share_points:
        if v != share_points[k]:
          raise base.InputError(
            f'{share} key/value {k}/{v} duplicated with conflicting value in {share_dict[k]}'
          )
        logging.warning(f'{share} key/value {k}/{v} is a duplicate of {share_dict[k]}: DISCARDED')
        continue
      share_points[k] = v
      share_dict[k] = share
    # if we don't have enough shares, complain loudly
    if (given_shares := len(share_points)) < self.minimum:
      mess: str = f'distinct shares {given_shares} < minimum shares {self.minimum}'
      if force_recover and given_shares > 1:
        logging.error(f'recovering secret even though: {mess}')
      else:
        raise key.CryptoError(f'unrecoverable secret: {mess}')
    # do the math
    return modmath.ModLagrangeInterpolate(0, share_points, self.modulus)

  @classmethod
  def Copy(cls, other: ShamirSharedSecretPublic, /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key.

    Args:
        other (ShamirSharedSecretPublic): object to copy from

    Returns:
        Self: a new ShamirSharedSecretPublic

    """
    return cls(minimum=other.minimum, modulus=other.modulus)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class ShamirSharedSecretPrivate(ShamirSharedSecretPublic):
  """Shamir Shared Secret (SSS) private keys.

  No measures are taken here to prevent timing attacks.
  Malicious share injection is possible! Add MAC or digital signature in hostile settings.

  We deliberately choose prime coefficients. This shrinks the key-space and leaks a bit of
  structure. It is "unusual", but with large enough modulus (bit length > ~ 500) it makes no
  difference because there will be plenty entropy in these primes.

  Attributes:
    polynomial (list[int]): prime coefficients for generation poly., each modulus.bit_length() size

  """

  polynomial: list[int]

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    super(ShamirSharedSecretPrivate, self).__post_init__()
    if (
      len(self.polynomial) != self.minimum - 1  # exactly this size
      or len(set(self.polynomial)) != self.minimum - 1  # no duplicate
      or self.modulus in self.polynomial  # different from modulus
      or any(
        not modmath.IsPrime(p) or p.bit_length() != self.modulus.bit_length()
        for p in self.polynomial
      )
    ):  # all primes and the right size
      raise base.InputError(f'invalid polynomial: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the ShamirSharedSecretPrivate.

    Returns:
      string representation of ShamirSharedSecretPrivate without leaking secrets

    """
    return (
      'ShamirSharedSecretPrivate('
      f'{super(ShamirSharedSecretPrivate, self).__str__()}, '
      f'polynomial=[{", ".join(hashes.ObfuscateSecret(i) for i in self.polynomial)}])'
    )

  def RawShare(self, secret: int, /, *, share_key: int = 0) -> ShamirSharePrivate:
    """Make a new ShamirSharePrivate for the `secret`.

    BEWARE: This is raw SSS, no modern message wrapping, padding or validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    This is the information-theoretic SSS but with no authentication or binding between
    share and secret.

    Args:
      secret (int): secret message to encrypt and share, 0 ≤ s < modulus
      share_key (int, optional): if given, a random value to use, 1 ≤ r < modulus;
          else will generate randomly

    Returns:
      ShamirSharePrivate object

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 <= secret < self.modulus:
      raise base.InputError(f'invalid secret: {secret=}')
    if not 1 <= share_key < self.modulus:
      if not share_key:  # default is zero, and that means we generate it here
        share_key = 0
        while not share_key or share_key in self.polynomial or share_key >= self.modulus:
          share_key = saferandom.RandBits(self.modulus.bit_length() - 1)
      else:
        raise base.InputError(f'invalid share_key: {share_key=}')
    # build object
    return ShamirSharePrivate(
      minimum=self.minimum,
      modulus=self.modulus,
      share_key=share_key,
      share_value=modmath.ModPolynomial(share_key, [secret, *self.polynomial], self.modulus),
    )

  def RawShares(self, secret: int, /, *, max_shares: int = 0) -> abc.Generator[ShamirSharePrivate]:
    """Make any number of ShamirSharePrivate for the `secret`.

    BEWARE: This is raw SSS, no modern message wrapping, padding or validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    This is the information-theoretic SSS but with no authentication or binding between
    share and secret.

    Args:
      secret (int): secret message to encrypt and share, 0 ≤ s < modulus
      max_shares (int, optional): if given, number (≥ 2) of shares to generate; else infinite

    Yields:
      ShamirSharePrivate object

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if max_shares and max_shares < self.minimum:
      raise base.InputError(f'invalid max_shares: {max_shares=} < {self.minimum=}')
    # generate shares
    count: int = 0
    used_keys: set[int] = set()
    while not max_shares or count < max_shares:
      share_key: int = 0
      while (
        not share_key
        or share_key in self.polynomial
        or share_key in used_keys
        or share_key >= self.modulus
      ):
        share_key = saferandom.RandBits(self.modulus.bit_length() - 1)
      try:
        yield self.RawShare(secret, share_key=share_key)
        used_keys.add(share_key)
        count += 1
      except base.InputError as err:
        # it could happen, for example, that the share_key will generate a value of 0
        logging.warning(err)

  def MakeDataShares(self, secret: bytes, total_shares: int, /) -> list[ShamirShareData]:
    """Make `total_shares` ShamirShareData objects with encrypted `secret`.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes
    • r = random 32 bytes
    • shares = SSS.Shares(r, total_shares)
    • ct = AES-256-GCM(key=SHA512("prefix" + r)[32:], plaintext=secret,
                       associated_data="prefix" + minimum + modulus)
    • return [share + ct for share in shares]

    Args:
      secret (bytes): Data to encrypt and distribute (encrypted) in each share.
      total_shares (int): Number of shares to make, ≥ minimum

    Returns:
      list[ShamirShareData]: the list of shares with encrypted data

    Raises:
      base.InputError: invalid inputs

    """
    if total_shares < self.minimum:
      raise base.InputError(f'invalid total_shares: {total_shares=} < {self.minimum=}')
    k: int = self.modulus_size
    if k <= 32:  # noqa: PLR2004
      raise base.InputError(f'modulus too small for key operations: {k} bytes')
    key256: bytes = saferandom.RandBytes(32)
    shares: list[ShamirSharePrivate] = list(
      self.RawShares(base.BytesToInt(key256), max_shares=total_shares)
    )
    aad: bytes = (
      _SSS_ENCRYPTION_AAD_PREFIX
      + base.IntToFixedBytes(self.minimum, 8)
      + base.IntToFixedBytes(self.modulus, k)
    )
    aead_key: bytes = hashes.Hash512(_SSS_ENCRYPTION_AAD_PREFIX + key256)
    ct: bytes = aes.AESKey(key256=aead_key[32:]).Encrypt(secret, associated_data=aad)
    return [
      ShamirShareData(
        minimum=s.minimum,
        modulus=s.modulus,
        share_key=s.share_key,
        share_value=s.share_value,
        encrypted_data=ct,
      )
      for s in shares
    ]

  def RawVerifyShare(self, secret: int, share: ShamirSharePrivate, /) -> bool:
    """Verify a ShamirSharePrivate object for the `secret`.

    BEWARE: This is raw SSS, no modern message wrapping, padding or validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    This is the information-theoretic SSS but with no authentication or binding between
    share and secret.

    Args:
      secret (int): secret message to encrypt and share, 0 ≤ s < modulus
      share (ShamirSharePrivate): share to verify

    Returns:
      True if share is valid; False otherwise

    """
    return share == self.RawShare(secret, share_key=share.share_key)

  @classmethod
  def New(cls, minimum_shares: int, bit_length: int, /) -> Self:
    """Make a new private SSS object of `bit_length` bits prime modulus and coefficients.

    Args:
      minimum_shares (int): minimum shares needed for recovery, ≥ 2
      bit_length (int): number of bits in the primes, ≥ 10

    Returns:
      ShamirSharedSecretPrivate object ready for use

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if minimum_shares < 2:  # noqa: PLR2004
      raise base.InputError(f'at least 2 shares are needed: {minimum_shares=}')
    if bit_length < 10:  # noqa: PLR2004
      raise base.InputError(f'invalid bit length: {bit_length=}')
    # make the primes
    unique_primes: set[int] = modmath.NBitRandomPrimes(bit_length, n_primes=minimum_shares)
    # get the largest prime for the modulus
    ordered_primes: list[int] = list(unique_primes)
    modulus: int = max(ordered_primes)
    ordered_primes.remove(modulus)
    # make polynomial be a random order
    saferandom.RandShuffle(ordered_primes)
    # build object
    return cls(minimum=minimum_shares, modulus=modulus, polynomial=ordered_primes)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class ShamirSharePrivate(ShamirSharedSecretPublic):
  """Shamir Shared Secret (SSS) one share.

  No measures are taken here to prevent timing attacks.
  Malicious share injection is possible! Add MAC or digital signature in hostile settings.

  Attributes:
    share_key (int): share secret key; a randomly picked value, 1 ≤ k < modulus
    share_value (int): share secret value, 1 ≤ v < modulus; (k, v) is a "point" of f(k)=v

  """

  share_key: int
  share_value: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    super(ShamirSharePrivate, self).__post_init__()
    if not 0 < self.share_key < self.modulus or not 0 < self.share_value < self.modulus:
      raise base.InputError(f'invalid share: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the ShamirSharePrivate.

    Returns:
      string representation of ShamirSharePrivate without leaking secrets

    """
    return (
      'ShamirSharePrivate('
      f'{super(ShamirSharePrivate, self).__str__()}, '
      f'share_key={hashes.ObfuscateSecret(self.share_key)}, '
      f'share_value={hashes.ObfuscateSecret(self.share_value)})'
    )

  @classmethod
  def CopyShare(cls, other: ShamirSharePrivate, /) -> Self:
    """Initialize a share taking the parts of another share.

    Args:
        other (ShamirSharePrivate): object to copy from

    Returns:
        Self: a new ShamirSharePrivate

    """
    return cls(
      minimum=other.minimum,
      modulus=other.modulus,
      share_key=other.share_key,
      share_value=other.share_value,
    )


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class ShamirShareData(ShamirSharePrivate):
  """Shamir Shared Secret (SSS) one share.

  No measures are taken here to prevent timing attacks.
  Malicious share injection is possible! Add MAC or digital signature in hostile settings.

  Attributes:
    share_key (int): share secret key; a randomly picked value, 1 ≤ k < modulus
    share_value (int): share secret value, 1 ≤ v < modulus; (k, v) is a "point" of f(k)=v
    encrypted_data (bytes): AES-256-GCM encrypted secret data with IV and tag

  """

  encrypted_data: bytes

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    super(ShamirShareData, self).__post_init__()
    if len(self.encrypted_data) < 32:  # noqa: PLR2004
      raise base.InputError(f'AES256+GCM SSS should have ≥32 bytes IV/CT/tag: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the ShamirShareData.

    Returns:
      string representation of ShamirShareData without leaking secrets

    """
    return (
      'ShamirShareData('
      f'{super(ShamirShareData, self).__str__()}, '
      f'encrypted_data={hashes.ObfuscateSecret(self.encrypted_data)})'
    )

  def RecoverData(self, other_shares: list[ShamirSharePrivate]) -> bytes:
    """Recover the encrypted data from ShamirSharePrivate objects.

    * key256 = SSS.RecoverSecret([this] + other_shares)
    * return AES-256-GCM(key=SHA512("prefix" + key256)[32:], ciphertext=encrypted_data,
                         associated_data="prefix" + minimum + modulus)

    Args:
      other_shares (list[ShamirSharePrivate]): Other shares to use to recover the secret

    Returns:
      bytes: Decrypted plaintext bytes

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: internal crypto failures, authentication failure, key mismatch, etc

    """
    k: int = self.modulus_size
    if k <= 32:  # noqa: PLR2004
      raise base.InputError(f'modulus too small for key operations: {k} bytes')
    # recover secret; raise if shares are invalid
    secret: int = self.RawRecoverSecret([self, *other_shares])
    if not 0 <= secret < (1 << 256):
      raise key.CryptoError('recovered key out of range for 256-bit key')
    key256: bytes = base.IntToFixedBytes(secret, 32)
    aad: bytes = (
      _SSS_ENCRYPTION_AAD_PREFIX
      + base.IntToFixedBytes(self.minimum, 8)
      + base.IntToFixedBytes(self.modulus, k)
    )
    aead_key: bytes = hashes.Hash512(_SSS_ENCRYPTION_AAD_PREFIX + key256)
    return aes.AESKey(key256=aead_key[32:]).Decrypt(self.encrypted_data, associated_data=aad)
