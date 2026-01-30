# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto bidding protocols."""

from __future__ import annotations

import dataclasses
from typing import Self

from transcrypto.core import hashes, key
from transcrypto.utils import base, saferandom


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class PublicBid512(key.CryptoKey):
  """Public commitment to a (cryptographically secure) bid that can be revealed/validated later.

  Bid is computed as: public_hash = Hash512(public_key || private_key || secret_bid)

  Everything is bytes. The public part is (public_key, public_hash) and the private
  part is (private_key, secret_bid). The whole computation can be checked later.

  No measures are taken here to prevent timing attacks (probably not a concern).

  Attributes:
    public_key (bytes): 512-bits random value
    public_hash (bytes): SHA-512 hash of (public_key || private_key || secret_bid)

  """

  public_key: bytes
  public_hash: bytes

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    if len(self.public_key) != 64 or len(self.public_hash) != 64:  # noqa: PLR2004
      raise base.InputError(f'invalid public_key or public_hash: {self}')

  def __str__(self) -> str:
    """Safe string representation of the PublicBid.

    Returns:
      string representation of PublicBid

    """
    return (
      'PublicBid512('
      f'public_key={base.BytesToEncoded(self.public_key)}, '
      f'public_hash={base.BytesToHex(self.public_hash)})'
    )

  def VerifyBid(self, private_key: bytes, secret: bytes, /) -> bool:
    """Verify a bid. True if OK; False if failed verification.

    Args:
      private_key (bytes): 512-bits private key
      secret (bytes): Any number of bytes (≥1) to bid on (e.g., UTF-8 encoded string)

    Returns:
      True if bid is valid, False otherwise

    """
    try:
      # creating the PrivateBid object will validate everything; InputError we allow to propagate
      PrivateBid512(
        public_key=self.public_key,
        public_hash=self.public_hash,
        private_key=private_key,
        secret_bid=secret,
      )
      return True  # if we got here, all is good
    except key.CryptoError:
      return False  # bid does not match the public commitment

  @classmethod
  def Copy(cls, other: PublicBid512, /) -> Self:
    """Initialize a public bid by taking the public parts of a public/private bid.

    Args:
        other (PublicBid512): the bid to copy from

    Returns:
        Self: an initialized PublicBid512

    """
    return cls(public_key=other.public_key, public_hash=other.public_hash)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class PrivateBid512(PublicBid512):
  """Private bid that can be revealed and validated against a public commitment (see PublicBid).

  Attributes:
    private_key (bytes): 512-bits random value
    secret_bid (bytes): Any number of bytes (≥1) to bid on (e.g., UTF-8 encoded string)

  """

  private_key: bytes
  secret_bid: bytes

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: bid does not match the public commitment

    """
    super(PrivateBid512, self).__post_init__()
    if len(self.private_key) != 64 or len(self.secret_bid) < 1:  # noqa: PLR2004
      raise base.InputError(f'invalid private_key or secret_bid: {self}')
    if self.public_hash != hashes.Hash512(self.public_key + self.private_key + self.secret_bid):
      raise key.CryptoError(f'inconsistent bid: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the PrivateBid.

    Returns:
      string representation of PrivateBid without leaking secrets

    """
    return (
      'PrivateBid512('
      f'{super(PrivateBid512, self).__str__()}, '
      f'private_key={hashes.ObfuscateSecret(self.private_key)}, '
      f'secret_bid={hashes.ObfuscateSecret(self.secret_bid)})'
    )

  @classmethod
  def New(cls, secret: bytes, /) -> Self:
    """Make the `secret` into a new bid.

    Args:
      secret (bytes): Any number of bytes (≥1) to bid on (e.g., UTF-8 encoded string)

    Returns:
      PrivateBid object ready for use (use PublicBid.Copy() to get the public part)

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if len(secret) < 1:
      raise base.InputError(f'invalid secret length: {len(secret)}')
    # generate random values
    public_key: bytes = saferandom.RandBytes(64)  # 512 bits
    private_key: bytes = saferandom.RandBytes(64)  # 512 bits
    # build object
    return cls(
      public_key=public_key,
      public_hash=hashes.Hash512(public_key + private_key + secret),
      private_key=private_key,
      secret_bid=secret,
    )
