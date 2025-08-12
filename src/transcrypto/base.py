#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto base library."""

import dataclasses
# import datetime
import hashlib
import logging
import os.path
# import pdb
import secrets
from typing import Any, Callable, MutableSequence

__author__ = 'balparda@github.com'
__version__ = '1.0.3'  # v1.0.3, 2025-07-30
__version_tuple__: tuple[int, ...] = tuple(int(v) for v in __version__.split('.'))

# MIN_TM = int(  # minimum allowed timestamp
#     datetime.datetime(2000, 1, 1, 0, 0, 0).replace(tzinfo=datetime.timezone.utc).timestamp())

BytesToHex: Callable[[bytes], str] = lambda b: b.hex()
BytesToInt: Callable[[bytes], int] = lambda b: int.from_bytes(b, 'big', signed=False)

HexToBytes: Callable[[str], bytes] = lambda h: bytes.fromhex(h)
IntToBytes: Callable[[int], bytes] = lambda i: i.to_bytes(
    (i.bit_length() + 7) // 8, 'big', signed=False)

PadBytesTo: Callable[[bytes, int], bytes] = lambda b, i: b.rjust((i + 7) // 8, b'\x00')


class Error(Exception):
  """TransCrypto exception."""


class InputError(Error):
  """Input exception (TransCrypto)."""


class CryptoError(Error):
  """Cryptographic exception (TransCrypto)."""


def RandBits(n_bits: int) -> int:
  """Crypto-random integer with guaranteed `n_bits` size (i.e., first bit == 1).
  
  The fact that the first bit will be 1 means the entropy is ~ (n_bits-1) and
  because of this we only allow for a byte or more bits generated. This drawback
  is negligible for the large integers a crypto library will work with, in practice.

  Args:
    n_bits (int): number of bits to produce, ≥ 8

  Returns:
    int with n_bits size

  Raises:
    InputError: invalid n_bits
  """
  # test inputs
  if n_bits < 8:
    raise InputError(f'n_bits must be ≥ 8: {n_bits}')
  # call underlying method
  n: int = 0
  while n.bit_length() != n_bits:
    n = secrets.randbits(n_bits)  # we could just set the bit, but IMO it is better to get another
  return n


def RandInt(min_int: int, max_int: int) -> int:
  """Crypto-random integer uniform over [min_int, max_int].

  Args:
    min_int (int): minimum integer, inclusive, ≥ 0
    max_int (int): maximum integer, inclusive, > min_int

  Returns:
    int between [min_int, max_int] inclusive

  Raises:
    InputError: invalid min/max
  """
  # test inputs
  if min_int < 0 or min_int >= max_int:
    raise InputError(f'min_int must be ≥ 0, and < max_int: {min_int} / {max_int}')
  # uniform over [min_int, max_int]
  span: int = max_int - min_int + 1
  n: int = min_int + secrets.randbelow(span)
  assert min_int <= n <= max_int
  return n


def RandShuffle[T: Any](seq: MutableSequence[T]) -> None:
  """In-place Crypto-random shuffle order for `seq` mutable sequence.

  Args:
    seq (MutableSequence[T]): any mutable sequence with 2 or more elements

  Raises:
    InputError: not enough elements
  """
  # test inputs
  if (n_seq := len(seq)) < 2:
    raise InputError(f'seq must have 2 or more elements: {n_seq}')
  # cryptographically sound Fisher–Yates using secrets.randbelow
  for i in range(n_seq - 1, 0, -1):
    j: int = secrets.randbelow(i + 1)
    seq[i], seq[j] = seq[j], seq[i]


def GCD(a: int, b: int, /) -> int:
  """Greatest Common Divisor for `a` and `b`, integers ≥0. Uses the Euclid method.

  O(log(min(a, b)))

  Args:
    a (int): integer a ≥ 0
    b (int): integer b ≥ 0 (can't be both zero)

  Returns:
    gcd(a, b)

  Raises:
    InputError: invalid inputs
  """
  # test inputs
  if a < 0 or b < 0 or (not a and not b):
    raise InputError(f'negative input or undefined gcd(0, 0): {a=} , {b=}')
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
    InputError: invalid inputs
  """
  # test inputs
  if a < 0 or b < 0 or (not a and not b):
    raise InputError(f'negative input or undefined gcd(0, 0): {a=} , {b=}')
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


def Hash256(data: bytes, /) -> bytes:
  """SHA-256 hash of bytes data. Always a length of 32 bytes.

  Args:
    data (bytes): Data to compute hash for

  Returns:
    32 bytes (256 bits) of SHA-256 hash;
    if converted to hexadecimal (with BytesToHex() or hex()) will be 64 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**256
  """
  return hashlib.sha256(data).digest()


def Hash512(data: bytes, /) -> bytes:
  """SHA-512 hash of bytes data. Always a length of 64 bytes.

  Args:
    data (bytes): Data to compute hash for

  Returns:
    64 bytes (512 bits) of SHA-512 hash;
    if converted to hexadecimal (with BytesToHex() or hex()) will be 128 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**512
  """
  return hashlib.sha512(data).digest()


def FileHash(full_path: str, /, *, digest: str = 'sha256') -> bytes:
  """SHA-256 hex hash of file on disk. Always a length of 32 bytes (if default digest=='sha256').

  Args:
    full_path (str): Path to exisiting file on disk
    digest (str, optional): Hash method to use, default is 'sha256'

  Returns:
    32 bytes (256 bits) of SHA-256 hash (if default digest=='sha256');
    if converted to hexadecimal (with BytesToHex() or hex()) will be 64 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**256

  Raises:
    InputError: file could not be found
  """
  # test inputs
  if digest not in ('sha256', 'sha512'):
    raise InputError(f'unrecognized digest: {digest!r}')
  full_path = full_path.strip()
  if not full_path or not os.path.exists(full_path):
    raise InputError(f'file {full_path!r} not found for hashing')
  # compute hash
  logging.info(f'Hashing file {full_path!r}')
  with open(full_path, 'rb') as file_obj:
    return hashlib.file_digest(file_obj, digest).digest()


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class CryptoKey:
  """A cryptographic key."""

  def __post_init__(self) -> None:
    """Check data."""
