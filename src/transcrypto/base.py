#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto base library."""

import abc
import base64
import dataclasses
# import datetime
import functools
import hashlib
import logging
import math
import os.path
# import pdb
import secrets
import time
from typing import Any, Callable, MutableSequence, Protocol, TypeVar, runtime_checkable, final


__author__ = 'balparda@github.com'
__version__ = '1.0.3'  # v1.0.3, 2025-07-30
__version_tuple__: tuple[int, ...] = tuple(int(v) for v in __version__.split('.'))

# MIN_TM = int(  # minimum allowed timestamp
#     datetime.datetime(2000, 1, 1, 0, 0, 0).replace(tzinfo=datetime.timezone.utc).timestamp())

BytesToHex: Callable[[bytes], str] = lambda b: b.hex()
BytesToInt: Callable[[bytes], int] = lambda b: int.from_bytes(b, 'big', signed=False)
BytesToEncoded: Callable[[bytes], str] = lambda b: base64.urlsafe_b64encode(b).decode('ascii')

HexToBytes: Callable[[str], bytes] = lambda h: bytes.fromhex(h)
IntToBytes: Callable[[int], bytes] = lambda i: i.to_bytes(
    (i.bit_length() + 7) // 8, 'big', signed=False)
EncodedToBytes: Callable[[bytes], str] = lambda e: base64.urlsafe_b64decode(e.encode('ascii'))

PadBytesTo: Callable[[bytes, int], bytes] = lambda b, i: b.rjust((i + 7) // 8, b'\x00')


class Error(Exception):
  """TransCrypto exception."""


class InputError(Error):
  """Input exception (TransCrypto)."""


class CryptoError(Error):
  """Cryptographic exception (TransCrypto)."""


def HumanizedBytes(inp_sz: int, /) -> str:  # pylint: disable=too-many-return-statements
  """Convert a byte count into a human-readable string using binary prefixes (powers of 1024).

  Scales the input size by powers of 1024, returning a value with the
  appropriate IEC binary unit suffix: `B`, `KiB`, `MiB`, `GiB`, `TiB`, `PiB`, `EiB`.

  Args:
    inp_sz (int): Size in bytes. Must be a non-negative integer.

  Returns:
    str: Formatted size string with up to two decimal places for units above bytes.

  Raises:
    InputError: If `inp_sz` is negative.

  Notes:
    - Units follow the IEC binary standard where:
        1 KiB = 1024 bytes
        1 MiB = 1024 KiB
        1 GiB = 1024 MiB
        1 TiB = 1024 GiB
        1 PiB = 1024 TiB
        1 EiB = 1024 PiB
    - Values under 1024 bytes are returned as an integer with a space and `B`.

  Examples:
    >>> HumanizedBytes(512)
    '512 B'
    >>> HumanizedBytes(2048)
    '2.00 KiB'
    >>> HumanizedBytes(5 * 1024**3)
    '5.00 GiB'
  """
  if inp_sz < 0:
    raise InputError(f'input should be >=0 and got {inp_sz}')
  if inp_sz < 1024:
    return f'{inp_sz} B'
  if inp_sz < 1024 * 1024:
    return f'{(inp_sz / 1024):0.2f} KiB'
  if inp_sz < 1024 * 1024 * 1024:
    return f'{(inp_sz / (1024 * 1024)):0.2f} MiB'
  if inp_sz < 1024 * 1024 * 1024 * 1024:
    return f'{(inp_sz / (1024 * 1024 * 1024)):0.2f} GiB'
  if inp_sz < 1024 * 1024 * 1024 * 1024 * 1024:
    return f'{(inp_sz / (1024 * 1024 * 1024 * 1024)):0.2f} TiB'
  if inp_sz < 1024 * 1024 * 1024 * 1024 * 1024 * 1024:
    return f'{(inp_sz / (1024 * 1024 * 1024 * 1024 * 1024)):0.2f} PiB'
  return f'{(inp_sz / (1024 * 1024 * 1024 * 1024 * 1024 * 1024)):0.2f} EiB'


def HumanizedDecimal(inp_sz: int | float, unit: str = '', /) -> str:  # pylint: disable=too-many-return-statements
  """Convert a numeric value into a human-readable string using metric prefixes (powers of 1000).

  Scales the input value by powers of 1000, returning a value with the
  appropriate SI metric unit prefix: `k`, `M`, `G`, `T`, `P`, `E`. The caller
  can optionally specify a base unit (e.g., `'Hz'`, `'m'`).

  Args:
    inp_sz (int | float): Quantity to convert. Must be finite and non-negative.
    unit (str, optional): Base unit to append to the result (e.g., `'Hz'`).
        If given, it will be separated by a space for values <1000 and appended
        without a space for scaled values.

  Returns:
    str: Formatted string with up to two decimal places for scaled values
        and up to four decimal places for small floats.

  Raises:
    InputError: If `inp_sz` is negative or not finite.

  Notes:
    - Uses decimal multiples: 1 k = 1000 units.
    - Values <1000 are returned as-is (integer) or with four decimal places (float).
    - Unit string is stripped of surrounding whitespace before use.

  Examples:
    >>> HumanizedDecimal(950)
    '950'
    >>> HumanizedDecimal(1500)
    '1.50 k'
    >>> HumanizedDecimal(1500, ' Hz ')
    '1.50 kHz'
    >>> HumanizedDecimal(0.123456, 'V')
    '0.1235 V'
  """
  if not math.isfinite(inp_sz) or inp_sz < 0:
    raise InputError(f'input should be >=0 and got {inp_sz} / {unit!r}')
  unit = unit.strip()
  if inp_sz < 1000:
    return (f'{inp_sz:0.4f}{" " + unit if unit else ""}' if isinstance(inp_sz, float) else
            f'{inp_sz}{" " + unit if unit else ""}')
  if inp_sz < 1000 * 1000:
    return f'{(inp_sz / 1000):0.2f} k{unit}'
  if inp_sz < 1000 * 1000 * 1000:
    return f'{(inp_sz / (1000 * 1000)):0.2f} M{unit}'
  if inp_sz < 1000 * 1000 * 1000 * 1000:
    return f'{(inp_sz / (1000 * 1000 * 1000)):0.2f} G{unit}'
  if inp_sz < 1000 * 1000 * 1000 * 1000 * 1000:
    return f'{(inp_sz / (1000 * 1000 * 1000 * 1000)):0.2f} T{unit}'
  if inp_sz < 1000 * 1000 * 1000 * 1000 * 1000 * 1000:
    return f'{(inp_sz / (1000 * 1000 * 1000 * 1000 * 1000)):0.2f} P{unit}'
  return f'{(inp_sz / (1000 * 1000 * 1000 * 1000 * 1000 * 1000)):0.2f} E{unit}'


def HumanizedSeconds(inp_secs: int | float, /) -> str:  # pylint: disable=too-many-return-statements
  """Convert a duration in seconds into a human-readable time string.

  Selects the appropriate time unit based on the duration's magnitude:
    - microseconds (`µs`)
    - milliseconds (`ms`)
    - seconds (`s`)
    - minutes (`min`)
    - hours (`h`)
    - days (`d`)

  Args:
    inp_secs (int | float): Time interval in seconds. Must be finite and non-negative.

  Returns:
    str: Human-readable string with the duration and unit. Precision depends
        on the chosen unit:
          - µs / ms: 3 decimal places
          - seconds ≥1: 2 decimal places
          - minutes, hours, days: 2 decimal places

  Raises:
    InputError: If `inp_secs` is negative or not finite.

  Notes:
    - Uses the micro sign (`µ`, U+00B5) for microseconds.
    - Thresholds:
        < 0.001 s → µs
        < 1 s → ms
        < 60 s → seconds
        < 3600 s → minutes
        < 86400 s → hours
        ≥ 86400 s → days

  Examples:
    >>> HumanizedSeconds(0)
    '0.00 s'
    >>> HumanizedSeconds(0.000004)
    '4.000 µs'
    >>> HumanizedSeconds(0.25)
    '250.000 ms'
    >>> HumanizedSeconds(42)
    '42.00 s'
    >>> HumanizedSeconds(3661)
    '1.02 h'
  """
  if not math.isfinite(inp_secs) or inp_secs < 0:
    raise InputError(f'input should be >=0 and got {inp_secs}')
  if inp_secs == 0:
    return '0.00 s'
  inp_secs = float(inp_secs)
  if inp_secs < 0.001:
    return f'{inp_secs * 1000 * 1000:0.3f} µs'
  if inp_secs < 1:
    return f'{inp_secs * 1000:0.3f} ms'
  if inp_secs < 60:
    return f'{inp_secs:0.2f} s'
  if inp_secs < 60 * 60:
    return f'{(inp_secs / 60):0.2f} min'
  if inp_secs < 24 * 60 * 60:
    return f'{(inp_secs / (60 * 60)):0.2f} h'
  return f'{(inp_secs / (24 * 60 * 60)):0.2f} d'


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
  assert min_int <= n <= max_int, 'should never happen: generated number out of range'
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


def RandBytes(n_bytes: int) -> bytes:
  """Crypto-random `n_bytes` bytes. Just plain good quality random bytes.

  Args:
    n_bytes (int): number of bits to produce, > 0

  Returns:
    bytes: random with len()==n_bytes

  Raises:
    InputError: invalid n_bytes
  """
  # test inputs
  if n_bytes < 1:
    raise InputError(f'n_bytes must be ≥ 1: {n_bytes}')
  # return from system call
  b: bytes = secrets.token_bytes(n_bytes)
  assert len(b) == n_bytes, 'should never happen: generated bytes incorrect size'
  return b


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


class Timer:
  """An execution timing class that can be used as both a context manager and a decorator.

  Examples:
  
    # As a context manager
    with Timer('Block timing'):
      time.sleep(1.2)

    # As a decorator
    @Timer('Function timing')
    def slow_function():
      time.sleep(0.8)
      
    # As a regular object
    tm = Timer('Inline timing')
    tm.Start()
    time.sleep(0.1)
    tm.Stop()
    print(tm)

  Attributes:
    label (str): Timer label
    emit_print (bool): If True will print() the timer, else will logging.info() the timer
    start (float | None): Start time
    end (float | None): End time
    elapsed (float | None): Time delta
  """

  def __init__(self, label: str = 'Elapsed time', /, *, emit_print: bool = False) -> None:
    """Initialize the Timer.

    Args:
      label (str, optional): A description or name for the timed block or function

    Raises:
      InputError: empty label
    """
    self.emit_print: bool = emit_print
    self.label: str = label.strip()
    if not self.label:
      raise InputError('Empty label')
    self.start: float | None = None
    self.end: float | None = None
    self.elapsed: float | None = None
    
  def __str__(self) -> str:
    """Current timer value."""
    if self.start is None:
      return f'{self.label}: <UNSTARTED>'
    if self.end is None or self.elapsed is None:
      return f'{self.label}: <PARTIAL> {HumanizedSeconds(time.perf_counter() - self.start)}'
    return f'{self.label}: {HumanizedSeconds(self.elapsed)}'

  def Start(self) -> None:
    """Start the timer."""
    if self.start is not None:
      raise Error('Re-starting timer is forbidden')
    self.start = time.perf_counter()

  def __enter__(self) -> 'Timer':
    """Start the timer when entering the context."""
    self.Start()
    return self

  def Stop(self) -> None:
    """Stop the timer and emit logging.info with timer message."""
    if self.start is None:
      raise Error('Stopping an unstarted timer')
    if self.end is not None or self.elapsed is not None:
      raise Error('Re-stopping timer is forbidden')
    self.end = time.perf_counter()
    self.elapsed = self.end - self.start
    logging.info(str(self))

  def __exit__(
      self, exc_type: type[BaseException] | None,
      exc_val: BaseException | None, exc_tb: Any) -> None:
    """Stop the timer when exiting the context, emit logging.info and optionally print elapsed time.

    Args:
      exc_type (type | None): Exception type, if any.
      exc_val (BaseException | None): Exception value, if any.
      exc_tb (Any): Traceback object, if any.
    """
    self.Stop()
    if self.emit_print:
      print(str(self))

  _F = TypeVar('_F', bound=Callable[..., Any])

  def __call__(self, func: 'Timer._F') -> 'Timer._F':
    """Allow the Timer to be used as a decorator.

    Args:
      func: The function to time.

    Returns:
      The wrapped function with timing behavior.
    """
  
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
      with self.__class__(self.label, emit_print=self.emit_print):
        return func(*args, **kwargs)
  
    return wrapper



@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class CryptoKey:
  """A cryptographic key."""

  def __post_init__(self) -> None:
    """Check data."""


class SymmetricCrypto(abc.ABC):
  """Abstract interface for symmetric encryption.

  Contract:
    - If algorithm accepts a `nonce` or `tag` these have to be handled internally by the
      implementation and appended to the cyphertext.
    - If AEAD is supported, `associated_data` (AAD) must be authenticated. If not supported
      then `associated_data` different from None must raise InputError.

  Args:
    key (bytes): Raw key material appropriate for the algorithm.

  Attributes:
    name (str): Short algorithm name (e.g., 'xor-demo', 'aes-gcm').
    key_size (int): Key length in bytes (informational).

  Notes:
    The interface is deliberately minimal: byte-in / byte-out.
    Metadata like nonce/tag may be:
      - returned alongside ciphertext, or
      - bundled/serialized into `ciphertext` by the implementation.
  """

  @abc.abstractmethod
  def Encrypt(self, plaintext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Encrypt `plaintext` and return `ciphertext`.

    Args:
      plaintext (bytes): Data to encrypt.
      associated_data (bytes, optional): Optional AAD for AEAD modes; must be
          provided again on decrypt

    Returns:
      bytes: Ciphertext; if a nonce/tag is needed for decryption, the implementation
      must encode it within the returned bytes (or document how to retrieve it)

    Raises:
      InputError: invalid inputs
      CryptoError: internal crypto failures
    """

  @abc.abstractmethod
  def Decrypt(self, ciphertext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Decrypt `ciphertext` and return the original `plaintext`.

    Args:
      ciphertext (bytes): Data to decrypt (including any embedded nonce/tag if applicable)
      associated_data (bytes, optional): Optional AAD (must match what was used during encrypt)

    Returns:
      bytes: Decrypted plaintext bytes

    Raises:
      InputError: invalid inputs
      CryptoError: internal crypto failures, authentication failure, key mismatch, etc
    """
