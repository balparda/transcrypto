# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto hash utilities library."""

from __future__ import annotations

import enum
import hashlib
import logging
import pathlib

from transcrypto.utils import base


class SHA(enum.Enum):
  """SHA enum."""

  SHA256 = 'sha256'
  SHA512 = 'sha512'


def Hash256(data: bytes) -> bytes:
  """SHA-256 hash of bytes data. Always a length of 32 bytes.

  Args:
    data (bytes): Data to compute hash for

  Returns:
    32 bytes (256 bits) of SHA-256 hash;
    if converted to hexadecimal (with BytesToHex() or hex()) will be 64 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**256

  """
  return hashlib.sha256(data).digest()


def Hash512(data: bytes) -> bytes:
  """SHA-512 hash of bytes data. Always a length of 64 bytes.

  Args:
    data (bytes): Data to compute hash for

  Returns:
    64 bytes (512 bits) of SHA-512 hash;
    if converted to hexadecimal (with BytesToHex() or hex()) will be 128 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**512

  """
  return hashlib.sha512(data).digest()


def FileHash(full_path: str | pathlib.Path, *, digest: SHA = SHA.SHA256) -> bytes:
  """SHA-256 hex hash of file on disk. Always a length of 32 bytes (if default digest==SHA.SHA256).

  Args:
    full_path (str | pathlib.Path): Path to existing file on disk
    digest (SHA, optional): Hash method to use, accepts SHA.SHA256 (default) or SHA.SHA512

  Returns:
    32 bytes (256 bits) of SHA-256 hash (if default digest==SHA.SHA256);
        if converted to hexadecimal (with BytesToHex() or hex()) will be 64 chars of string;
        if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**256

  Raises:
    base.InputError: file could not be found

  """
  # test inputs
  if digest not in {SHA.SHA256, SHA.SHA512}:
    raise base.InputError(f'unrecognized digest: {digest!r}')
  full_path = pathlib.Path(full_path)
  if not full_path.exists():
    raise base.InputError(f'file {str(full_path)!r} not found for hashing')
  # compute hash
  logging.info(f'Hashing file {str(full_path)!r}')
  with full_path.open('rb') as file_obj:
    return hashlib.file_digest(file_obj, digest.value).digest()


def ObfuscateSecret(data: str | bytes | int) -> str:
  """Obfuscate a secret string/key/bytes/int by hashing SHA-512 and only showing the first 4 bytes.

  Always a length of 9 chars, e.g. "aabbccdd…" (always adds '…' at the end).
  Known vulnerability: If the secret is small, can be brute-forced!
  Use only on large (~>64bits) secrets.

  Args:
    data (str | bytes | int): Data to obfuscate

  Returns:
      str: obfuscated string, e.g. "aabbccdd…"

  Raises:
      base.InputError: if the input data type is invalid

  """
  if isinstance(data, str):
    data = data.encode('utf-8')
  elif isinstance(data, int):
    data = base.IntToBytes(data)
  if not isinstance(data, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
    raise base.InputError(f'invalid type for data: {type(data)}')
  return base.BytesToHex(Hash512(data))[:8] + '…'
