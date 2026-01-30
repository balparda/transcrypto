# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto hash utilities library."""

from __future__ import annotations

import hashlib
import logging
import pathlib

from transcrypto.utils import base


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
    full_path (str): Path to existing file on disk
    digest (str, optional): Hash method to use, accepts 'sha256' (default) or 'sha512'

  Returns:
    32 bytes (256 bits) of SHA-256 hash (if default digest=='sha256');
    if converted to hexadecimal (with BytesToHex() or hex()) will be 64 chars of string;
    if converted to int (big-endian, unsigned, with BytesToInt()) will be 0 ≤ i < 2**256

  Raises:
    base.InputError: file could not be found

  """
  # test inputs
  digest = digest.lower().strip().replace('-', '')  # normalize so we can accept e.g. "SHA-256"
  if digest not in {'sha256', 'sha512'}:
    raise base.InputError(f'unrecognized digest: {digest!r}')
  full_path = full_path.strip()
  if not full_path or not pathlib.Path(full_path).exists():
    raise base.InputError(f'file {full_path!r} not found for hashing')
  # compute hash
  logging.info(f'Hashing file {full_path!r}')
  with pathlib.Path(full_path).open('rb') as file_obj:
    return hashlib.file_digest(file_obj, digest).digest()


def ObfuscateSecret(data: str | bytes | int, /) -> str:
  """Obfuscate a secret string/key/bytes/int by hashing SHA-512 and only showing the first 4 bytes.

  Always a length of 9 chars, e.g. "aabbccdd…" (always adds '…' at the end).
  Known vulnerability: If the secret is small, can be brute-forced!
  Use only on large (~>64bits) secrets.

  Args:
    data (str | bytes | int): Data to obfuscate

  Raises:
      base.InputError: _description_

  Returns:
      str: obfuscated string, e.g. "aabbccdd…"

  """
  if isinstance(data, str):
    data = data.encode('utf-8')
  elif isinstance(data, int):
    data = base.IntToBytes(data)
  if not isinstance(data, bytes):  # pyright: ignore[reportUnnecessaryIsInstance]
    raise base.InputError(f'invalid type for data: {type(data)}')
  return base.BytesToHex(Hash512(data))[:8] + '…'
