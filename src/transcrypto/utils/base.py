# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto base library."""

from __future__ import annotations

import base64
import codecs
from collections import abc

# Data conversion utils

# JSON types
type JSONValue = bool | int | float | str | list[JSONValue] | dict[str, JSONValue] | None
type JSONDict = dict[str, JSONValue]

BytesToHex: abc.Callable[[bytes], str] = lambda b: b.hex()
BytesToInt: abc.Callable[[bytes], int] = lambda b: int.from_bytes(b, 'big', signed=False)
BytesToEncoded: abc.Callable[[bytes], str] = lambda b: base64.urlsafe_b64encode(b).decode('ascii')

HexToBytes: abc.Callable[[str], bytes] = bytes.fromhex
IntToFixedBytes: abc.Callable[[int, int], bytes] = lambda i, n: i.to_bytes(n, 'big', signed=False)
IntToBytes: abc.Callable[[int], bytes] = lambda i: IntToFixedBytes(i, (i.bit_length() + 7) // 8)
IntToEncoded: abc.Callable[[int], str] = lambda i: BytesToEncoded(IntToBytes(i))
EncodedToBytes: abc.Callable[[str], bytes] = lambda e: base64.urlsafe_b64decode(e.encode('ascii'))

PadBytesTo: abc.Callable[[bytes, int], bytes] = lambda b, i: b.rjust((i + 7) // 8, b'\x00')


class Error(Exception):
  """TransCrypto exception."""


class InputError(Error):
  """Input exception (TransCrypto)."""


class ImplementationError(Error, NotImplementedError):
  """Feature is not implemented yet (TransCrypto)."""


def BytesToRaw(b: bytes, /) -> str:
  r"""Convert bytes to double-quoted string with \\xNN escapes where needed.

  1. map bytes 0..255 to same code points (latin1)
  2. escape non-printables/backslash/quotes via unicode_escape

  Args:
    b (bytes): input

  Returns:
    str: double-quoted string with \\xNN escapes where needed

  """
  inner: str = b.decode('latin1').encode('unicode_escape').decode('ascii')
  return f'"{inner.replace('"', r"\"")}"'


def RawToBytes(s: str, /) -> bytes:
  r"""Convert double-quoted string with \\xNN escapes where needed to bytes.

  Args:
    s (str): input (expects a double-quoted string; parses \\xNN, \n, \\ etc)

  Returns:
    bytes: data

  """
  if len(s) >= 2 and s[0] == s[-1] == '"':  # noqa: PLR2004
    s = s[1:-1]
  # decode backslash escapes to code points, then map 0..255 -> bytes
  return codecs.decode(s, 'unicode_escape').encode('latin1')
