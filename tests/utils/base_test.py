# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/base.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/base_test.py
"""

from __future__ import annotations

from transcrypto.core import base


def test_bytes_conversions() -> None:
  """Test."""
  bb: bytes = b'xyz'
  assert base.BytesToHex(bb) == '78797a'
  assert base.BytesToInt(bb) == 7895418
  assert base.BytesToEncoded(bb) == 'eHl6'
  assert base.HexToBytes('78797a') == bb
  assert base.IntToBytes(7895418) == bb
  assert base.IntToEncoded(7895418) == 'eHl6'
  assert base.EncodedToBytes('eHl6') == bb
  assert base.PadBytesTo(bb, 8) == bb
  assert base.PadBytesTo(bb, 16) == bb
  assert base.PadBytesTo(bb, 24) == bb
  assert base.PadBytesTo(bb, 32) == b'\x00xyz'
  assert base.PadBytesTo(bb, 40) == b'\x00\x00xyz'
  assert base.PadBytesTo(b'\x01\x00', 40) == b'\x00\x00\x00\x01\x00'
  padded: bytes = base.PadBytesTo(bb, 64)
  assert padded == b'\x00\x00\x00\x00\x00xyz'
  assert base.BytesToHex(padded) == '000000000078797a'
  assert base.BytesToInt(padded) == 7895418
  assert base.BytesToEncoded(padded) == 'AAAAAAB4eXo='  # cspell:disable-line
  assert base.HexToBytes('000000000078797a') == padded
  assert base.EncodedToBytes('AAAAAAB4eXo=') == padded  # cspell:disable-line


def test_BytesToRaw() -> None:
  """Test."""
  assert base.BytesToRaw(b'abcd') == '"abcd"'
  for i in range(256):
    b: bytes = b'ab' + bytes([i]) + b'cd'
    assert base.RawToBytes(base.BytesToRaw(b)) == b
