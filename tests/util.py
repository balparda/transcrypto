# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Unit test util methods."""

from transcrypto import aes, base


def TestCryptoKeyEncoding(obj: base.CryptoKey, tp: type[base.CryptoKey]) -> None:
  """Test encoding for a CryptoKey instance. Only for use from test modules."""
  assert tp.FromJSON(obj.json) == obj
  assert tp.FromJSON(obj.formatted_json) == obj
  assert tp.Load(obj.blob) == obj
  assert tp.Load(obj.encoded) == obj
  assert tp.Load(obj.hex) == obj
  assert tp.Load(obj.raw) == obj
  key = aes.AESKey(key256=b'x' * 32)
  assert tp.Load(obj.Blob(key=key), key=key) == obj
  assert tp.Load(obj.Encoded(key=key), key=key) == obj
  assert tp.Load(obj.Hex(key=key), key=key) == obj
  assert tp.Load(obj.Raw(key=key), key=key) == obj
