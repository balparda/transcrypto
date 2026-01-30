# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Unit test util methods."""

from transcrypto.core import aes, key


def TestCryptoKeyEncoding(obj: key.CryptoKey, tp: type[key.CryptoKey]) -> None:
  """Test encoding for a CryptoKey instance. Only for use from test modules."""
  assert tp.FromJSON(obj.json) == obj
  assert tp.FromJSON(obj.formatted_json) == obj
  assert tp.Load(obj.blob) == obj
  assert tp.Load(obj.encoded) == obj
  assert tp.Load(obj.hex) == obj
  assert tp.Load(obj.raw) == obj
  aes_key = aes.AESKey(key256=b'x' * 32)
  assert tp.Load(obj.Blob(encryption_key=aes_key), decryption_key=aes_key) == obj
  assert tp.Load(obj.Encoded(encryption_key=aes_key), decryption_key=aes_key) == obj
  assert tp.Load(obj.Hex(encryption_key=aes_key), decryption_key=aes_key) == obj
  assert tp.Load(obj.Raw(encryption_key=aes_key), decryption_key=aes_key) == obj
