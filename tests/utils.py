#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""utils.py unittest utilities."""

from src.transcrypto import base, aes


def TestCryptoKeyEncoding(obj: base.CryptoKey, tp: type[base.CryptoKey]) -> None:
  """Test encoding for a CryptoKey instance."""
  assert tp.FromJSON(obj.json) == obj
  assert tp.FromJSON(obj.formatted_json) == obj
  assert tp.Load(obj.blob) == obj
  assert tp.Load(obj.encoded) == obj
  key = aes.AESKey(key256=b'x' * 32)
  assert tp.Load(obj.Blob(key=key), key=key) == obj
  assert tp.Load(obj.Encoded(key=key), key=key) == obj
