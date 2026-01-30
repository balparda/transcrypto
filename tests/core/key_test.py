# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""core/key.py unittest.

Run with:
  poetry run pytest -vvv tests/core/key_test.py
"""

from __future__ import annotations

import dataclasses
import io
import json
import pathlib
import sys

import pytest
import typeguard
import zstandard

from transcrypto.core import aes, hashes, key
from transcrypto.utils import base


@pytest.mark.parametrize(
  ('inp', 'tp'),
  [
    ('', None),
    ('sss', None),
    ('@xxx', key.CryptoInputType.PATH),
    ('@-', key.CryptoInputType.STDIN),
    ('hex:aaaa', key.CryptoInputType.HEX),
    ('b64:eHl6', key.CryptoInputType.BASE64),
    ('str:sss', key.CryptoInputType.STR),
    ('raw:"rr\\x00r"', key.CryptoInputType.RAW),
  ],
)
def test_DetectInputType(inp: str, tp: key.CryptoInputType | None) -> None:
  """Test."""
  assert key.DetectInputType(inp) == tp


@pytest.mark.parametrize(
  ('inp', 'exp', 'b'),
  [
    # hex
    ('hex:aaaa', None, b'\xaa\xaa'),
    ('hex:aaaa', key.CryptoInputType.HEX, b'\xaa\xaa'),
    ('aaaa', key.CryptoInputType.HEX, b'\xaa\xaa'),
    # encoded
    ('b64:eHl6', None, b'xyz'),
    ('b64:eHl6', key.CryptoInputType.BASE64, b'xyz'),
    ('eHl6', key.CryptoInputType.BASE64, b'xyz'),
    # str
    ('str:sss', None, b'sss'),
    ('str:sss', key.CryptoInputType.STR, b'sss'),
    ('sss', key.CryptoInputType.STR, b'sss'),
    ('sss', None, b'sss'),  # the default when nothing is said
    # raw
    ('raw:"rr\\x00r"', None, b'rr\x00r'),
    ('raw:"rr\\x00r"', key.CryptoInputType.RAW, b'rr\x00r'),
    ('"rr\\x00r"', key.CryptoInputType.RAW, b'rr\x00r'),
  ],
)
def test_BytesFromInput(inp: str, exp: key.CryptoInputType | None, b: bytes) -> None:
  """Test."""
  assert key.BytesFromInput(inp, expect=exp) == b


@pytest.mark.parametrize(
  ('inp', 'exp', 'm'),
  [
    ('@-', key.CryptoInputType.HEX, r'Expected type.*is different from detected type'),
    ('@xxx', key.CryptoInputType.HEX, r'Expected type.*is different from detected type'),
    # hex
    ('hex:aaa', None, r'fromhex\(\) arg'),
    ('aaa', key.CryptoInputType.HEX, r'fromhex\(\) arg'),
    ('str:aaaa', key.CryptoInputType.HEX, r'Expected type.*is different from detected type'),
    # encoded
    ('b64:e^%Hll6', None, 'Invalid base64-encoded string'),
    ('e^%Hll6', key.CryptoInputType.BASE64, 'Invalid base64-encoded string'),
    ('hex:eHl6', key.CryptoInputType.BASE64, r'Expected type.*is different from detected type'),
    # str
    ('hex:sss', key.CryptoInputType.STR, r'Expected type.*is different from detected type'),
    # raw
    (r'raw:\u20ac', None, "invalid input: 'latin-1' codec can't encode"),
    (r'\u20ac', key.CryptoInputType.RAW, "invalid input: 'latin-1' codec can't encode"),
    ('hex:"rr\\x00r"', key.CryptoInputType.RAW, r'Expected type.*is different from detected type'),
  ],
)
def test_BytesFromInput_invalid(inp: str, exp: key.CryptoInputType | None, m: str) -> None:
  """Test."""
  with pytest.raises(base.InputError, match=m):
    key.BytesFromInput(inp, expect=exp)


def test_BytesFromInput_type() -> None:
  """Test."""
  with (
    typeguard.suppress_type_checks(),
    pytest.raises(base.InputError, match="invalid input: invalid type 'inv:'"),
  ):
    key.BytesFromInput('sss', expect='inv:')  # type:ignore


def test_BytesFromInput_path(tmp_path: pathlib.Path) -> None:
  """Test."""
  inp_path: str = str(tmp_path / 'blob.bin')
  data = b'rr\x00r'
  pathlib.Path(inp_path).write_bytes(data)
  assert key.BytesFromInput('@' + inp_path) == data
  assert key.BytesFromInput('@' + inp_path, expect=key.CryptoInputType.PATH) == data
  assert key.BytesFromInput(inp_path, expect=key.CryptoInputType.PATH) == data
  with pytest.raises(base.InputError, match='invalid input: cannot find file'):
    key.BytesFromInput('@' + inp_path + 'xxx')


def test_BytesFromInput_stdin_binary(monkeypatch: pytest.MonkeyPatch) -> None:
  """Reading from stdin.buffer (binary)."""

  class _FakeStdin:
    def __init__(self, b: bytes) -> None:
      self.buffer = io.BytesIO(b)

  data = b'rr\x00r'
  fake = _FakeStdin(data)
  monkeypatch.setattr(sys, 'stdin', fake)
  # Using explicit @- prefix
  assert key.BytesFromInput('@-') == data
  # Using expect=STDIN without the prefix should also read from stdin
  monkeypatch.setattr(sys, 'stdin', _FakeStdin(data))
  assert key.BytesFromInput('', expect=key.CryptoInputType.STDIN) == data


def test_BytesFromInput_stdin_text(monkeypatch: pytest.MonkeyPatch) -> None:
  """Reading from text-mode stdin (no .buffer)."""
  # Contains a non-ASCII character to ensure UTF-8 path is used
  text = 'hé\n'
  monkeypatch.setattr(sys, 'stdin', io.StringIO(text))
  # With @- prefix
  assert key.BytesFromInput('@-') == text.encode('utf-8')
  # With expect=STDIN and no prefix
  monkeypatch.setattr(sys, 'stdin', io.StringIO(text))
  assert key.BytesFromInput('', expect=key.CryptoInputType.STDIN) == text.encode('utf-8')


def test_stdin_non_text_data_text_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
  """If sys.stdin.read() returns non-str, raise."""

  class _FakeStdin:
    def read(self) -> bytes:  # noqa: PLR6301
      return b'not-a-str'  # wrong type

  monkeypatch.setattr(sys, 'stdin', _FakeStdin())
  with (
    typeguard.suppress_type_checks(),
    pytest.raises(base.InputError, match=r'invalid input: sys.stdin.read.*produced non-text data'),
  ):
    key.BytesFromInput('@-')


def test_stdin_non_text_data_binary(monkeypatch: pytest.MonkeyPatch) -> None:
  """If sys.stdin.buffer.read() returns non-bytes, raise."""

  class _FakeBuffer:
    def read(self) -> str:  # noqa: PLR6301
      return 'not-bytes'  # wrong type

  class _FakeStdin:
    def __init__(self) -> None:
      self.buffer = _FakeBuffer()

  monkeypatch.setattr(sys, 'stdin', _FakeStdin())
  with (
    typeguard.suppress_type_checks(),
    pytest.raises(
      base.InputError, match=r'invalid input: sys.stdin.buffer.read.*produced non-binary data'
    ),
  ):
    key.BytesFromInput('@-')


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class _ToyCrypto1(key.CryptoKey):
  """Toy class 1."""

  key: bytes
  secret: str
  modulus: int

  def __post_init__(self) -> None:
    pass

  def __str__(self) -> str:
    return (
      f'_ToyCrypto(key={hashes.ObfuscateSecret(self.key)}, '
      f'secret={hashes.ObfuscateSecret(self.secret)}, '
      f'modulus={hashes.ObfuscateSecret(self.modulus)})'
    )


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class _ToyCrypto2(key.CryptoKey):
  """Toy class 2."""

  key: bytes
  secret: str
  modulus: int
  poly1: list[int]
  poly2: list[str]
  is_x: bool

  def __post_init__(self) -> None:
    pass

  def __str__(self) -> str:
    return ''


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class _ToyCrypto3(key.CryptoKey):
  """Toy class 3."""

  modulus: int
  inv: dict[str, str]

  def __post_init__(self) -> None:
    pass

  def __str__(self) -> str:
    return ''


def test_CryptoKey_base() -> None:
  """Test."""
  crypto = _ToyCrypto1(key=b'abc', secret='cba', modulus=123)  # noqa: S106
  aes_key = aes.AESKey(key256=b'x' * 32)
  assert str(crypto) == '_ToyCrypto(key=ddaf35a1…, secret=3b1d17bf…, modulus=c2d03c6e…)'
  assert str(crypto) == repr(crypto)
  assert crypto._DebugDump() == "_ToyCrypto1(key=b'abc', secret='cba', modulus=123)"
  assert crypto.blob == b'(\xb5/\xfd +Y\x01\x00{"key":"YWJj","secret":"cba","modulus":123}'
  assert crypto.blob == crypto.Blob()  # Blob() with no options should be the same as blob
  assert crypto.encoded == crypto.Encoded()  # Encoded() with no options should be same as encoded
  assert _ToyCrypto1.Load(crypto.blob) == crypto
  assert (
    crypto.encoded
    == (
      'b64:KLUv_SArWQEAeyJrZXkiOiJZV0pqIiwic2VjcmV0IjoiY2JhIiwibW9kdWx1cyI6MTIzfQ=='  # cspell:disable-line
    )
  )
  assert crypto.hex == (
    'hex:28b52ffd202b5901007b226b6579223a2259574a6a222c22736563726574223a22636'
    '261222c226d6f64756c7573223a3132337d'
  )
  assert crypto.raw == (
    'raw:"(\\xb5/\\xfd +Y\\x01\\x00{\\"key\\":\\"YWJj\\",\\"secret\\":\\"cba\\",\\"modulus\\":123}"'
  )
  assert _ToyCrypto1.Load(crypto.encoded) == crypto
  blob_crypto: bytes = crypto.Blob(encryption_key=aes_key)
  assert _ToyCrypto1.Load(blob_crypto, decryption_key=aes_key) == crypto
  encoded_crypto: str = crypto.Encoded(encryption_key=aes_key)
  assert _ToyCrypto1.Load(encoded_crypto, decryption_key=aes_key) == crypto
  crypto2 = _ToyCrypto2(
    key=b'ijk5845976584',
    secret='abc',  # noqa: S106
    modulus=123,
    poly1=[13, 17, 19],
    poly2=['xz', 'yz'],
    is_x=True,
  )
  assert crypto2._json_dict == {
    'is_x': True,
    'key': 'aWprNTg0NTk3NjU4NA==',
    'modulus': 123,
    'poly1': [13, 17, 19],
    'poly2': ['xz', 'yz'],
    'secret': 'abc',
  }
  with typeguard.suppress_type_checks():
    with pytest.raises(base.InputError, match=r'input decode error.*invalid start byte'):
      _ToyCrypto1.Load(key.Serialize(crypto2._json_dict, compress=None))  # binary is a dict
    with pytest.raises(base.InputError, match='decoded to unexpected fields'):
      _ToyCrypto1.Load(
        key.Serialize(crypto2._json_dict, compress=None, pickler=key.PickleJSON)
      )  # binary is a dict
    with pytest.raises(base.InputError, match='JSON data decoded to unexpected type'):
      _ToyCrypto1.FromJSON(json.dumps([1, 2]))
  with pytest.raises(base.ImplementationError, match='Unsupported JSON field'):
    _ = _ToyCrypto3(modulus=10, inv={'a': 'b'}).json
  with pytest.raises(base.ImplementationError, match='Unsupported JSON field'):
    _ToyCrypto3._FromJSONDict({'modulus': 34, 'inv': {'a': 'b'}})
  assert crypto2.json == (
    '{"key":"aWprNTg0NTk3NjU4NA==","secret":"abc","modulus":123,'
    '"poly1":[13,17,19],"poly2":["xz","yz"],"is_x":true}'
  )
  assert (
    crypto2.formatted_json
    == """\
{
    "is_x": true,
    "key": "aWprNTg0NTk3NjU4NA==",
    "modulus": 123,
    "poly1": [
        13,
        17,
        19
    ],
    "poly2": [
        "xz",
        "yz"
    ],
    "secret": "abc"
}"""
  )
  assert crypto2.encoded == (
    'b64:KLUv_SBucQMAeyJrZXkiOiJhV3ByTlRnME5UazNOalU0TkE9PSIsInNlY3JldCI6ImFiYyIs'
    'Im1vZHVsdXMiOjEyMywicG9seTEiOlsxMywxNywxOV0sInBvbHkyIjpbInh6IiwieXoiXSwiaXNfeCI6dHJ1ZX0='
  )


@pytest.fixture
def sample_obj() -> key.CryptDict:
  """Sample object fixture.

  Returns:
      key.CryptDict: sample object

  """
  # moderately nested object to exercise pickle well
  return {
    'nums': list(range(50)),
    'nested': {'a': 1, 'b': b'bytes', 'c': None},
    'text': 'zstd 🍰 compression test',
  }


def test_serialize_deserialize_no_compress_no_encrypt(sample_obj: key.CryptDict) -> None:
  """Test."""
  blob: bytes = key.Serialize(sample_obj, compress=None)
  # should NOT look like zstd: DeSerialize should skip decompression path
  obj2: key.CryptDict = key.DeSerialize(data=blob)
  assert obj2 == sample_obj


def test_serialize_deserialize_with_compress_negative_clamped(sample_obj: key.CryptDict) -> None:
  """Test."""
  # request a very fast negative level; function clamps to >= -22 then compresses
  blob: bytes = key.Serialize(sample_obj, compress=-100)  # expect clamp to -22 internally
  # Verify magic-detected zstd path and successful round-trip
  obj2: key.CryptDict = key.DeSerialize(data=blob)
  assert obj2 == sample_obj


def test_serialize_deserialize_with_compress_high_clamped(sample_obj: key.CryptDict) -> None:
  """Test."""
  # request above max; function clamps to 22
  blob: bytes = key.Serialize(sample_obj, compress=99)
  obj2: key.CryptDict = key.DeSerialize(data=blob)
  assert obj2 == sample_obj


def test_serialize_deserialize_with_encrypt_ok(sample_obj: key.CryptDict) -> None:
  """Test."""
  aes_key = aes.AESKey(key256=b'x' * 32)
  blob: bytes = key.Serialize(sample_obj, compress=3, encryption_key=aes_key)
  # must supply same key (and same AAD inside implementation)
  obj2: key.CryptDict = key.DeSerialize(data=blob, decryption_key=aes_key)
  assert obj2 == sample_obj


def test_serialize_save_and_load_from_file(
  tmp_path: pathlib.Path, sample_obj: key.CryptDict
) -> None:
  """Test."""
  p: pathlib.Path = tmp_path / 'payload.bin'
  blob: bytes = key.Serialize(sample_obj, compress=3, file_path=str(p))
  assert p.exists() and p.stat().st_size == len(blob)
  obj2: key.CryptDict = key.DeSerialize(file_path=str(p))
  assert obj2 == sample_obj


def test_deserialize_exclusivity_both_args(tmp_path: pathlib.Path) -> None:
  """Test."""
  p: pathlib.Path = tmp_path / 'x.bin'
  p.write_bytes(b'data')
  with pytest.raises(base.InputError, match='you must provide only one of either'):
    key.DeSerialize(data=b'data', file_path=str(p))


def test_deserialize_invalid_calls() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='you must provide only one of either'):
    key.DeSerialize()
  with pytest.raises(base.InputError, match='invalid file_path'):
    key.DeSerialize(file_path='/definitely/not/here.bin')
  with pytest.raises(base.InputError, match='invalid data: too small'):
    key.DeSerialize(data=b'\x00\x01\x02')


def test_deserialize_wrong_key_raises(sample_obj: key.CryptDict) -> None:
  """Test."""
  key_ok = aes.AESKey(key256=b'x' * 32)
  key_bad = aes.AESKey(key256=b'y' * 32)
  blob: bytes = key.Serialize(sample_obj, compress=3, encryption_key=key_ok)
  with pytest.raises(key.CryptoError):
    key.DeSerialize(data=blob, decryption_key=key_bad)


def test_deserialize_corrupted_zstd_raises(sample_obj: key.CryptDict) -> None:
  """Test."""
  # create a valid zstd-compressed blob
  blob: bytes = key.Serialize(sample_obj, compress=3)
  # corrupt a byte beyond the first 4 (to keep magic intact)
  mutable = bytearray(blob)
  if len(mutable) <= 10:
    pytest.skip('blob too small to corrupt safely for this test')
  mutable[10] ^= 0xFF
  corrupted = bytes(mutable)
  # DeSerialize should detect zstd via magic, attempt to decompress, and zstd should error
  with pytest.raises(zstandard.ZstdError):
    key.DeSerialize(data=corrupted)


def test_deserialize_no_compression_detected_branch(sample_obj: key.CryptDict) -> None:
  """Test."""
  # Craft a blob that is NOT zstd: disable compression
  blob: bytes = key.Serialize(sample_obj, compress=None)
  # This exercises the "(no compression detected)" branch
  obj2: key.CryptDict = key.DeSerialize(data=blob)
  assert obj2 == sample_obj
