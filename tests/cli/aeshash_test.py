# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""cli/aeshash.py unittest.

Run with:
  poetry run pytest -vvv tests/cli/aeshash_test.py
"""

from __future__ import annotations

import os
import pathlib
import re

import pytest
from click import testing as click_testing

from tests import transcrypto_test
from transcrypto.core import aes, key
from transcrypto.utils import base
from transcrypto.utils import config as app_config
from transcrypto.utils import logging as tc_logging


@pytest.fixture(autouse=True)
def reset_cli() -> None:
  """Reset CLI singleton before each test."""
  tc_logging.ResetConsole()
  app_config.ResetConfig()


@pytest.mark.parametrize(
  ('argv', 'expected'),
  [
    (  # SHA-256('abc')
      ['--input-format', 'bin', 'hash', 'sha256', 'abc'],
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    ),
    (  # SHA-256('abc'), hex input
      ['--input-format', 'hex', 'hash', 'sha256', '616263'],
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    ),
    (  # SHA-256('abc'), base64url output
      ['--input-format', 'bin', '--output-format', 'b64', 'hash', 'sha256', 'abc'],
      'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0=',
    ),
    (  # SHA-256('abc') via base64url input YWJj
      ['--input-format', 'b64', 'hash', 'sha256', 'YWJj'],
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    ),
    (  # SHA-512('abc')
      ['--input-format', 'bin', 'hash', 'sha512', 'abc'],
      (
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
      ),
    ),
  ],
)
def test_cli_deterministic_pairs(argv: list[str], expected: str) -> None:
  """Test CLI commands with deterministic outputs."""
  res: click_testing.Result = transcrypto_test.CallCLI(argv)
  assert res.exit_code == 0, f'non-zero exit for argv={argv!r}'
  if '\n' in expected:
    assert transcrypto_test.Out(res) == expected
  else:
    assert transcrypto_test.OneToken(res) == expected


def test_cli_hash_file(tmp_path: pathlib.Path) -> None:
  """Test CLI hash file command with a small file."""
  # Create a small file and hash it (deterministic)
  p: pathlib.Path = tmp_path / 'hello.txt'
  p.write_text('hello', encoding='utf-8')
  res: click_testing.Result = transcrypto_test.CallCLI(['hash', 'file', str(p)])
  assert res.exit_code == 0
  assert (  # SHA-256('hello')
    transcrypto_test.OneToken(res)
    == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
  )


@pytest.mark.parametrize(
  ('argv', 'needle'),
  [
    # AES-GCM requires a key.
    (['aes', 'encrypt', 'abc'], 'provide -k/--key or -p/--key-path'),
    (['aes', 'decrypt', '00'], 'provide -k/--key or -p/--key-path'),
    # AES-ECB requires a key.
    (['aes', 'ecb', 'encrypt', '00112233445566778899aabbccddeeff'], 'provide -k/--key'),
    (['aes', 'ecb', 'decrypt', '00112233445566778899aabbccddeeff'], 'provide -k/--key'),
  ],
)
def test_cli_aes_missing_key_prints_error(argv: list[str], needle: str) -> None:
  """Test CLI AES commands missing key print expected error messages."""
  res: click_testing.Result = transcrypto_test.CallCLI(argv)
  assert res.exit_code == 0
  assert needle in res.output


def test_cli_aes_ecb_help_when_no_subcommand() -> None:
  """Test AES-ECB subapp shows help when no subcommand given."""
  res: click_testing.Result = transcrypto_test.CallCLI(['aes', 'ecb'])
  assert res.exit_code in {0, 2}
  assert 'AES-256-ECB' in res.output


@pytest.mark.slow
@pytest.mark.veryslow
def test_aes_key_print_b64_matches_library(tmp_path: pathlib.Path) -> None:
  """Test AES key CLI command output matches library."""
  # CLI derives & prints b64; library derives for ground truth
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['--output-format', 'b64', 'aes', 'key', 'correct horse battery staple']
  )
  assert res.exit_code == 0
  assert (
    transcrypto_test.OneToken(res)
    == 'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es='  # cspell:disable-line
  )  # cspell:disable-line
  priv_path: pathlib.Path = tmp_path / 'password.priv'
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(
    ['-p', str(priv_path), 'aes', 'key', 'correct horse battery staple']
  )
  assert res.exit_code == 0
  assert 'AES key saved to' in res.output
  assert priv_path.exists()


@pytest.fixture
def aes_key_file(tmp_path: pathlib.Path) -> pathlib.Path:
  """Create a random AES-256 key and serialize it to disk for CLI to consume.

  Args:
      tmp_path (pathlib.Path): temp path

  Returns:
      pathlib.Path: blob path

  """
  aes_key = aes.AESKey(key256=os.urandom(32))
  blob_path: pathlib.Path = tmp_path / 'aes_key.bin'
  _: bytes = key.Serialize(aes_key, file_path=str(blob_path))  # no password
  return blob_path


def test_aes_ecb_encrypthex_decrypthex_roundtrip() -> None:
  """Test AES-ECB encrypthex/decrypthex round trip via CLI."""
  key_bytes = bytes(range(32))  # 00 01 02 ... 1f
  key_b64: str = base.BytesToEncoded(key_bytes)
  block_hex = '00112233445566778899aabbccddeeff'
  # Encrypt (hex → hex)
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'encrypt', '-k', key_b64, block_hex]
  )
  assert res.exit_code == 0
  assert re.fullmatch(r'[0-9a-f]{32}', block_hex)  # sanity of input
  assert re.fullmatch(r'[0-9a-f]{32}', transcrypto_test.OneToken(res))  # 16-byte block
  # Decrypt back
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  res2: click_testing.Result = transcrypto_test.CallCLI(
    [
      '--input-format',
      'b64',
      'aes',
      'ecb',
      'decrypt',
      '-k',
      key_b64,
      transcrypto_test.OneToken(res),
    ]
  )
  assert res2.exit_code == 0
  assert transcrypto_test.OneToken(res2) == block_hex


def test_aes_gcm_encrypt_decrypt_roundtrip(aes_key_file: pathlib.Path) -> None:
  """Test AES-GCM encrypt/decrypt round trip via CLI."""
  plaintext = 'secret message'
  aad = 'assoc'
  # Encrypt: inputs as binary text, outputs default hex
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['--input-format', 'bin', '-p', str(aes_key_file), 'aes', 'encrypt', plaintext, '-a', aad]
  )
  assert res.exit_code == 0
  ct_hex = transcrypto_test.OneToken(res)
  assert re.fullmatch(r'[0-9a-f]+', ct_hex) is not None
  assert len(ct_hex) >= 32  # IV(16)+TAG(16)+ct → hex length ≥ 64; allow any ≥ minimal sanity
  # Decrypt: ciphertext hex in, ask for raw output so we can compare to original string
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  res2: click_testing.Result = transcrypto_test.CallCLI(
    [
      '--input-format',
      'hex',
      '-p',
      str(aes_key_file),
      '--output-format',
      'bin',
      'aes',
      'decrypt',
      ct_hex,
      '-a',
      base.BytesToHex(aad.encode('utf-8')),
    ]
  )
  assert res2.exit_code == 0
  assert transcrypto_test.Out(res2) == plaintext


@pytest.mark.parametrize(
  ('argv', 'needle'),
  [
    # AES key size validation branches.
    (['--input-format', 'bin', 'aes', 'encrypt', '-k', 'x', 'abc'], 'invalid AES key size'),
    (['--input-format', 'bin', 'aes', 'decrypt', '-k', 'x', 'abc'], 'invalid AES key size'),
    (
      [
        '--input-format',
        'bin',
        'aes',
        'ecb',
        'encrypt',
        '-k',
        'x',
        '00112233445566778899aabbccddeeff',
      ],
      'invalid AES key size',
    ),
    (
      [
        '--input-format',
        'bin',
        'aes',
        'ecb',
        'decrypt',
        '-k',
        'x',
        '00112233445566778899aabbccddeeff',
      ],
      'invalid AES key size',
    ),
  ],
)
def test_cli_aes_invalid_key_size_prints_error(argv: list[str], needle: str) -> None:
  """Test CLI AES commands with invalid key sizes print expected error messages."""
  res: click_testing.Result = transcrypto_test.CallCLI(argv)
  assert res.exit_code == 0
  assert needle in res.output


@pytest.mark.parametrize(
  'argv',
  [
    ['--input-format', 'bin', 'aes', 'encrypt', 'msg'],
    ['--input-format', 'bin', 'aes', 'decrypt', 'msg'],
    ['aes', 'ecb', 'encrypt', '00112233445566778899aabbccddeeff'],
    ['rsa', 'new'],
  ],
)
def test_requires_key(argv: list[str]) -> None:
  """Hit the 'provide --key or --key-path' error in AES."""
  res: click_testing.Result = transcrypto_test.CallCLI(argv)
  assert res.exit_code == 0
  assert '-p/--key-path' in res.output


@pytest.mark.slow
def test_aes_gcm_decrypt_wrong_aad_raises() -> None:
  """Force the GCM InvalidTag path (wrong AAD) → base.CryptoError."""
  # Fixed key for repeatability
  key_bytes = bytes(range(32))
  key_b64: str = base.BytesToEncoded(key_bytes)
  # Encrypt with AAD='A'
  res: click_testing.Result = transcrypto_test.CallCLI(
    [
      '--input-format',
      'b64',
      '--output-format',
      'hex',
      'aes',
      'encrypt',
      'AAAAAAB4eXo=',  # cspell:disable-line
      '-k',
      key_b64,
      '-a',
      'eHl6',
    ]
  )
  assert res.exit_code == 0 and re.fullmatch(r'[0-9a-f]+', transcrypto_test.OneToken(res))
  # Decrypt with WRONG AAD='B' → should raise CryptoError
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(
    [
      '--input-format',
      'b64',
      'aes',
      'decrypt',
      '-k',
      key_b64,
      '-a',
      'eHm6',
      '--',
      base.BytesToEncoded(base.HexToBytes(transcrypto_test.OneToken(res))),
    ]
  )
  assert res.exit_code == 0 and 'failed decryption' in res.output


@pytest.mark.slow
def test_aes_ecb_encrypt_decrypt_with_key_path(tmp_path: pathlib.Path) -> None:
  """Cover AES-ECB key selection via --key-path (elif branch)."""
  # Write a serialized AES key file
  aes_key = aes.AESKey(key256=os.urandom(32))
  key_path: pathlib.Path = tmp_path / 'k.bin'
  key.Serialize(aes_key, file_path=str(key_path))
  block_hex = '00112233445566778899aabbccddeeff'
  # Encrypt with --key-path
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(key_path), 'aes', 'ecb', 'encrypt', block_hex]
  )
  assert res.exit_code == 0 and re.fullmatch(r'[0-9a-f]{32}', transcrypto_test.OneToken(res))
  # Decrypt with --key-path
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  res2: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(key_path), 'aes', 'ecb', 'decrypt', transcrypto_test.OneToken(res)]
  )
  assert res2.exit_code == 0 and transcrypto_test.OneToken(res2) == block_hex


def test_aes_ecb_wrong_length_input() -> None:
  """Cover AES-ECB input validation for wrong-length plaintext/ciphertext."""
  key_b64 = base.BytesToEncoded(bytes(range(32)))
  # Wrong-length plaintext
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'encrypt', '-k', key_b64, 'abc']
  )
  assert res.exit_code == 0
  assert 'must be exactly 32 hex chars' in res.output
  # Invalid hexadecimal string (not hex) - encrypt - 32 chars with 'Z' which is not hex
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'encrypt', '-k', key_b64, 'Z' * 32]
  )
  assert res.exit_code == 0
  assert 'invalid hexadecimal string' in res.output
  # Invalid hexadecimal in decrypt - 32 chars with 'Z' which is not hex
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'decrypt', '-k', key_b64, 'Z' * 32]
  )
  assert res.exit_code == 0
  assert 'invalid hexadecimal string' in res.output
  # Wrong-length ciphertext
  tc_logging.ResetConsole()
  res2: click_testing.Result = transcrypto_test.CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'decrypt', '-k', key_b64, 'abc']
  )
  assert res2.exit_code == 0
  assert 'must be exactly 32 hex chars' in res2.output
