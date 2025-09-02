#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""transcrypto.py unittest."""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import os
import pathlib
# import pdb
import re
import runpy
import sys
import textwrap

import pytest

from src.transcrypto import aes, base, modmath, transcrypto

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = transcrypto.__version__  # tests inherit version from module


def _RunCLI(argv: list[str]) -> tuple[int, str]:
  """Run the CLI with argv, capture stdout, return (exit_code, stdout_stripped)."""
  buf = io.StringIO()
  with redirect_stdout(buf):
    code: int = transcrypto.main(argv)
  out: str = buf.getvalue().strip()
  return (code, out)


def test_LoadObj_wrong_type_raises(tmp_path: pathlib.Path) -> None:
  """_LoadObj should raise if the on-disk object is not of the expected type."""
  path: pathlib.Path = tmp_path / "obj.saved"
  # Save an AESKey object…
  key = aes.AESKey(key256=b"\x00" * 32)
  transcrypto._SaveObj(key, str(path), None)
  # …then try to load it expecting a completely different type.
  with pytest.raises(base.InputError, match=r'invalid type.*AESKey.*expected.*PublicBid'):
    transcrypto._LoadObj(str(path), None, base.PublicBid)  # expecting PublicBid, got AESKey


@pytest.mark.parametrize(
    'argv, expected',
    [
        # --- primality ---
        (['isprime', '2305843009213693951'], 'True'),
        (['isprime', '2305843009213693953'], 'False'),

        # --- gcd / xgcd ---
        (['gcd', '462', '1071'], '21'),
        (['xgcd', '100', '24'], '(4, 1, -4)'),

        # --- modular arithmetic ---
        (['mod', 'inv', '0x3', '11'], '4'),          # 3^-1 mod 11 = 4
        (['mod', 'inv', '3', '9'],
         '<<INVALID>> no modular inverse exists (ModularDivideError)'),
        (['mod', 'div', '0o12', '4', '13'], '9'),  # z*4 ≡ 10 (mod 13) → z = 9
        (['mod', 'div', '4', '0', '13'],
         '<<INVALID>> no modular inverse exists (ModularDivideError)'),
        (['mod', 'exp', '3', '20', '97'], '91'),   # 3^20 mod 97 = 91 (precomputed)
        (['mod', 'poly', '127', '19937', '10', '30', '20', '12', '31'], '12928'),
        (['mod', 'lagrange', '9', '5', '1:1', '3:3'], '4'),
        (['mod', 'crt', '0b10', '3', '3', '5'], '8'),
        (['mod', 'crt', '2', '3', '3', '0xf'],
         '<<INVALID>> moduli m1/m2 not co-prime (ModularDivideError)'),

        # --- prime generation (deterministic with -c) ---
        (['primegen', '10', '-c', '5'], textwrap.dedent('''\
            11
            13
            17
            19
            23''').strip()),
        (['mersenne', '--min-k', '2', '--cutoff-k', '7'], textwrap.dedent('''\
            k=2  M=3  perfect=6
            k=3  M=7  perfect=28
            k=5  M=31  perfect=496
            k=7  M=127  perfect=8128
            k=13  M=8191  perfect=33550336''').strip()),

        # --- hashing (strings) ---
        # SHA-256('abc')
        (['--bin', 'hash', 'sha256', 'abc'],
         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
        # SHA-256('abc'), hex input
        (['--hex', 'hash', 'sha256', '616263'],
         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
        # SHA-256('abc'), base64url output
        (['--bin', '--out-b64', 'hash', 'sha256', 'abc'],
         'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0='),
        # SHA-256('abc') via base64url input YWJj
        (['--b64', 'hash', 'sha256', 'YWJj'],
         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
        # SHA-512('abc')
        (['--bin', 'hash', 'sha512', 'abc'],
         'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
         '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'),
    ],
)
def test_cli_deterministic_pairs(argv: list[str], expected: str) -> None:
  """Test CLI commands with deterministic outputs."""
  code, out = _RunCLI(argv)
  assert code == 0, f'non-zero exit for argv={argv!r}'
  assert out == expected


def test_cli_hash_file(tmp_path: pathlib.Path) -> None:
  """Test CLI hash file command with a small file."""
  # Create a small file and hash it (deterministic)
  p: pathlib.Path = tmp_path / 'hello.txt'
  p.write_text('hello', encoding='utf-8')
  code, out = _RunCLI(['hash', 'file', str(p)])
  assert code == 0
  # SHA-256('hello')
  assert out == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'


def test_cli_doc_md_has_header() -> None:
  """Test CLI doc md command output has expected header."""
  code, out = _RunCLI(['doc', 'md'])
  assert code == 0
  # Don’t lock to the entire generated doc (it mirrors argparse & may change);
  # just verify the key header appears.
  assert '## Command-Line Interface' in out


def test_rand_bits_properties() -> None:
  """Test random bits CLI command output properties."""
  code, out = _RunCLI(['random', 'bits', '16'])
  assert code == 0
  n = int(out)
  assert 1 << 15 <= n < (1 << 16)  # exact bit length 16, msb=1


def test_rand_int_properties() -> None:
  """Test random int CLI command output properties."""
  code, out = _RunCLI(['random', 'int', '5', '9'])
  assert code == 0
  n = int(out)
  assert 5 <= n <= 9


def test_rand_bytes_shape() -> None:
  """Test random bytes CLI command output shape."""
  code, out = _RunCLI(['random', 'bytes', '4'])
  assert code == 0
  # CLI prints hex for rand bytes
  assert re.fullmatch(r'[0-9a-f]{8}', out) is not None


@pytest.mark.parametrize('bits', [11, 32, 64])
def test_random_prime_properties(bits: int) -> None:
  """Test randomprime CLI command output properties."""
  code, out = _RunCLI(['random', 'prime', str(bits)])
  assert code == 0
  p = int(out)
  # exact bit-size guarantee and primality
  assert p.bit_length() == bits
  assert modmath.IsPrime(p) is True


@pytest.mark.slow
def test_aes_key_print_b64_matches_library(tmp_path: pathlib.Path) -> None:
  """Test AES key CLI command output matches library."""
  # CLI derives & prints b64; library derives for ground truth
  code, out = _RunCLI(
      ['--out-b64', 'aes', 'key', 'correct horse battery staple'])
  assert code == 0
  assert out == 'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es='  # cspell:disable-line
  priv_path: pathlib.Path = tmp_path / 'password.priv'
  code, out = _RunCLI(
      ['-p', str(priv_path), 'aes', 'key', 'correct horse battery staple', ])
  assert code == 0
  assert 'AES key saved to' in out
  assert priv_path.exists()


@pytest.fixture
def aes_key_file(tmp_path: pathlib.Path) -> pathlib.Path:
  """Create a random AES-256 key and serialize it to disk for CLI to consume."""
  key = aes.AESKey(key256=os.urandom(32))
  blob_path: pathlib.Path = tmp_path / 'aes_key.bin'
  _: bytes = base.Serialize(key, file_path=str(blob_path))  # no password
  return blob_path


def test_aes_ecb_encrypthex_decrypthex_roundtrip() -> None:
  """Test AES-ECB encrypthex/decrypthex round trip via CLI."""
  key_bytes = bytes(range(32))  # 00 01 02 ... 1f
  key_b64: str = base.BytesToEncoded(key_bytes)
  block_hex = '00112233445566778899aabbccddeeff'
  # Encrypt (hex → hex)
  code, ct_hex = _RunCLI(['--b64', 'aes', 'ecb', '-k', key_b64, 'encrypt', block_hex])
  assert code == 0
  assert re.fullmatch(r'[0-9a-f]{32}', block_hex)  # sanity of input
  assert re.fullmatch(r'[0-9a-f]{32}', ct_hex)     # 16-byte block
  # Decrypt back
  code, pt_hex = _RunCLI(['--b64', 'aes', 'ecb', '-k', key_b64, 'decrypt', ct_hex])
  assert code == 0
  assert pt_hex == block_hex


def test_aes_gcm_encrypt_decrypt_roundtrip(aes_key_file: pathlib.Path) -> None:  # pylint: disable=redefined-outer-name
  """Test AES-GCM encrypt/decrypt round trip via CLI."""
  plaintext = 'secret message'
  aad = 'assoc'
  # Encrypt: inputs as binary text, outputs default hex
  code, ct_hex = _RunCLI(
      ['--bin', '-p', str(aes_key_file), 'aes', 'encrypt', plaintext, '-a', aad])
  assert code == 0
  assert re.fullmatch(r'[0-9a-f]+', ct_hex) is not None
  assert len(ct_hex) >= 32  # IV(16)+TAG(16)+ct → hex length ≥ 64; allow any ≥ minimal sanity
  # Decrypt: ciphertext hex in, ask for raw output so we can compare to original string
  code, out = _RunCLI(
      ['--hex', '-p', str(aes_key_file), '--out-bin', 'aes', 'decrypt',
       ct_hex, '-a', base.BytesToHex(aad.encode('utf-8'))])
  assert code == 0
  assert out == plaintext


@pytest.mark.slow
def test_rsa_encrypt_decrypt_and_sign_verify(tmp_path: pathlib.Path) -> None:
  """Test RSA key gen, encrypt/decrypt, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'rsa'
  priv_path: pathlib.Path = tmp_path / 'rsa.priv'
  pub_path: pathlib.Path = tmp_path / 'rsa.pub'
  # Key gen (small for speed)
  code, out = _RunCLI(['-p', str(base_path), 'rsa', 'new', '--bits', '512'])
  assert code == 0 and 'RSA private/public keys saved to' in out
  assert priv_path.exists()
  assert pub_path.exists()
  # Encrypt/decrypt a small message
  msg = 12345
  code, cipher = _RunCLI(['-p', str(priv_path), 'rsa', 'rawencrypt', str(msg)])
  assert code == 0
  c = int(cipher)
  assert c > 0
  code, plain = _RunCLI(['-p', str(priv_path), 'rsa', 'rawdecrypt', str(c)])
  assert code == 0
  assert int(plain) == msg
  # Sign/verify
  code, sig = _RunCLI(['-p', str(priv_path), 'rsa', 'rawsign', str(msg)])
  assert code == 0
  s = int(sig)
  assert s > 0
  code, ok = _RunCLI(['-p', str(priv_path), 'rsa', 'rawverify', str(msg), str(s)])
  assert code == 0
  assert ok == 'RSA signature: OK'
  code, ok = _RunCLI(['-p', str(priv_path), 'rsa', 'rawverify', str(msg + 1), str(s)])
  assert code == 0
  assert ok == 'RSA signature: INVALID'


def test_elgamal_encrypt_decrypt_and_sign_verify(tmp_path: pathlib.Path) -> None:  # pylint: disable=too-many-locals
  """Test ElGamal shared/new, encrypt/decrypt, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'eg'
  shared_path: pathlib.Path = tmp_path / 'eg.shared'
  priv_path: pathlib.Path = tmp_path / 'eg.priv'
  pub_path: pathlib.Path = tmp_path / 'eg.pub'
  # Shared params & private key
  code, out = _RunCLI(['-p', str(base_path), 'elgamal', 'shared', '--bits', '64'])
  assert code == 0 and 'El-Gamal shared key saved to' in out
  assert shared_path.exists()
  code, out = _RunCLI(['-p', str(base_path), 'elgamal', 'new'])
  assert code == 0 and 'El-Gamal private/public keys saved to' in out
  assert priv_path.exists()
  assert pub_path.exists()
  # Encrypt/decrypt (public can be derived from private file)
  msg = 42
  code, out = _RunCLI(['-p', str(priv_path), 'elgamal', 'rawencrypt', str(msg)])
  assert code == 0
  code, plain = _RunCLI(['-p', str(priv_path), 'elgamal', 'rawdecrypt', out])
  assert code == 0
  assert int(plain) == msg
  # Sign/verify
  code, out = _RunCLI(['-p', str(priv_path), 'elgamal', 'rawsign', str(msg)])
  assert code == 0
  code, ok = _RunCLI(['-p', str(priv_path), 'elgamal', 'rawverify', str(msg), out])
  assert code == 0 and ok == 'El-Gamal signature: OK'
  code, ok = _RunCLI(['-p', str(priv_path), 'elgamal', 'rawverify', str(msg + 1), out])
  assert code == 0 and ok == 'El-Gamal signature: INVALID'


def test_dsa_sign_verify(tmp_path: pathlib.Path) -> None:
  """Test DSA shared/new, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'dsa'
  shared_path: pathlib.Path = tmp_path / 'dsa.shared'
  priv_path: pathlib.Path = tmp_path / 'dsa.priv'
  pub_path: pathlib.Path = tmp_path / 'dsa.pub'
  # Small, but respect constraints: p_bits >= q_bits + 11, q_bits >= 11
  code, out = _RunCLI(
      ['-p', str(base_path), 'dsa', 'shared', '--p-bits', '64', '--q-bits', '32'])
  assert code == 0 and 'DSA shared key saved to' in out
  assert shared_path.exists()
  code, out = _RunCLI(['-p', str(base_path), 'dsa', 'new'])
  assert code == 0 and 'DSA private/public keys saved to' in out
  assert priv_path.exists()
  assert pub_path.exists()
  msg = 123456
  code, sig = _RunCLI(['-p', str(priv_path), 'dsa', 'rawsign', str(msg)])
  assert code == 0
  code, ok = _RunCLI(['-p', str(priv_path), 'dsa', 'rawverify', str(msg), sig])
  assert code == 0 and ok == 'DSA signature: OK'
  code, ok = _RunCLI(['-p', str(priv_path), 'dsa', 'rawverify', str(msg + 1), sig])
  assert code == 0 and ok == 'DSA signature: INVALID'


def test_bid_commit_verify(tmp_path: pathlib.Path) -> None:
  """Test bidding via CLI."""
  key_base = tmp_path / 'bid-key'
  priv_path = pathlib.Path(str(key_base) + '.priv')
  pub_path = pathlib.Path(str(key_base) + '.pub')
  secret = 'top-secret-123'  # raw UTF-8; we'll use --bin so it’s treated as bytes
  # Create new bid (writes .priv/.pub beside key_base)
  code, out = _RunCLI(['--bin', '-p', str(key_base), 'bid', 'new', secret])
  assert code == 0 and 'Bid private/public commitments saved to' in out
  assert priv_path.exists()
  assert pub_path.exists()
  # Verify: should print OK and echo the secret back
  code, out = _RunCLI(['--out-bin', '-p', str(key_base), 'bid', 'verify'])
  assert code == 0 and out == 'Bid commitment: OK\nBid secret:\ntop-secret-123'


@pytest.mark.slow
def test_sss_new_shares_recover_verify(tmp_path: pathlib.Path) -> None:
  """Test Shamir's Secret Sharing new, shares, recover, verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'sss'
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Generate params
  code, out = _RunCLI(['-p', str(base_path), 'sss', 'new', '3', '--bits', '128'])
  assert code == 0 and 'SSS private/public keys saved to' in out
  assert priv_path.exists() and pub_path.exists()
  # Issue 3 shares for a known secret
  secret = 999
  code, out = _RunCLI(['-p', str(base_path), 'sss', 'shares', str(secret), '3'])
  assert code == 0
  assert 'SSS 3 individual (private) shares saved to' in out and '1…3' in out
  for i in range(3):
    share_path = pathlib.Path(f'{base_path}.share.{i + 1}')
    assert share_path.exists()
  # Recover with public key
  code, out = _RunCLI(['-p', str(base_path), 'sss', 'recover'])
  assert code == 0
  lines: list[str] = out.splitlines()
  assert len(lines) == 5
  assert 'Loaded SSS share' in lines[0]
  assert int(lines[-1]) == secret
  # Verify a share against the same secret with private key
  code, out = _RunCLI(['-p', str(base_path), 'sss', 'verify', str(secret)])
  assert code == 0
  lines = out.splitlines()
  assert len(lines) == 3
  for line in lines:
    assert 'verification: OK' in line
  code, out = _RunCLI(['-p', str(base_path), 'sss', 'verify', str(secret + 1)])
  assert code == 0
  lines = out.splitlines()
  assert len(lines) == 3
  for line in lines:
    assert 'verification: INVALID' in line


@pytest.mark.parametrize(
    'argv',
    [
        ['random'],
        ['hash'],
        ['mod'],
        ['aes'],
        ['--b64', 'aes', 'ecb', '-k', 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='],
        ['-p', 'kkk', 'rsa'],
        ['-p', 'kkk', 'elgamal'],
        ['-p', 'kkk', 'dsa'],
        ['-p', 'kkk', 'bid'],
        ['-p', 'kkk', 'sss'],
        ['doc'],
    ],
)
def test_not_implemented_error_paths(argv: list[str]) -> None:
  """Test CLI paths that raise NotImplementedError."""
  code, out = _RunCLI(argv)
  assert code == 0
  assert 'Invalid command' in out


def test_from_flags_conflict_raises() -> None:
  """Directly hit _StrBytesType.FromFlags conflicting flags branch."""
  with pytest.raises(base.InputError):
    # Conflicting: --hex and --b64 at the same time
    transcrypto._StrBytesType.FromFlags(True, True, False)


@pytest.mark.parametrize(
    'mode, text, expect_hex',
    [
        (transcrypto._StrBytesType.RAW, 'hello', '68656c6c6f'),
        (transcrypto._StrBytesType.HEXADECIMAL, '68656c6c6f', '68656c6c6f'),
        (transcrypto._StrBytesType.BASE64, 'aGVsbG8=', '68656c6c6f'),
    ],
)
def test_bytes_from_to_text_modes(
    mode: transcrypto._StrBytesType, text: str, expect_hex: str) -> None:
  """Exercise _BytesFromText/_BytesToText in all 3 branches."""
  b: bytes = transcrypto._BytesFromText(text, mode)
  # Convert to hex using the CLI helper to normalize
  hex_out: str = transcrypto._BytesToText(b, transcrypto._StrBytesType.HEXADECIMAL)
  assert hex_out == expect_hex
  # Round-trip each mode back to itself (RAW/B64 produce readable strings)
  s_again: str = transcrypto._BytesToText(
      transcrypto._BytesFromText(text, mode), mode)
  # RAW returns original (utf-8), HEX and B64 return normalized encodings;
  # we just assert it doesn't crash and is non-empty.
  assert isinstance(s_again, str) and len(s_again) > 0


def test_rows_for_actions_metadata_branches() -> None:
  """Build a synthetic parser to trigger _FlagNames/_Format* metadata paths."""
  p = argparse.ArgumentParser(add_help=False)
  # Positional arg with nargs=2 and tuple metavar → exercises tuple branch in _FlagNames
  p.add_argument('pos', nargs=2, metavar=('FILE1', 'FILE2'))
  p.add_argument('pos2', nargs=2, metavar='FILE3')  # also test single string metavar
  # Boolean default True (store_true normally False) → _FormatDefault(bool True)
  p.add_argument('--switch', action='store_true', default=True, help='flag with default true')
  # Choices → _FormatChoices
  p.add_argument('--color', choices=['red', 'blue'], help='choose color')
  # Type=int and default value → _FormatType + _FormatDefault
  p.add_argument('--num', type=int, default=7, help='number')
  rows: list[tuple[str, str]] = transcrypto._RowsForActions(p._actions)  # type: ignore[attr-defined]
  # Flatten for easy search
  flat: str = '\n'.join(f'{l} :: {r}' for (l, r) in rows)
  # Tuple metavar shows both names
  assert 'FILE1, FILE2' in flat and 'FILE3' in flat
  # store_true default on
  assert '(default: on)' in flat
  # choices listed
  assert 'choices: [\'red\', \'blue\']' in flat or 'choices: ["red", "blue"]' in flat
  # type int appears
  assert 'type: int' in flat
  # default numeric prints
  assert '(default: 7)' in flat


def test_markdown_table_helper() -> None:
  """Tiny check of _MarkdownTable formatting."""
  table: str = transcrypto._MarkdownTable([('A', 'alpha'), ('B', 'beta')])
  assert table.splitlines()[0].startswith('| Option/Arg |')
  assert '`A`' in table and 'alpha' in table
  assert transcrypto._MarkdownTable([]) == ''  # empty input → empty output


@pytest.mark.parametrize(
    'argv',
    [
        ['--bin', 'aes', 'encrypt', 'msg'],
        ['--bin', 'aes', 'decrypt', 'msg'],
        ['aes', 'ecb', 'encrypt', '00112233445566778899aabbccddeeff'],
        ['rsa', 'new'],
    ],
)
def test_requires_key(argv: list[str]) -> None:
  """Hit the 'provide --key or --key-path' error in AES."""
  code, out = _RunCLI(argv)
  assert code == 0
  assert '-p/--key-path' in out


def test_aes_gcm_decrypt_wrong_aad_raises() -> None:
  """Force the GCM InvalidTag path (wrong AAD) → base.CryptoError."""
  # Fixed key for repeatability
  key_bytes = bytes(range(32))
  key_b64: str = base.BytesToEncoded(key_bytes)
  # Encrypt with AAD='A'
  code, out = _RunCLI(
      ['--b64', '--out-hex', 'aes', 'encrypt', 'AAAAAAB4eXo=', '-k', key_b64, '-a', 'eHl6'])  # cspell:disable-line
  assert code == 0 and re.fullmatch(r'[0-9a-f]+', out)
  # Decrypt with WRONG AAD='B' → should raise CryptoError
  code, out = _RunCLI(
      ['--b64', 'aes', 'decrypt',
       '"' + base.BytesToEncoded(base.HexToBytes(out)) + '"', '-k', key_b64, '-a', 'eHm6'])
  assert code == 0 and 'failed decryption' in out


def test_walk_subcommands_includes_deep_path() -> None:
  """Ensure _WalkSubcommands traverses nested subparsers (e.g., aes ecb encrypthex)."""
  parser: argparse.ArgumentParser = transcrypto._BuildParser()
  paths: list[str] = [' '.join(p[0]) for p in transcrypto._WalkSubcommands(parser)]
  # A representative deep path present in your CLI
  assert 'aes ecb encrypt' in paths
  assert transcrypto._HelpText(parser, None) == ''


def test_from_flags_conflict_raises_again() -> None:
  """Hit the conflicting flags branch in _StrBytesType.FromFlags."""
  with pytest.raises(base.InputError):
    transcrypto._StrBytesType.FromFlags(True, True, False)


def test_rows_for_actions_cover_suppress_custom_and_help() -> None:
  """Drive _RowsForActions metadata branches: SUPPRESS, custom type, help action."""
  # Keep add_help=True to include the built-in -h/--help action (exercises isinstance(_HelpAction))
  p = argparse.ArgumentParser()
  # Arg with default=SUPPRESS → exercises that early-return in _FormatDefault
  p.add_argument('--maybe', default=argparse.SUPPRESS, help='maybe suppressed default')

  # Custom callable without __name__ → forces 'type: custom' in _FormatType
  class _CallableNoName:  # pragma: no cover - cover is for transcrypto lines, not this helper  # pylint: disable=too-few-public-methods
    def __call__(self, s: str) -> str:
      return s

  p.add_argument('--weird', type=_CallableNoName(), help='custom callable type')
  # Also add one standard store_true to hit bool-default branch
  p.add_argument('--flag', action='store_true', default=False, help='bool default false')
  rows: list[tuple[str, str]] = transcrypto._RowsForActions(p._actions)  # type: ignore[attr-defined]
  text: str = '\n'.join(f'{l} :: {r}' for (l, r) in rows)
  # SUPPRESS default should not render a "(default: ...)" string
  assert '--maybe' in text and '(default:' not in text.split('--maybe', 1)[1].splitlines()[0]
  # Custom callable should show "type: custom"
  assert 'type: custom' in text
  # Built-in help action is skipped by _RowsForActions; make sure other rows exist
  assert any('--flag' in l for (l, _r) in rows)


def test_aes_ecb_encrypt_decrypt_with_key_path(tmp_path: pathlib.Path) -> None:
  """Cover AES-ECB key selection via --key-path (elif branch)."""
  # Write a serialized AES key file
  key = aes.AESKey(key256=os.urandom(32))
  key_path: pathlib.Path = tmp_path / 'k.bin'
  base.Serialize(key, file_path=str(key_path))
  block_hex = '00112233445566778899aabbccddeeff'
  # Encrypt with --key-path
  code, ct_hex = _RunCLI(['-p', str(key_path), 'aes', 'ecb', 'encrypt', block_hex])
  assert code == 0 and re.fullmatch(r'[0-9a-f]{32}', ct_hex)
  # Decrypt with --key-path
  code, pt_hex = _RunCLI(['-p', str(key_path), 'aes', 'ecb', 'decrypt', ct_hex])
  assert code == 0 and pt_hex == block_hex


@pytest.mark.filterwarnings(r'ignore:.*found in sys.modules.*:RuntimeWarning')
def test_run_entrypoint_block(monkeypatch: pytest.MonkeyPatch) -> None:
  """Execute the `if __name__ == '__main__'` block to cover the last lines."""
  # Make the CLI think it was invoked with no args → prints help then exits(0).
  monkeypatch.setattr(sys, 'argv', ['transcrypto.py'])
  # Run the module by *name* with run_name="__main__" so relative imports work.
  with pytest.raises(SystemExit) as exc:
    runpy.run_module('src.transcrypto.transcrypto', run_name='__main__')
  assert exc.value.code == 0


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
