# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""transcrypto.py unittest.

Run this test with:

poetry run pytest -vvv tests/transcrypto_test.py
"""

from __future__ import annotations

import io
import os
import pathlib
import re
import sys
import textwrap
from collections import abc

import pytest
import typeguard
from click import testing as click_testing
from rich import console as rich_console
from typer import testing

from transcrypto import aes, base, modmath, transcrypto


@pytest.fixture(autouse=True)
def reset_cli_logging_singletons() -> abc.Generator[None]:
  """Reset global console/logging state between tests.

  The CLI callback initializes a global Rich console singleton via InitLogging().
  Tests invoke the CLI multiple times across test cases, so we must reset that
  singleton to keep tests isolated.
  """
  base.ResetConsole()
  yield  # noqa: PT022


def _CallCLI(args: list[str]) -> click_testing.Result:
  """Call the CLI with args.

  Args:
      args (list[str]): CLI arguments.

  Returns:
      click_testing.Result: CLI result.

  """
  with typeguard.suppress_type_checks():
    # we suppress type checks here because CliRunner.invoke expects a click.Command,
    # but we are passing a typer.Typer (which is a subclass of click.Command)
    return testing.CliRunner().invoke(transcrypto.app, args, env={'COLUMNS': '2000'})


def _Out(res: click_testing.Result) -> str:
  return res.output.strip()


def _OneToken(res: click_testing.Result) -> str:
  # Rich hard-wrap can insert newlines inside long tokens; normalize for token outputs.
  return _Out(res).replace('\n', '')


_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def _CLIOutput(res: click_testing.Result) -> str:
  """Return CLI output for assertions.

  Typer/Click may send errors to stderr and may add ANSI styling (especially
  when Rich is installed). Normalize that here so tests are stable across
  environments.

  Returns:
      str: cleaned CLI output.

  """
  stdout = getattr(res, 'stdout', '')
  stderr = getattr(res, 'stderr', '')
  combined = (stdout + stderr) if (stdout or stderr) else res.output
  return _ANSI_ESCAPE_RE.sub('', combined)


def test_LoadObj_wrong_type_raises(tmp_path: pathlib.Path) -> None:
  """_LoadObj should raise if the on-disk object is not of the expected type."""
  path: pathlib.Path = tmp_path / 'obj.saved'
  # Save an AESKey object…
  key = aes.AESKey(key256=b'\x00' * 32)
  transcrypto._SaveObj(key, str(path), None)
  # …then try to load it expecting a completely different type.
  with pytest.raises(base.InputError, match=r'invalid type.*AESKey.*expected.*PublicBid'):
    transcrypto._LoadObj(str(path), None, base.PublicBid512)  # expecting PublicBid, got AESKey


@pytest.mark.parametrize(
  ('argv', 'expected'),
  [
    # --- primality ---
    (['isprime', '2305843009213693951'], 'True'),
    (['isprime', '2305843009213693953'], 'False'),
    # --- gcd / xgcd ---
    (['gcd', '462', '1071'], '21'),
    (['xgcd', '100', '24'], '(4, 1, -4)'),
    # --- modular arithmetic ---
    (['mod', 'inv', '0x3', '11'], '4'),  # 3^-1 mod 11 = 4
    (['mod', 'inv', '3', '9'], '<<INVALID>> no modular inverse exists (ModularDivideError)'),
    (['mod', 'div', '0o12', '4', '13'], '9'),  # z*4 ≡ 10 (mod 13) → z = 9
    (
      ['mod', 'div', '4', '0', '13'],
      '<<INVALID>> divide-by-zero or not invertible (ModularDivideError)',
    ),
    (['mod', 'exp', '3', '20', '97'], '91'),  # 3^20 mod 97 = 91 (precomputed)
    (['mod', 'poly', '127', '19937', '10', '30', '20', '12', '31'], '12928'),
    (['mod', 'lagrange', '9', '5', '1:1', '3:3'], '4'),
    (['mod', 'crt', '0b10', '3', '3', '5'], '8'),
    (
      ['mod', 'crt', '2', '3', '3', '0xf'],
      '<<INVALID>> moduli `m1`/`m2` not co-prime (ModularDivideError)',
    ),
    # --- prime generation (deterministic with -c) ---
    (
      ['primegen', '10', '-c', '5'],
      textwrap.dedent("""\
            11
            13
            17
            19
            23""").strip(),
    ),
    (
      ['mersenne', '--min-k', '2', '--max-k', '13'],
      textwrap.dedent("""\
            k=2  M=3  perfect=6
            k=3  M=7  perfect=28
            k=5  M=31  perfect=496
            k=7  M=127  perfect=8128
            k=13  M=8191  perfect=33550336""").strip(),
    ),
    # --- hashing (strings) ---
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
  res: click_testing.Result = _CallCLI(argv)
  assert res.exit_code == 0, f'non-zero exit for argv={argv!r}'
  if '\n' in expected:
    assert _Out(res) == expected
  else:
    assert _OneToken(res) == expected


def test_cli_hash_file(tmp_path: pathlib.Path) -> None:
  """Test CLI hash file command with a small file."""
  # Create a small file and hash it (deterministic)
  p: pathlib.Path = tmp_path / 'hello.txt'
  p.write_text('hello', encoding='utf-8')
  res: click_testing.Result = _CallCLI(['hash', 'file', str(p)])
  assert res.exit_code == 0
  assert (  # SHA-256('hello')
    _OneToken(res) == '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
  )


def test_cli_markdown_has_header() -> None:
  """Test CLI markdown command output has expected header."""
  res: click_testing.Result = _CallCLI(['markdown'])
  assert res.exit_code == 0
  assert '# `transcrypto`' in res.output


def test_cli_version_exits_zero() -> None:
  """Test CLI --version shows version and exits zero."""
  res: click_testing.Result = _CallCLI(['--version'])
  assert res.exit_code == 0
  assert transcrypto.__version__ in res.output  # type: ignore[attr-defined]


@pytest.mark.parametrize(
  ('argv', 'needle'),
  [
    (
      ['primegen', '10', '-c', '0'],
      "Invalid value for '-c' / '--count': 0 is not in the range x>=1",
    ),
    (
      ['mersenne', '--min-k', '0', '--max-k', '5'],
      "Invalid value for '-k' / '--min-k': 0 is not in the range x>=1",
    ),
    (
      ['mersenne', '--min-k', '2', '--max-k', '0'],
      "Invalid value for '-m' / '--max-k': 0 is not in the range x>=1",
    ),
  ],
)
def test_cli_validations_print_errors(argv: list[str], needle: str) -> None:
  """Test CLI argument validations print expected error messages."""
  res: click_testing.Result = _CallCLI(argv)
  assert res.exit_code == 2
  assert needle in _CLIOutput(res)


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
  res: click_testing.Result = _CallCLI(argv)
  assert res.exit_code == 0
  assert needle in res.output


def test_cli_aes_ecb_help_when_no_subcommand() -> None:
  """Test AES-ECB subapp shows help when no subcommand given."""
  res: click_testing.Result = _CallCLI(['aes', 'ecb'])
  assert res.exit_code in {0, 2}
  assert 'AES-256-ECB' in res.output


def test_rand_bits_properties() -> None:
  """Test random bits CLI command output properties."""
  res: click_testing.Result = _CallCLI(['random', 'bits', '16'])
  assert res.exit_code == 0
  n = int(_OneToken(res))
  assert 1 << 15 <= n < (1 << 16)  # exact bit length 16, msb=1


def test_rand_int_properties() -> None:
  """Test random int CLI command output properties."""
  res: click_testing.Result = _CallCLI(['random', 'int', '5', '9'])
  assert res.exit_code == 0
  n = int(_OneToken(res))
  assert 5 <= n <= 9


def test_rand_bytes_shape() -> None:
  """Test random bytes CLI command output shape."""
  res: click_testing.Result = _CallCLI(['random', 'bytes', '4'])
  assert res.exit_code == 0
  # CLI prints hex for rand bytes
  assert re.fullmatch(r'[0-9a-f]{8}', _OneToken(res)) is not None


def test_cli_gcd_both_zero_prints_error() -> None:
  """Cover GCD CLI error branch when both inputs are zero."""
  res: click_testing.Result = _CallCLI(['gcd', '0', '0'])
  assert res.exit_code == 0
  assert "`a` and `b` can't both be zero" in res.output


def test_cli_xgcd_both_zero_prints_error() -> None:
  """Cover XGCD CLI error branch when both inputs are zero."""
  res: click_testing.Result = _CallCLI(['xgcd', '0', '0'])
  assert res.exit_code == 0
  assert "`a` and `b` can't both be zero" in res.output


def test_cli_random_int_invalid_range_prints_error() -> None:
  """Cover RandomInt CLI error branch when max <= min."""
  res: click_testing.Result = _CallCLI(['random', 'int', '9', '5'])
  assert res.exit_code == 0
  assert 'int must be ≥ 10, got 5' in res.output


def test_cli_mersenne_max_lt_min_prints_error() -> None:
  """Cover Mersenne CLI error branch when max_k < min_k."""
  res: click_testing.Result = _CallCLI(['mersenne', '--min-k', '10', '--max-k', '5'])
  assert res.exit_code == 0
  assert 'max-k (5) must be >= min-k (10)' in res.output


def test_cli_internal_parse_helpers_error_branches() -> None:
  """Cover small helper branches that are hard to hit via CLI parsing."""
  # _ParseInt: empty string and invalid literal.
  with pytest.raises(base.InputError, match=r'invalid int'):
    transcrypto._ParseInt('   ')
  with pytest.raises(base.InputError, match=r'invalid int'):
    transcrypto._ParseInt('not_an_int')

  # _ParseIntPairCLI: invalid pair formatting.
  with pytest.raises(base.InputError, match=r'invalid int\(s\)'):
    transcrypto._ParseIntPairCLI('1')
  with pytest.raises(base.InputError, match=r'invalid int'):
    transcrypto._ParseIntPairCLI('1:')
  with pytest.raises(base.InputError, match=r'invalid int'):
    transcrypto._ParseIntPairCLI(':2')


@pytest.mark.parametrize('bits', [11, 32, 64])
def test_random_prime_properties(bits: int) -> None:
  """Test randomprime CLI command output properties."""
  res: click_testing.Result = _CallCLI(['random', 'prime', str(bits)])
  assert res.exit_code == 0
  p = int(_OneToken(res))
  # exact bit-size guarantee and primality
  assert p.bit_length() == bits
  assert modmath.IsPrime(p) is True


@pytest.mark.slow
@pytest.mark.veryslow
def test_aes_key_print_b64_matches_library(tmp_path: pathlib.Path) -> None:
  """Test AES key CLI command output matches library."""
  # CLI derives & prints b64; library derives for ground truth
  res: click_testing.Result = _CallCLI(
    ['--output-format', 'b64', 'aes', 'key', 'correct horse battery staple']
  )
  assert res.exit_code == 0
  assert _OneToken(res) == 'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es='  # cspell:disable-line
  priv_path: pathlib.Path = tmp_path / 'password.priv'
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'aes', 'key', 'correct horse battery staple'])
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
  res: click_testing.Result = _CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'encrypt', '-k', key_b64, block_hex]
  )
  assert res.exit_code == 0
  assert re.fullmatch(r'[0-9a-f]{32}', block_hex)  # sanity of input
  assert re.fullmatch(r'[0-9a-f]{32}', _OneToken(res))  # 16-byte block
  # Decrypt back
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res2: click_testing.Result = _CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'decrypt', '-k', key_b64, _OneToken(res)]
  )
  assert res2.exit_code == 0
  assert _OneToken(res2) == block_hex


def test_aes_gcm_encrypt_decrypt_roundtrip(aes_key_file: pathlib.Path) -> None:
  """Test AES-GCM encrypt/decrypt round trip via CLI."""
  plaintext = 'secret message'
  aad = 'assoc'
  # Encrypt: inputs as binary text, outputs default hex
  res: click_testing.Result = _CallCLI(
    ['--input-format', 'bin', '-p', str(aes_key_file), 'aes', 'encrypt', plaintext, '-a', aad]
  )
  assert res.exit_code == 0
  ct_hex = _OneToken(res)
  assert re.fullmatch(r'[0-9a-f]+', ct_hex) is not None
  assert len(ct_hex) >= 32  # IV(16)+TAG(16)+ct → hex length ≥ 64; allow any ≥ minimal sanity
  # Decrypt: ciphertext hex in, ask for raw output so we can compare to original string
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res2: click_testing.Result = _CallCLI(
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
  assert _Out(res2) == plaintext


def test_rsa_encrypt_decrypt_and_sign_verify(tmp_path: pathlib.Path) -> None:
  """Test RSA key gen, encrypt/decrypt, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'rsa'
  priv_path: pathlib.Path = tmp_path / 'rsa.priv'
  pub_path: pathlib.Path = tmp_path / 'rsa.pub'
  # Key gen (small for speed)
  res: click_testing.Result = _CallCLI(['-p', str(base_path), 'rsa', 'new', '--bits', '512'])
  assert res.exit_code == 0 and 'RSA private/public keys saved to' in res.output
  assert priv_path.exists()
  assert pub_path.exists()
  # Encrypt/decrypt a small message
  msg = 12345
  # Reset CLI singletons before additional CLI invocations within same test
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'rsa', 'rawencrypt', str(msg)])
  assert res.exit_code == 0
  c = int(_OneToken(res))
  assert c > 0
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'rsa', 'rawdecrypt', str(c)])
  assert res.exit_code == 0
  assert int(_OneToken(res)) == msg
  # Sign/verify
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'rsa', 'rawsign', str(msg)])
  assert res.exit_code == 0
  s = int(_OneToken(res))
  assert s > 0
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'rsa', 'rawverify', str(msg), str(s)])
  assert res.exit_code == 0 and _Out(res) == 'RSA signature: OK'
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'rsa', 'rawverify', str(msg + 1), str(s)])
  assert res.exit_code == 0 and _Out(res) == 'RSA signature: INVALID'


@pytest.mark.parametrize(
  ('argv', 'expected_prefix'),
  [
    # RSA commands that require -p/--key-path, exercise each command's try/except.
    (['rsa', 'rawencrypt', '1'], 'you must provide -p/--key-path option for'),
    (['rsa', 'rawdecrypt', '1'], 'you must provide -p/--key-path option for'),
    (['rsa', 'rawsign', '1'], 'you must provide -p/--key-path option for'),
    (['rsa', 'rawverify', '1', '1'], 'you must provide -p/--key-path option for'),
    (['rsa', 'encrypt', '00'], 'you must provide -p/--key-path option for'),
    (['rsa', 'decrypt', '00'], 'you must provide -p/--key-path option for'),
    (['rsa', 'sign', '00'], 'you must provide -p/--key-path option for'),
    (['rsa', 'verify', '00', '00'], 'you must provide -p/--key-path option for'),
    # ElGamal commands that require -p/--key-path.
    (['elgamal', 'shared'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'new'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'rawencrypt', '1'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'rawdecrypt', '1:1'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'rawsign', '1'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'rawverify', '1', '1:1'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'encrypt', '00'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'decrypt', '00'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'sign', '00'], 'you must provide -p/--key-path option for'),
    (['elgamal', 'verify', '00', '00'], 'you must provide -p/--key-path option for'),
    # DSA commands that require -p/--key-path.
    (['dsa', 'shared'], 'you must provide -p/--key-path option for'),
    (['dsa', 'new'], 'you must provide -p/--key-path option for'),
    (['dsa', 'rawsign', '1'], 'you must provide -p/--key-path option for'),
    (['dsa', 'rawverify', '1', '1:1'], 'you must provide -p/--key-path option for'),
    (['dsa', 'sign', '00'], 'you must provide -p/--key-path option for'),
    (['dsa', 'verify', '00', '00'], 'you must provide -p/--key-path option for'),
    # Bid verify requires -p/--key-path.
    (['bid', 'new', '00'], 'you must provide -p/--key-path option for'),
    (['bid', 'verify'], 'you must provide -p/--key-path option for'),
    # SSS subcommands require -p/--key-path.
    (['sss', 'new', '2'], 'you must provide -p/--key-path option for'),
    (['sss', 'rawshares', '1', '2'], 'you must provide -p/--key-path option for'),
    (['sss', 'rawrecover'], 'you must provide -p/--key-path option for'),
    (['sss', 'rawverify', '1'], 'you must provide -p/--key-path option for'),
    (['sss', 'shares', '00', '2'], 'you must provide -p/--key-path option for'),
    (['sss', 'recover'], 'you must provide -p/--key-path option for'),
  ],
)
def test_cli_commands_that_require_key_path_print_error(
  argv: list[str], expected_prefix: str
) -> None:
  """Test CLI commands that require -p/--key-path print expected error messages."""
  res: click_testing.Result = _CallCLI(argv)
  assert res.exit_code == 0
  assert expected_prefix in res.output


@pytest.mark.parametrize('subapp', ['rsa', 'elgamal', 'dsa', 'bid', 'sss'])
def test_cli_subapps_show_help_when_no_subcommand(subapp: str) -> None:
  """Subapp-only invocations should show help."""
  res: click_testing.Result = _CallCLI([subapp])
  assert res.exit_code in {0, 2}
  assert 'Usage:' in res.output


def test_transcrypto_run_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test transcrypto.Run() with no args exits cleanly."""
  monkeypatch.setattr(sys, 'argv', ['transcrypto'])
  with pytest.raises(SystemExit) as exc:
    transcrypto.Run()
  # No-args help behavior depends on Click/Typer; exit code is not important.
  assert exc.value.code in {0, 2}


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
  res: click_testing.Result = _CallCLI(argv)
  assert res.exit_code == 0
  assert needle in res.output


@pytest.mark.slow
def test_rsa_encrypt_decrypt_and_sign_verify_safe(tmp_path: pathlib.Path) -> None:
  """RSA safe encrypt/decrypt and sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'rsa_safe'
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Safe signing requires k > 64 → use ≥1024-bit modulus
  res: click_testing.Result = _CallCLI(['-p', str(base_path), 'rsa', 'new', '--bits', '1024'])
  assert res.exit_code == 0 and 'RSA private/public keys saved to' in res.output
  assert priv_path.exists() and pub_path.exists()
  # Encrypt (bin in → b64 out) with AAD='xyz'
  # Reset CLI singletons before additional CLI invocations within same test
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'bin',
      '--output-format',
      'b64',
      '-p',
      str(priv_path),
      'rsa',
      'encrypt',
      'abcde',
      '-a',
      'xyz',
    ]
  )
  assert res.exit_code == 0 and len(_OneToken(res)) > 0
  ct_b64 = _OneToken(res)
  # Decrypt (b64 in → bin out) with same AAD (as base64: 'eHl6')
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'b64',
      '--output-format',
      'bin',
      '-p',
      str(priv_path),
      'rsa',
      'decrypt',
      '-a',
      'eHl6',
      '--',
      ct_b64,
    ]
  )
  assert res.exit_code == 0 and _Out(res) == 'abcde'
  # Sign (bin in → b64 out) with AAD='aad'
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'bin',
      '--output-format',
      'b64',
      '-p',
      str(priv_path),
      'rsa',
      'sign',
      'xyz',
      '-a',
      'aad',
    ]
  )
  assert res.exit_code == 0 and len(_OneToken(res)) > 0
  sig_b64 = _OneToken(res)
  # Verify OK (message='xyz' as b64 'eHl6', AAD='aad' as b64 'YWFk')
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'b64',
      '-p',
      str(priv_path),
      'rsa',
      'verify',
      '-a',
      'YWFk',
      '--',
      'eHl6',
      sig_b64,
    ]
  )
  assert res.exit_code == 0 and _Out(res) == 'RSA signature: OK'
  # Verify INVALID with wrong message
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'b64',
      '-p',
      str(priv_path),
      'rsa',
      'verify',
      '-a',
      'YWFk',
      '--',
      'eLl6',
      sig_b64,
    ]
  )
  assert res.exit_code == 0 and _Out(res) == 'RSA signature: INVALID'


def test_elgamal_encrypt_decrypt_and_sign_verify(tmp_path: pathlib.Path) -> None:
  """Test ElGamal shared/new, encrypt/decrypt, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'eg'
  shared_path: pathlib.Path = tmp_path / 'eg.shared'
  priv_path: pathlib.Path = tmp_path / 'eg.priv'
  pub_path: pathlib.Path = tmp_path / 'eg.pub'
  # Shared params & private key
  res: click_testing.Result = _CallCLI(['-p', str(base_path), 'elgamal', 'shared', '--bits', '64'])
  assert res.exit_code == 0 and 'El-Gamal shared key saved to' in res.output
  assert shared_path.exists()
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'elgamal', 'new'])
  assert res.exit_code == 0 and 'El-Gamal private/public keys saved to' in res.output
  assert priv_path.exists()
  assert pub_path.exists()
  # Encrypt/decrypt (public can be derived from private file)
  msg = 42
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'elgamal', 'rawencrypt', str(msg)])
  assert res.exit_code == 0 and len(_OneToken(res)) > 0
  ct = _OneToken(res)
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'elgamal', 'rawdecrypt', ct])
  assert res.exit_code == 0 and int(_OneToken(res)) == msg
  # Sign/verify
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'elgamal', 'rawsign', str(msg)])
  assert res.exit_code == 0 and len(_OneToken(res)) > 0
  sig = _OneToken(res)
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'elgamal', 'rawverify', str(msg), sig])
  assert res.exit_code == 0 and _Out(res) == 'El-Gamal signature: OK'
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'elgamal', 'rawverify', str(msg + 1), sig])
  assert res.exit_code == 0 and _Out(res) == 'El-Gamal signature: INVALID'


@pytest.mark.slow
def test_elgamal_encrypt_decrypt_and_sign_verify_safe(tmp_path: pathlib.Path) -> None:
  """ElGamal safe encrypt/decrypt and sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'eg_safe'
  shared_path = pathlib.Path(str(base_path) + '.shared')
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Safe signing requires k > 64 → use ≥1024-bit prime
  res: click_testing.Result = _CallCLI(
    ['-p', str(base_path), 'elgamal', 'shared', '--bits', '1024']
  )
  assert (
    res.exit_code == 0 and shared_path.exists() and 'El-Gamal shared key saved to' in res.output
  )
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'elgamal', 'new'])
  assert (
    res.exit_code == 0
    and priv_path.exists()
    and pub_path.exists()
    and 'El-Gamal private/public keys saved to' in res.output
  )
  # Encrypt (bin in → b64 out) with AAD='xyz'
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'bin',
      '--output-format',
      'b64',
      '-p',
      str(priv_path),
      'elgamal',
      'encrypt',
      'abcde',
      '-a',
      'xyz',
    ]
  )
  assert res.exit_code == 0 and len(_OneToken(res)) > 0
  ct_b64 = _OneToken(res)
  # Decrypt (b64 in → bin out) with same AAD 'eHl6'
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'b64',
      '--output-format',
      'bin',
      '-p',
      str(priv_path),
      'elgamal',
      'decrypt',
      '-a',
      'eHl6',
      '--',
      ct_b64,
    ]
  )
  assert res.exit_code == 0 and _Out(res) == 'abcde'
  # Sign (bin in → b64 out) with AAD='aad'
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'bin',
      '--output-format',
      'b64',
      '-p',
      str(priv_path),
      'elgamal',
      'sign',
      'xyz',
      '-a',
      'aad',
    ]
  )
  assert res.exit_code == 0 and len(_OneToken(res)) > 0
  sig_b64 = _OneToken(res)
  # Verify OK and INVALID cases
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'b64',
      '-p',
      str(priv_path),
      'elgamal',
      'verify',
      '-a',
      'YWFk',
      '--',
      'eHl6',
      sig_b64,
    ]
  )
  assert res.exit_code == 0 and _Out(res) == 'El-Gamal signature: OK'
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'b64',
      '-p',
      str(priv_path),
      'elgamal',
      'verify',
      '-a',
      'YWFk',
      '--',
      'eLl6',
      sig_b64,
    ]
  )
  assert res.exit_code == 0 and _Out(res) == 'El-Gamal signature: INVALID'


@pytest.mark.slow
def test_dsa_sign_verify(tmp_path: pathlib.Path) -> None:
  """Test DSA shared/new, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'dsa'
  shared_path: pathlib.Path = tmp_path / 'dsa.shared'
  priv_path: pathlib.Path = tmp_path / 'dsa.priv'
  pub_path: pathlib.Path = tmp_path / 'dsa.pub'
  # Small, but respect constraints: p_bits >= q_bits + 11, q_bits >= 11
  res: click_testing.Result = _CallCLI(
    ['-p', str(base_path), 'dsa', 'shared', '--p-bits', '64', '--q-bits', '32']
  )
  assert res.exit_code == 0 and 'DSA shared key saved to' in res.output
  assert shared_path.exists()
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'dsa', 'new'])
  assert res.exit_code == 0 and 'DSA private/public keys saved to' in res.output
  assert priv_path.exists()
  assert pub_path.exists()
  msg = 123456
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'dsa', 'rawsign', str(msg)])
  assert res.exit_code == 0 and len(_OneToken(res)) > 0
  sig = _OneToken(res)
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'dsa', 'rawverify', str(msg), sig])
  assert res.exit_code == 0 and _Out(res) == 'DSA signature: OK'
  base.ResetConsole()
  res = _CallCLI(['-p', str(priv_path), 'dsa', 'rawverify', str(msg + 1), sig])
  assert res.exit_code == 0 and _Out(res) == 'DSA signature: INVALID'


@pytest.mark.slow
def test_dsa_sign_verify_safe(tmp_path: pathlib.Path) -> None:
  """DSA safe sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'dsa_safe'
  shared_path = pathlib.Path(str(base_path) + '.shared')
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Safe DSA requires q > 512 bits (k > 64 bytes). Use q=544, p≥q+11 → p=1024.
  res: click_testing.Result = _CallCLI(
    ['-p', str(base_path), 'dsa', 'shared', '--p-bits', '1024', '--q-bits', '544']
  )
  assert res.exit_code == 0 and shared_path.exists() and 'DSA shared key saved to' in res.output
  # Generate private/public keys
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'dsa', 'new'])
  assert res.exit_code == 0 and priv_path.exists() and pub_path.exists()
  assert 'DSA private/public keys saved to' in res.output
  # Sign (bin in → b64 out) with AAD='aad'
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'bin',
      '--output-format',
      'b64',
      '-p',
      str(priv_path),
      'dsa',
      'sign',
      'xyz',
      '-a',
      'aad',
    ]
  )
  assert res.exit_code == 0 and len(_OneToken(res)) > 0
  sig_b64 = _OneToken(res)
  # Verify OK (message='xyz' b64) and INVALID (wrong message)
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'b64',
      '-p',
      str(priv_path),
      'dsa',
      'verify',
      '-a',
      'YWFk',
      '--',
      'eHl6',
      sig_b64,
    ]
  )
  assert res.exit_code == 0 and _Out(res) == 'DSA signature: OK'
  base.ResetConsole()
  res = _CallCLI(
    [
      '--input-format',
      'b64',
      '-p',
      str(priv_path),
      'dsa',
      'verify',
      '-a',
      'YWFk',
      '--',
      'eHL6',
      sig_b64,
    ]
  )
  assert res.exit_code == 0 and _Out(res) == 'DSA signature: INVALID'


def test_bid_commit_verify(tmp_path: pathlib.Path) -> None:
  """Test bidding via CLI."""
  key_base: pathlib.Path = tmp_path / 'bid-key'
  priv_path = pathlib.Path(str(key_base) + '.priv')
  pub_path = pathlib.Path(str(key_base) + '.pub')
  bid_message = (
    'bid-message-123'  # raw UTF-8; we'll use `--input-format bin` so it's treated as bytes
  )
  # Create new bid (writes .priv/.pub beside key_base)
  res: click_testing.Result = _CallCLI(
    ['--input-format', 'bin', '-p', str(key_base), 'bid', 'new', bid_message]
  )
  assert res.exit_code == 0 and 'Bid private/public commitments saved to' in res.output
  assert priv_path.exists()
  assert pub_path.exists()
  # Verify: should print OK and echo the secret back
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res = _CallCLI(['--output-format', 'bin', '-p', str(key_base), 'bid', 'verify'])
  assert res.exit_code == 0 and _Out(res) == 'Bid commitment: OK\nBid secret:\nbid-message-123'


def test_sss_new_shares_recover_verify(tmp_path: pathlib.Path) -> None:
  """Test Shamir's Secret Sharing new, shares, recover, verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'sss'
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Generate params
  res: click_testing.Result = _CallCLI(['-p', str(base_path), 'sss', 'new', '3', '--bits', '128'])
  assert res.exit_code == 0 and 'SSS private/public keys saved to' in res.output
  assert priv_path.exists() and pub_path.exists()
  # Test count < minimum validation (rawshares)
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'sss', 'rawshares', '999', '2'])
  assert res.exit_code == 0
  assert 'count (2) must be >= minimum (3)' in res.output
  # Issue 3 shares for a known secret
  sss_message = 999
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'sss', 'rawshares', str(sss_message), '3'])
  assert res.exit_code == 0
  assert 'SSS 3 individual (private) shares saved to' in res.output and '1…3' in res.output
  for i in range(3):
    share_path = pathlib.Path(f'{base_path}.share.{i + 1}')
    assert share_path.exists()
  # Recover with public key
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'sss', 'rawrecover'])
  assert res.exit_code == 0
  lines: list[str] = _Out(res).splitlines()
  assert len(lines) == 5
  assert 'Loaded SSS share' in lines[0]
  assert int(lines[-1]) == sss_message
  # Verify a share against the same secret with private key
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'sss', 'rawverify', str(sss_message)])
  assert res.exit_code == 0
  lines = _Out(res).splitlines()
  assert len(lines) == 3
  for line in lines:
    assert 'verification: OK' in line
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'sss', 'rawverify', str(sss_message + 1)])
  assert res.exit_code == 0
  lines = _Out(res).splitlines()
  assert len(lines) == 3
  for line in lines:
    assert 'verification: INVALID' in line
  # verify sss recover without any data shares → should error
  base.ResetConsole()
  res = _CallCLI(['-p', str(base_path), 'sss', 'recover'])
  assert res.exit_code == 0 and 'no data share found among the available shares' in res.output


def test_sss_shares_recover_safe(tmp_path: pathlib.Path) -> None:
  """SSS safe shares/recover for data (AEAD-wrapped)."""
  base_path: pathlib.Path = tmp_path / 'sss_safe'
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Make params. AEAD path requires modulus_size > 32 → bits > 256 (use 384 for speed).
  res: click_testing.Result = _CallCLI(['-p', str(base_path), 'sss', 'new', '3', '--bits', '384'])
  assert res.exit_code == 0 and priv_path.exists() and pub_path.exists()
  assert 'SSS private/public keys saved to' in res.output
  # Test count < minimum validation (shares)
  base.ResetConsole()
  res = _CallCLI(['--input-format', 'bin', '-p', str(base_path), 'sss', 'shares', 'abcde', '2'])
  assert res.exit_code == 0
  assert 'count (2) must be >= minimum (3)' in res.output
  # Issue 3 data shares for secret "abcde" (bin so it's treated as bytes)
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res = _CallCLI(['--input-format', 'bin', '-p', str(base_path), 'sss', 'shares', 'abcde', '3'])
  assert res.exit_code == 0 and 'SSS 3 individual (private) shares saved' in res.output
  for i in range(1, 4):
    assert pathlib.Path(f'{base_path}.share.{i}').exists()
  # Recover (out as bin) → prints loaded shares then the secret
  base.ResetConsole()
  res = _CallCLI(['--output-format', 'bin', '-p', str(base_path), 'sss', 'recover'])
  assert res.exit_code == 0
  lines: list[str] = _Out(res).splitlines()
  assert any('Loaded SSS share' in ln for ln in lines)
  assert lines[-2] == 'Secret:'
  assert lines[-1] == 'abcde'


@pytest.mark.parametrize(
  'argv',
  [
    ['random'],
    ['hash'],
    ['mod'],
    ['aes'],
    ['aes', 'ecb'],
    ['-p', 'kkk', 'rsa'],
    ['-p', 'kkk', 'elgamal'],
    ['-p', 'kkk', 'dsa'],
    ['-p', 'kkk', 'bid'],
    ['-p', 'kkk', 'sss'],
  ],
)
def test_group_help_outputs(argv: list[str]) -> None:
  """Group-only invocations should show help."""
  res: click_testing.Result = _CallCLI(argv)
  assert res.exit_code in {0, 2}
  assert 'Usage:' in res.output


@pytest.mark.parametrize(
  ('mode', 'text', 'expect_hex'),
  [
    (transcrypto.IOFormat.bin, 'hello', '68656c6c6f'),
    (transcrypto.IOFormat.hex, '68656c6c6f', '68656c6c6f'),
    (transcrypto.IOFormat.b64, 'aGVsbG8=', '68656c6c6f'),
  ],
)
def test_bytes_from_to_text_modes(mode: transcrypto.IOFormat, text: str, expect_hex: str) -> None:
  """Exercise _BytesFromText/_BytesToText in all 3 branches."""
  b: bytes = transcrypto._BytesFromText(text, mode)
  # Convert to hex using the CLI helper to normalize
  hex_out: str = transcrypto._BytesToText(b, transcrypto.IOFormat.hex)
  assert hex_out == expect_hex
  # Round-trip each mode back to itself (bin/b64 produce readable strings)
  s_again: str = transcrypto._BytesToText(transcrypto._BytesFromText(text, mode), mode)
  # RAW returns original (utf-8), HEX and B64 return normalized encodings;
  # we just assert it doesn't crash and is non-empty.
  assert isinstance(s_again, str) and len(s_again) > 0


def test_markdown_includes_deep_path() -> None:
  """Ensure markdown docs include a representative deep path."""
  res: click_testing.Result = _CallCLI(['markdown'])
  assert res.exit_code == 0
  md = res.output
  assert 'aes ecb encrypt' in md


def test_require_keypath_rejects_directory(tmp_path: pathlib.Path) -> None:
  """Cover _RequireKeyPath directory error path."""
  c = rich_console.Console(file=io.StringIO(), force_terminal=False, color_system=None, record=True)
  cfg = transcrypto.TransConfig(
    console=c,
    verbose=0,
    color=None,
    input_format=transcrypto.IOFormat.hex,
    output_format=transcrypto.IOFormat.hex,
    key_path=tmp_path,
    protect='',
  )
  with pytest.raises(base.InputError):
    transcrypto._RequireKeyPath(cfg, 'rsa')


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
  res: click_testing.Result = _CallCLI(argv)
  assert res.exit_code == 0
  assert '-p/--key-path' in res.output


@pytest.mark.slow
def test_aes_gcm_decrypt_wrong_aad_raises() -> None:
  """Force the GCM InvalidTag path (wrong AAD) → base.CryptoError."""
  # Fixed key for repeatability
  key_bytes = bytes(range(32))
  key_b64: str = base.BytesToEncoded(key_bytes)
  # Encrypt with AAD='A'
  res: click_testing.Result = _CallCLI(
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
  assert res.exit_code == 0 and re.fullmatch(r'[0-9a-f]+', _OneToken(res))
  # Decrypt with WRONG AAD='B' → should raise CryptoError
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res = _CallCLI(
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
      base.BytesToEncoded(base.HexToBytes(_OneToken(res))),
    ]
  )
  assert res.exit_code == 0 and 'failed decryption' in res.output


@pytest.mark.slow
def test_aes_ecb_encrypt_decrypt_with_key_path(tmp_path: pathlib.Path) -> None:
  """Cover AES-ECB key selection via --key-path (elif branch)."""
  # Write a serialized AES key file
  key = aes.AESKey(key256=os.urandom(32))
  key_path: pathlib.Path = tmp_path / 'k.bin'
  base.Serialize(key, file_path=str(key_path))
  block_hex = '00112233445566778899aabbccddeeff'
  # Encrypt with --key-path
  res: click_testing.Result = _CallCLI(['-p', str(key_path), 'aes', 'ecb', 'encrypt', block_hex])
  assert res.exit_code == 0 and re.fullmatch(r'[0-9a-f]{32}', _OneToken(res))
  # Decrypt with --key-path
  # Reset CLI singletons before calling CLI again in the same test
  base.ResetConsole()
  res2: click_testing.Result = _CallCLI(
    ['-p', str(key_path), 'aes', 'ecb', 'decrypt', _OneToken(res)]
  )
  assert res2.exit_code == 0 and _OneToken(res2) == block_hex


def test_aes_ecb_wrong_length_input() -> None:
  """Cover AES-ECB input validation for wrong-length plaintext/ciphertext."""
  key_b64 = base.BytesToEncoded(bytes(range(32)))
  # Wrong-length plaintext
  res: click_testing.Result = _CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'encrypt', '-k', key_b64, 'abc']
  )
  assert res.exit_code == 0
  assert 'must be exactly 32 hex chars' in res.output
  # Invalid hexadecimal string (not hex) - encrypt - 32 chars with 'Z' which is not hex
  base.ResetConsole()
  res = _CallCLI(['--input-format', 'b64', 'aes', 'ecb', 'encrypt', '-k', key_b64, 'Z' * 32])
  assert res.exit_code == 0
  assert 'invalid hexadecimal string' in res.output
  # Invalid hexadecimal in decrypt - 32 chars with 'Z' which is not hex
  base.ResetConsole()
  res = _CallCLI(['--input-format', 'b64', 'aes', 'ecb', 'decrypt', '-k', key_b64, 'Z' * 32])
  assert res.exit_code == 0
  assert 'invalid hexadecimal string' in res.output
  # Wrong-length ciphertext
  base.ResetConsole()
  res2: click_testing.Result = _CallCLI(
    ['--input-format', 'b64', 'aes', 'ecb', 'decrypt', '-k', key_b64, 'abc']
  )
  assert res2.exit_code == 0
  assert 'must be exactly 32 hex chars' in res2.output
