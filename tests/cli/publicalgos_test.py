# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""cli/publicalgos.py unittest.

Run with:
  poetry run pytest -vvv tests/cli/publicalgos_test.py
"""

from __future__ import annotations

import pathlib

import pytest
from click import testing as click_testing

from tests import transcrypto_test
from transcrypto.utils import config as app_config
from transcrypto.utils import logging as tc_logging


@pytest.fixture(autouse=True)
def reset_cli() -> None:
  """Reset CLI singleton before each test."""
  tc_logging.ResetConsole()
  app_config.ResetConfig()


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
  ],
)
def test_cli_commands_that_require_key_path_print_error(
  argv: list[str], expected_prefix: str
) -> None:
  """Test CLI commands that require -p/--key-path print expected error messages."""
  res: click_testing.Result = transcrypto_test.CallCLI(argv)
  assert res.exit_code == 0
  assert expected_prefix in res.output


def test_rsa_encrypt_decrypt_and_sign_verify(tmp_path: pathlib.Path) -> None:
  """Test RSA key gen, encrypt/decrypt, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'rsa'
  priv_path: pathlib.Path = tmp_path / 'rsa.priv'
  pub_path: pathlib.Path = tmp_path / 'rsa.pub'
  # Key gen (small for speed)
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(base_path), 'rsa', 'new', '--bits', '512']
  )
  assert res.exit_code == 0 and 'RSA private/public keys saved to' in res.output
  assert priv_path.exists()
  assert pub_path.exists()
  # Encrypt/decrypt a small message
  msg = 12345
  # Reset CLI singletons before additional CLI invocations within same test
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'rsa', 'rawencrypt', str(msg)])
  assert res.exit_code == 0
  c = int(transcrypto_test.OneToken(res))
  assert c > 0
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'rsa', 'rawdecrypt', str(c)])
  assert res.exit_code == 0
  assert int(transcrypto_test.OneToken(res)) == msg
  # Sign/verify
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'rsa', 'rawsign', str(msg)])
  assert res.exit_code == 0
  s = int(transcrypto_test.OneToken(res))
  assert s > 0
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'rsa', 'rawverify', str(msg), str(s)])
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'RSA signature: OK'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'rsa', 'rawverify', str(msg + 1), str(s)])
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'RSA signature: INVALID'


@pytest.mark.slow
def test_rsa_encrypt_decrypt_and_sign_verify_safe(tmp_path: pathlib.Path) -> None:
  """RSA safe encrypt/decrypt and sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'rsa_safe'
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Safe signing requires k > 64 → use ≥1024-bit modulus
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(base_path), 'rsa', 'new', '--bits', '1024']
  )
  assert res.exit_code == 0 and 'RSA private/public keys saved to' in res.output
  assert priv_path.exists() and pub_path.exists()
  # Encrypt (bin in → b64 out) with AAD='xyz'
  # Reset CLI singletons before additional CLI invocations within same test
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and len(transcrypto_test.OneToken(res)) > 0
  ct_b64 = transcrypto_test.OneToken(res)
  # Decrypt (b64 in → bin out) with same AAD (as base64: 'eHl6')
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'abcde'
  # Sign (bin in → b64 out) with AAD='aad'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and len(transcrypto_test.OneToken(res)) > 0
  sig_b64 = transcrypto_test.OneToken(res)
  # Verify OK (message='xyz' as b64 'eHl6', AAD='aad' as b64 'YWFk')
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'RSA signature: OK'
  # Verify INVALID with wrong message
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'RSA signature: INVALID'


def test_elgamal_encrypt_decrypt_and_sign_verify(tmp_path: pathlib.Path) -> None:
  """Test ElGamal shared/new, encrypt/decrypt, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'eg'
  shared_path: pathlib.Path = tmp_path / 'eg.shared'
  priv_path: pathlib.Path = tmp_path / 'eg.priv'
  pub_path: pathlib.Path = tmp_path / 'eg.pub'
  # Shared params & private key
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(base_path), 'elgamal', 'shared', '--bits', '64']
  )
  assert res.exit_code == 0 and 'El-Gamal shared key saved to' in res.output
  assert shared_path.exists()
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'elgamal', 'new'])
  assert res.exit_code == 0 and 'El-Gamal private/public keys saved to' in res.output
  assert priv_path.exists()
  assert pub_path.exists()
  # Encrypt/decrypt (public can be derived from private file)
  msg = 42
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'elgamal', 'rawencrypt', str(msg)])
  assert res.exit_code == 0 and len(transcrypto_test.OneToken(res)) > 0
  ct: str = transcrypto_test.OneToken(res)
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'elgamal', 'rawdecrypt', ct])
  assert res.exit_code == 0 and int(transcrypto_test.OneToken(res)) == msg
  # Sign/verify
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'elgamal', 'rawsign', str(msg)])
  assert res.exit_code == 0 and len(transcrypto_test.OneToken(res)) > 0
  sig: str = transcrypto_test.OneToken(res)
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'elgamal', 'rawverify', str(msg), sig])
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'El-Gamal signature: OK'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'elgamal', 'rawverify', str(msg + 1), sig])
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'El-Gamal signature: INVALID'


@pytest.mark.slow
def test_elgamal_encrypt_decrypt_and_sign_verify_safe(tmp_path: pathlib.Path) -> None:
  """ElGamal safe encrypt/decrypt and sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'eg_safe'
  shared_path = pathlib.Path(str(base_path) + '.shared')
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Safe signing requires k > 64 → use ≥1024-bit prime
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(base_path), 'elgamal', 'shared', '--bits', '1024']
  )
  assert (
    res.exit_code == 0 and shared_path.exists() and 'El-Gamal shared key saved to' in res.output
  )
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'elgamal', 'new'])
  assert (
    res.exit_code == 0
    and priv_path.exists()
    and pub_path.exists()
    and 'El-Gamal private/public keys saved to' in res.output
  )
  # Encrypt (bin in → b64 out) with AAD='xyz'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and len(transcrypto_test.OneToken(res)) > 0
  ct_b64: str = transcrypto_test.OneToken(res)
  # Decrypt (b64 in → bin out) with same AAD 'eHl6'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'abcde'
  # Sign (bin in → b64 out) with AAD='aad'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and len(transcrypto_test.OneToken(res)) > 0
  sig_b64 = transcrypto_test.OneToken(res)
  # Verify OK and INVALID cases
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'El-Gamal signature: OK'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'El-Gamal signature: INVALID'


@pytest.mark.slow
def test_dsa_sign_verify(tmp_path: pathlib.Path) -> None:
  """Test DSA shared/new, sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'dsa'
  shared_path: pathlib.Path = tmp_path / 'dsa.shared'
  priv_path: pathlib.Path = tmp_path / 'dsa.priv'
  pub_path: pathlib.Path = tmp_path / 'dsa.pub'
  # Small, but respect constraints: p_bits >= q_bits + 11, q_bits >= 11
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(base_path), 'dsa', 'shared', '--p-bits', '64', '--q-bits', '32']
  )
  assert res.exit_code == 0 and 'DSA shared key saved to' in res.output
  assert shared_path.exists()
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'dsa', 'new'])
  assert res.exit_code == 0 and 'DSA private/public keys saved to' in res.output
  assert priv_path.exists()
  assert pub_path.exists()
  msg = 123456
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'dsa', 'rawsign', str(msg)])
  assert res.exit_code == 0 and len(transcrypto_test.OneToken(res)) > 0
  sig: str = transcrypto_test.OneToken(res)
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'dsa', 'rawverify', str(msg), sig])
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'DSA signature: OK'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(priv_path), 'dsa', 'rawverify', str(msg + 1), sig])
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'DSA signature: INVALID'


@pytest.mark.slow
def test_dsa_sign_verify_safe(tmp_path: pathlib.Path) -> None:
  """DSA safe sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'dsa_safe'
  shared_path = pathlib.Path(str(base_path) + '.shared')
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Safe DSA requires q > 512 bits (k > 64 bytes). Use q=544, p≥q+11 → p=1024.
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(base_path), 'dsa', 'shared', '--p-bits', '1024', '--q-bits', '544']
  )
  assert res.exit_code == 0 and shared_path.exists() and 'DSA shared key saved to' in res.output
  # Generate private/public keys
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'dsa', 'new'])
  assert res.exit_code == 0 and priv_path.exists() and pub_path.exists()
  assert 'DSA private/public keys saved to' in res.output
  # Sign (bin in → b64 out) with AAD='aad'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and len(transcrypto_test.OneToken(res)) > 0
  sig_b64: str = transcrypto_test.OneToken(res)
  # Verify OK (message='xyz' b64) and INVALID (wrong message)
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'DSA signature: OK'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = transcrypto_test.CallCLI(
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
  assert res.exit_code == 0 and transcrypto_test.Out(res) == 'DSA signature: INVALID'
