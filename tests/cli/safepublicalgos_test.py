# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""cli/safepublicalgos.py unittest.

Run with:
  poetry run pytest -vvv tests/cli/safepublicalgos_test.py
"""

from __future__ import annotations

import pathlib

import pytest
from click import testing as click_testing

from tests import safetrans_test
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
    (['rsa', 'encrypt', '00'], 'you must provide -p/--key-path option for'),
    (['rsa', 'decrypt', '00'], 'you must provide -p/--key-path option for'),
    (['rsa', 'sign', '00'], 'you must provide -p/--key-path option for'),
    (['rsa', 'verify', '00', '00'], 'you must provide -p/--key-path option for'),
    # DSA commands that require -p/--key-path.
    (['dsa', 'shared'], 'you must provide -p/--key-path option for'),
    (['dsa', 'new'], 'you must provide -p/--key-path option for'),
    (['dsa', 'sign', '00'], 'you must provide -p/--key-path option for'),
    (['dsa', 'verify', '00', '00'], 'you must provide -p/--key-path option for'),
  ],
)
def test_cli_commands_that_require_key_path_print_error(
  argv: list[str], expected_prefix: str
) -> None:
  """Test CLI commands that require -p/--key-path print expected error messages."""
  res: click_testing.Result = safetrans_test._CallCLI(argv)
  assert res.exit_code == 0
  assert expected_prefix in res.output


@pytest.mark.slow
def test_rsa_encrypt_decrypt_and_sign_verify_safe(tmp_path: pathlib.Path) -> None:
  """RSA safe encrypt/decrypt and sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'rsa_safe'
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Safe signing requires k > 64 → use ≥1024-bit modulus
  res: click_testing.Result = safetrans_test._CallCLI(
    ['-p', str(base_path), 'rsa', 'new', '--bits', '1024']
  )
  assert res.exit_code == 0 and 'RSA private/public keys saved to' in res.output
  assert priv_path.exists() and pub_path.exists()
  # Encrypt (bin in → b64 out) with AAD='xyz'
  # Reset CLI singletons before additional CLI invocations within same test
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(
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
  assert res.exit_code == 0 and len(safetrans_test.OneToken(res)) > 0
  ct_b64 = safetrans_test.OneToken(res)
  # Decrypt (b64 in → bin out) with same AAD (as base64: 'eHl6')
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(
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
  assert res.exit_code == 0 and safetrans_test.Out(res) == 'abcde'
  # Sign (bin in → b64 out) with AAD='aad'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(
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
  assert res.exit_code == 0 and len(safetrans_test.OneToken(res)) > 0
  sig_b64 = safetrans_test.OneToken(res)
  # Verify OK (message='xyz' as b64 'eHl6', AAD='aad' as b64 'YWFk')
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(
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
  assert res.exit_code == 0 and safetrans_test.Out(res) == 'RSA signature: OK'
  # Verify INVALID with wrong message
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(
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
  assert res.exit_code == 0 and safetrans_test.Out(res) == 'RSA signature: INVALID'


@pytest.mark.slow
def test_dsa_sign_verify_safe(tmp_path: pathlib.Path) -> None:
  """DSA safe sign/verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'dsa_safe'
  shared_path = pathlib.Path(str(base_path) + '.shared')
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Safe DSA requires q > 512 bits (k > 64 bytes). Use q=544, p≥q+11 → p=1024.
  res: click_testing.Result = safetrans_test._CallCLI(
    ['-p', str(base_path), 'dsa', 'shared', '--p-bits', '1024', '--q-bits', '544']
  )
  assert res.exit_code == 0 and shared_path.exists() and 'DSA shared key saved to' in res.output
  # Generate private/public keys
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(['-p', str(base_path), 'dsa', 'new'])
  assert res.exit_code == 0 and priv_path.exists() and pub_path.exists()
  assert 'DSA private/public keys saved to' in res.output
  # Sign (bin in → b64 out) with AAD='aad'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(
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
  assert res.exit_code == 0 and len(safetrans_test.OneToken(res)) > 0
  sig_b64: str = safetrans_test.OneToken(res)
  # Verify OK (message='xyz' b64) and INVALID (wrong message)
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(
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
  assert res.exit_code == 0 and safetrans_test.Out(res) == 'DSA signature: OK'
  tc_logging.ResetConsole()
  app_config.ResetConfig()
  res = safetrans_test._CallCLI(
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
  assert res.exit_code == 0 and safetrans_test.Out(res) == 'DSA signature: INVALID'
