# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""cli/bidsecret.py unittest.

Run with:
  poetry run pytest -vvv tests/cli/bidsecret_test.py
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
  res: click_testing.Result = transcrypto_test.CallCLI(argv)
  assert res.exit_code == 0
  assert expected_prefix in res.output


def test_bid_commit_verify(tmp_path: pathlib.Path) -> None:
  """Test bidding via CLI."""
  key_base: pathlib.Path = tmp_path / 'bid-key'
  priv_path = pathlib.Path(str(key_base) + '.priv')
  pub_path = pathlib.Path(str(key_base) + '.pub')
  bid_message = (
    'bid-message-123'  # raw UTF-8; we'll use `--input-format bin` so it's treated as bytes
  )
  # Create new bid (writes .priv/.pub beside key_base)
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['--input-format', 'bin', '-p', str(key_base), 'bid', 'new', bid_message]
  )
  assert res.exit_code == 0 and 'Bid private/public commitments saved to' in res.output
  assert priv_path.exists()
  assert pub_path.exists()
  # Verify: should print OK and echo the secret back
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(['--output-format', 'bin', '-p', str(key_base), 'bid', 'verify'])
  assert (
    res.exit_code == 0
    and transcrypto_test.Out(res) == 'Bid commitment: OK\nBid secret:\nbid-message-123'
  )


def test_sss_new_shares_recover_verify(tmp_path: pathlib.Path) -> None:
  """Test Shamir's Secret Sharing new, shares, recover, verify via CLI."""
  base_path: pathlib.Path = tmp_path / 'sss'
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Generate params
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(base_path), 'sss', 'new', '3', '--bits', '128']
  )
  assert res.exit_code == 0 and 'SSS private/public keys saved to' in res.output
  assert priv_path.exists() and pub_path.exists()
  # Test count < minimum validation (rawshares)
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'sss', 'rawshares', '999', '2'])
  assert res.exit_code == 0
  assert 'count (2) must be >= minimum (3)' in res.output
  # Issue 3 shares for a known secret
  sss_message = 999
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'sss', 'rawshares', str(sss_message), '3'])
  assert res.exit_code == 0
  assert 'SSS 3 individual (private) shares saved to' in res.output and '1…3' in res.output
  for i in range(3):
    share_path = pathlib.Path(f'{base_path}.share.{i + 1}')
    assert share_path.exists()
  # Recover with public key
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'sss', 'rawrecover'])
  assert res.exit_code == 0
  lines: list[str] = transcrypto_test.Out(res).splitlines()
  assert len(lines) == 5
  assert 'Loaded SSS share' in lines[0]
  assert int(lines[-1]) == sss_message
  # Verify a share against the same secret with private key
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'sss', 'rawverify', str(sss_message)])
  assert res.exit_code == 0
  lines = transcrypto_test.Out(res).splitlines()
  assert len(lines) == 3
  for line in lines:
    assert 'verification: OK' in line
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'sss', 'rawverify', str(sss_message + 1)])
  assert res.exit_code == 0
  lines = transcrypto_test.Out(res).splitlines()
  assert len(lines) == 3
  for line in lines:
    assert 'verification: INVALID' in line
  # verify sss recover without any data shares → should error
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(['-p', str(base_path), 'sss', 'recover'])
  assert res.exit_code == 0 and 'no data share found among the available shares' in res.output


def test_sss_shares_recover_safe(tmp_path: pathlib.Path) -> None:
  """SSS safe shares/recover for data (AEAD-wrapped)."""
  base_path: pathlib.Path = tmp_path / 'sss_safe'
  priv_path = pathlib.Path(str(base_path) + '.priv')
  pub_path = pathlib.Path(str(base_path) + '.pub')
  # Make params. AEAD path requires modulus_size > 32 → bits > 256 (use 384 for speed).
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['-p', str(base_path), 'sss', 'new', '3', '--bits', '384']
  )
  assert res.exit_code == 0 and priv_path.exists() and pub_path.exists()
  assert 'SSS private/public keys saved to' in res.output
  # Test count < minimum validation (shares)
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(
    ['--input-format', 'bin', '-p', str(base_path), 'sss', 'shares', 'abcde', '2']
  )
  assert res.exit_code == 0
  assert 'count (2) must be >= minimum (3)' in res.output
  # Issue 3 data shares for secret "abcde" (bin so it's treated as bytes)
  # Reset CLI singletons before calling CLI again in the same test
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(
    ['--input-format', 'bin', '-p', str(base_path), 'sss', 'shares', 'abcde', '3']
  )
  assert res.exit_code == 0 and 'SSS 3 individual (private) shares saved' in res.output
  for i in range(1, 4):
    assert pathlib.Path(f'{base_path}.share.{i}').exists()
  # Recover (out as bin) → prints loaded shares then the secret
  tc_logging.ResetConsole()
  res = transcrypto_test.CallCLI(['--output-format', 'bin', '-p', str(base_path), 'sss', 'recover'])
  assert res.exit_code == 0
  lines: list[str] = transcrypto_test.Out(res).splitlines()
  assert any('Loaded SSS share' in ln for ln in lines)
  assert lines[-2] == 'Secret:'
  assert lines[-1] == 'abcde'
