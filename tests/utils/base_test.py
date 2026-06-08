# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""utils/base.py unittest.

Run with:
  poetry run pytest -vvv tests/utils/base_test.py
"""

from __future__ import annotations

import pathlib
import subprocess  # noqa: S404
import unittest.mock

import pytest

from transcrypto.utils import base


def test_bytes_conversions() -> None:
  """Test."""
  bb: bytes = b'xyz'
  assert base.BytesToHex(bb) == '78797a'
  assert base.BytesToInt(bb) == 7895418
  assert base.BytesToEncoded(bb) == 'eHl6'
  assert base.HexToBytes('78797a') == bb
  assert base.IntToBytes(7895418) == bb
  assert base.IntToEncoded(7895418) == 'eHl6'
  assert base.EncodedToBytes('eHl6') == bb
  assert base.PadBytesTo(bb, 8) == bb
  assert base.PadBytesTo(bb, 16) == bb
  assert base.PadBytesTo(bb, 24) == bb
  assert base.PadBytesTo(bb, 32) == b'\x00xyz'
  assert base.PadBytesTo(bb, 40) == b'\x00\x00xyz'
  assert base.PadBytesTo(b'\x01\x00', 40) == b'\x00\x00\x00\x01\x00'
  padded: bytes = base.PadBytesTo(bb, 64)
  assert padded == b'\x00\x00\x00\x00\x00xyz'
  assert base.BytesToHex(padded) == '000000000078797a'
  assert base.BytesToInt(padded) == 7895418
  assert base.BytesToEncoded(padded) == 'AAAAAAB4eXo='  # cspell:disable-line
  assert base.HexToBytes('000000000078797a') == padded
  assert base.EncodedToBytes('AAAAAAB4eXo=') == padded  # cspell:disable-line


def test_BytesToRaw() -> None:
  """Test."""
  assert base.BytesToRaw(b'abcd') == '"abcd"'
  for i in range(256):
    b: bytes = b'ab' + bytes([i]) + b'cd'
    assert base.RawToBytes(base.BytesToRaw(b)) == b


def test_Run_success() -> None:
  """Test Run with a command that succeeds."""
  result: subprocess.CompletedProcess[str] = base.Run(['echo', 'hello'])
  assert result.returncode == 0
  assert result.stdout.strip() == 'hello'


def test_Run_failure() -> None:
  """Test Run raises AssertionError on non-zero exit code."""
  with pytest.raises(AssertionError, match=r'Command failed \(exit='):
    base.Run(['false'])


def test_Run_with_cwd(tmp_path: pathlib.Path) -> None:
  """Test Run with cwd parameter."""
  result: subprocess.CompletedProcess[str] = base.Run(['pwd'], cwd=tmp_path)
  assert result.returncode == 0
  # resolve to handle macOS /private/tmp symlink
  assert pathlib.Path(result.stdout.strip()).resolve() == tmp_path.resolve()


def test_Run_with_env() -> None:
  """Test Run with env parameter."""
  result: subprocess.CompletedProcess[str] = base.Run(
    ['env'], env={'MY_TEST_VAR': 'test_value_42', 'PATH': '/usr/bin:/bin'}
  )
  assert 'MY_TEST_VAR=test_value_42' in result.stdout


def test_VersionCallCheck_success() -> None:
  """Test VersionCallCheck with matching version."""
  cli: pathlib.Path = pathlib.Path('/usr/bin/test-cli')
  expected_version: str = '1.2.3'
  mock_result: subprocess.CompletedProcess[str] = subprocess.CompletedProcess(
    args=['test-cli', '--version'],
    returncode=0,
    stdout='1.2.3\n',
    stderr='',
  )
  with unittest.mock.patch('transcrypto.utils.base.Run', return_value=mock_result):
    base.VersionCallCheck(cli, expected_version)  # Should not raise


def test_VersionCallCheck_version_mismatch() -> None:
  """Test VersionCallCheck with mismatched version."""
  cli: pathlib.Path = pathlib.Path('/usr/bin/test-cli')
  expected_version: str = '1.2.3'
  mock_result: subprocess.CompletedProcess[str] = subprocess.CompletedProcess(
    args=['test-cli', '--version'],
    returncode=0,
    stdout='2.0.0\n',
    stderr='',
  )
  with (
    unittest.mock.patch('transcrypto.utils.base.Run', return_value=mock_result),
    pytest.raises(base.Error, match=r'CLI version mismatch'),
  ):
    base.VersionCallCheck(cli, expected_version)


def test_VersionCallCheck_command_fails() -> None:
  """Test VersionCallCheck when the command fails."""
  cli: pathlib.Path = pathlib.Path('/usr/bin/test-cli')
  expected_version: str = '1.2.3'
  mock_result: subprocess.CompletedProcess[str] = subprocess.CompletedProcess(
    args=['test-cli', '--version'],
    returncode=1,
    stdout='',
    stderr='command not found',
  )
  with (
    unittest.mock.patch('transcrypto.utils.base.Run', return_value=mock_result),
    pytest.raises(base.Error, match=r'Failed:'),
  ):
    base.VersionCallCheck(cli, expected_version)
