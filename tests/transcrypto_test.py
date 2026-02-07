# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""transcrypto.py unittest.

Run with:
  poetry run pytest -vvv tests/transcrypto_test.py
"""

from __future__ import annotations

import io
import pathlib
import re
import sys

import pytest
from click import testing as click_testing
from rich import console as rich_console
from typer import testing

from transcrypto import transcrypto
from transcrypto.core import aes, bid
from transcrypto.utils import base
from transcrypto.utils import config as app_config
from transcrypto.utils import logging as tc_logging


@pytest.fixture(autouse=True)
def reset_cli() -> None:
  """Reset CLI singleton before each test."""
  tc_logging.ResetConsole()
  app_config.ResetConfig()


def CallCLI(args: list[str]) -> click_testing.Result:
  """Call the CLI with args.

  Args:
      args (list[str]): CLI arguments.

  Returns:
      click_testing.Result: CLI result.

  """
  return testing.CliRunner().invoke(transcrypto.app, args, env={'COLUMNS': '2000'})


def Out(res: click_testing.Result) -> str:
  """Return stripped CLI output.

  Args:
      res (click_testing.Result): CLI result.

  Returns:
      str: stripped CLI output.

  """
  return res.output.strip()


def OneToken(res: click_testing.Result) -> str:
  """Return CLI output as a single token with newlines removed.

  Args:
      res (click_testing.Result): CLI result.

  Returns:
      str: CLI output as a single token with newlines removed.

  """
  # Rich hard-wrap can insert newlines inside long tokens; normalize for token outputs.
  return Out(res).replace('\n', '')


ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')


def CLIOutput(res: click_testing.Result) -> str:
  """Return CLI output for assertions.

  Typer/Click may send errors to stderr and may add ANSI styling (especially
  when Rich is installed). Normalize that here so tests are stable across
  environments.

  Returns:
      str: cleaned CLI output.

  """
  stdout: str = getattr(res, 'stdout', '')
  stderr: str = getattr(res, 'stderr', '')
  combined: str = (stdout + stderr) if (stdout or stderr) else res.output
  return ANSI_ESCAPE_RE.sub('', combined)


def test_LoadObj_wrong_type_raises(tmp_path: pathlib.Path) -> None:
  """_LoadObj should raise if the on-disk object is not of the expected type."""
  path: pathlib.Path = tmp_path / 'obj.saved'
  # Save an AESKey object…
  aes_key = aes.AESKey(key256=b'\x00' * 32)
  transcrypto.SaveObj(aes_key, str(path), None)
  # …then try to load it expecting a completely different type.
  with pytest.raises(base.InputError, match=r'invalid type.*AESKey.*expected.*PublicBid'):
    transcrypto.LoadObj(str(path), None, bid.PublicBid512)  # expecting PublicBid, got AESKey


def test_cli_markdown_has_header() -> None:
  """Test CLI markdown command output has expected header."""
  res: click_testing.Result = CallCLI(['markdown'])
  assert res.exit_code == 0
  assert '# `transcrypto`' in res.output


def test_cli_version_exits_zero() -> None:
  """Test CLI --version shows version and exits zero."""
  res: click_testing.Result = CallCLI(['--version'])
  assert res.exit_code == 0
  assert transcrypto.__version__ in res.output  # type: ignore[attr-defined]


def test_cli_internal_parse_helpers_error_branches() -> None:
  """Cover small helper branches that are hard to hit via CLI parsing."""
  # ParseInt: empty string and invalid literal.
  with pytest.raises(base.InputError, match=r'invalid int'):
    transcrypto.ParseInt('   ')
  with pytest.raises(base.InputError, match=r'invalid int'):
    transcrypto.ParseInt('not_an_int')

  # ParseIntPairCLI: invalid pair formatting.
  with pytest.raises(base.InputError, match=r'invalid int\(s\)'):
    transcrypto.ParseIntPairCLI('1')
  with pytest.raises(base.InputError, match=r'invalid int'):
    transcrypto.ParseIntPairCLI('1:')
  with pytest.raises(base.InputError, match=r'invalid int'):
    transcrypto.ParseIntPairCLI(':2')


def test_transcrypto_run_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
  """Test transcrypto.Run() with no args exits cleanly."""
  monkeypatch.setattr(sys, 'argv', ['transcrypto'])
  with pytest.raises(SystemExit) as exc:
    transcrypto.Run()
  # No-args help behavior depends on Click/Typer; exit code is not important.
  assert exc.value.code in {0, 2}


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
  res: click_testing.Result = CallCLI(argv)
  assert res.exit_code in {0, 2}
  assert 'Usage:' in res.output


@pytest.mark.parametrize('subapp', ['rsa', 'elgamal', 'dsa', 'bid', 'sss', 'random', 'mod'])
def test_cli_subapps_show_help_when_no_subcommand(subapp: str) -> None:
  """Subapp-only invocations should show help."""
  res: click_testing.Result = CallCLI([subapp])
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
  """Exercise BytesFromText/BytesToText in all 3 branches."""
  b: bytes = transcrypto.BytesFromText(text, mode)
  # Convert to hex using the CLI helper to normalize
  hex_out: str = transcrypto.BytesToText(b, transcrypto.IOFormat.hex)
  assert hex_out == expect_hex
  # Round-trip each mode back to itself (bin/b64 produce readable strings)
  s_again: str = transcrypto.BytesToText(transcrypto.BytesFromText(text, mode), mode)
  # RAW returns original (utf-8), HEX and B64 return normalized encodings;
  # we just assert it doesn't crash and is non-empty.
  assert isinstance(s_again, str) and len(s_again) > 0


def test_markdown_includes_deep_path() -> None:
  """Ensure markdown docs include a representative deep path."""
  res: click_testing.Result = CallCLI(['markdown'])
  assert res.exit_code == 0
  assert "Loaded SSS share: 'sss-key.share.5'" in res.output


def test_require_keypath_rejects_directory(tmp_path: pathlib.Path) -> None:
  """Cover RequireKeyPath directory error path."""
  c = rich_console.Console(file=io.StringIO(), force_terminal=False, color_system=None, record=True)
  appconfig: app_config.AppConfig = app_config.InitConfig('test_app4', 'test4.bin')
  cfg = transcrypto.TransConfig(
    console=c,
    verbose=0,
    color=None,
    appconfig=appconfig,
    input_format=transcrypto.IOFormat.hex,
    output_format=transcrypto.IOFormat.hex,
    key_path=tmp_path,
    protect='',
  )
  with pytest.raises(base.InputError):
    transcrypto.RequireKeyPath(cfg, 'rsa')
