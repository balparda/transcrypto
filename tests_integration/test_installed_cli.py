# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: build wheel, install into a fresh venv, run installed console scripts.

Why this exists (vs normal unit tests):
- Unit tests (CliRunner) validate CLI wiring while running from the source tree.
- This test validates *packaging*: the wheel builds, installs, and the console scripts work.

What we verify:
- `transcrypto --version` prints the expected version.
- `profiler --version` prints the expected version.
- Both CLIs run a small `--no-color` command successfully and produce non-ANSI output.

Run this with:

poetry run pytest -vvv -q tests_integration
"""

from __future__ import annotations

import pathlib

import pytest

import transcrypto
from transcrypto.utils import base, config

_APP_NAME: str = 'transcrypto'
_APP_NAMES: set[str] = {'transcrypto', 'profiler'}


@pytest.mark.integration
def test_installed_cli_smoke(tmp_path: pathlib.Path) -> None:
  """Build wheel, install into a clean venv, run the installed CLIs."""
  repo_root: pathlib.Path = pathlib.Path(__file__).resolve().parents[1]
  expected_version: str = transcrypto.__version__
  vpy, bin_dir = config.EnsureAndInstallWheel(repo_root, tmp_path, expected_version, _APP_NAMES)
  cli_paths: dict[str, pathlib.Path] = config.EnsureConsoleScriptsPrintExpectedVersion(
    vpy, bin_dir, expected_version, _APP_NAMES
  )
  # basic command smoke tests
  _transcrypto_call(cli_paths)
  _profiler_call(cli_paths)


def _transcrypto_call(cli_paths: dict[str, pathlib.Path], /) -> None:
  # basic command smoke tests; use --no-color to avoid ANSI codes in asserts.
  r = base.Run([str(cli_paths['transcrypto']), '--no-color', 'gcd', '462', '1071'])
  assert r.stdout.strip() == '21'
  assert '\x1b[' not in r.stdout  # no ANSI escape sequences
  assert '\x1b[' not in r.stderr


def _profiler_call(cli_paths: dict[str, pathlib.Path], /) -> None:
  # simple profiler command
  r = base.Run([str(cli_paths['profiler']), '--no-color', '-n', '1', '-b', '16,17,1', 'primes'])
  assert 'Finished in' in r.stdout
  assert '\x1b[' not in r.stdout
  assert '\x1b[' not in r.stderr
