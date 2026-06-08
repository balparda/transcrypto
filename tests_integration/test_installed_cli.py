# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: build wheel, install into a fresh venv, run installed console scripts.

Run this with: make cov
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess  # noqa: S404

import pytest

import transcrypto
from transcrypto.utils import base


@pytest.mark.integration
@pytest.mark.slow
def test_installed_cli_smoke() -> None:
  """Test the installed CLI from the current environment."""
  # find the installed console script; will raise if not found
  tr_path: str | None = shutil.which('transcrypto')
  if tr_path is None:
    pytest.fail('Console script "transcrypto" not found in PATH')
  pr_path: str | None = shutil.which('profiler')
  if pr_path is None:
    pytest.fail('Console script "profiler" not found in PATH')
  # verify version
  base.VersionCallCheck(pathlib.Path(tr_path), transcrypto.__version__)
  # basic command smoke tests
  _transcrypto_call(pathlib.Path(tr_path))
  _profiler_call(pathlib.Path(pr_path))


def _transcrypto_call(cli: pathlib.Path) -> None:
  # basic command smoke tests; use --no-color to avoid ANSI codes in asserts.
  r: subprocess.CompletedProcess[str] = base.Run(
    # run
    [str(cli), '--no-color', 'gcd', '462', '1071']
  )
  assert r.stdout.strip() == '21'
  assert '\x1b[' not in r.stdout  # no ANSI escape sequences
  assert '\x1b[' not in r.stderr


def _profiler_call(cli: pathlib.Path) -> None:
  # simple profiler command
  r: subprocess.CompletedProcess[str] = base.Run(
    # run
    [
      str(cli),
      '--no-color',
      '-n',
      '1',
      '-b',
      '16,17,1',
      'primes',
    ]
  )
  assert 'Finished in' in r.stdout
  assert '\x1b[' not in r.stdout  # no ANSI escape sequences
  assert '\x1b[' not in r.stderr
