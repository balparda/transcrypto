# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""profiler.py unittest."""

from __future__ import annotations

import io
import runpy
import sys
from contextlib import redirect_stdout

import pytest

from transcrypto import base, profiler

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = base.__version__  # tests inherit version from module


@pytest.fixture(autouse=True)
def _reset_base_logging() -> None:  # type: ignore
  base.ResetConsole()


def _RunCLI(argv: list[str]) -> tuple[int, str]:
  """Run the CLI with argv, capture stdout, return (exit_code, stdout_stripped)."""
  buf = io.StringIO()
  with redirect_stdout(buf):
    code: int = profiler.main(argv)
  out: str = buf.getvalue().strip()
  return (code, out)


def test_profiler_primes() -> None:
  """Test."""
  code: int
  out: str
  code, out = _RunCLI(['-n', '3', '-b', '300,900,300', '-c', '80', 'primes'])
  assert code == 0
  lines: list[str] = out.splitlines()
  assert len(lines) == 4
  assert lines[0] == 'Starting SERIAL regular primes test'
  assert '300 →' in lines[1] and '80%CI@3' in lines[1]
  assert '600 →' in lines[2] and '80%CI@3' in lines[2]
  assert 'Finished in' in lines[3]
  code, out = _RunCLI(['-p', '-n', '2', '-b', '300,800,200', '-c', '70', 'dsa'])
  assert code == 0
  lines = out.splitlines()
  assert len(lines) == 5
  assert lines[0] == 'Starting PARALLEL DSA primes test'
  assert '300 →' in lines[1] and '70%CI@2' in lines[1]
  assert '500 →' in lines[2] and '70%CI@2' in lines[2]
  assert '700 →' in lines[3] and '70%CI@2' in lines[3]
  assert 'Finished in' in lines[4]
  code, out = _RunCLI(['-p', '-n', '2', '-b', '300,800', '-c', '70', 'dsa'])
  assert code == 0 and '-b/--bits should be 3 ints' in out


def test_cli_doc_md_has_header() -> None:
  """Test CLI doc md command output has expected header."""
  code, out = _RunCLI(['doc', 'md'])
  assert code == 0
  assert '# `profiler` Command-Line Interface' in out


@pytest.mark.parametrize(
  'argv',
  [
    ['doc'],
  ],
)
def test_not_implemented_error_paths(argv: list[str]) -> None:
  """Test CLI paths that raise NotImplementedError."""
  code, out = _RunCLI(argv)
  assert code == 0
  assert 'Invalid command' in out


@pytest.mark.filterwarnings(r'ignore:.*found in sys.modules.*:RuntimeWarning')
def test_run_entrypoint_block(monkeypatch: pytest.MonkeyPatch) -> None:
  """Execute the `if __name__ == '__main__'` block to cover the last lines."""
  # Make the CLI think it was invoked with no args → prints help then exits(0).
  monkeypatch.setattr(sys, 'argv', ['profiler.py'])
  # Run the module by *name* with run_name="__main__" so relative imports work.
  with pytest.raises(SystemExit) as exc:
    runpy.run_module('transcrypto.profiler', run_name='__main__')
  assert exc.value.code == 0
