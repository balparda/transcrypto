# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""profiler.py unittest.

Run this test with:

poetry run pytest -vvv tests/profiler_test.py
"""

from __future__ import annotations

import sys
from collections import abc

import pytest
import typeguard
from click import testing as click_testing
from typer import testing

from transcrypto import profiler
from transcrypto.cli import clibase


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
    return testing.CliRunner().invoke(profiler.app, args)


@pytest.fixture(autouse=True)
def reset_cli_logging_singletons() -> abc.Generator[None]:
  """Reset global console/logging state between tests.

  The CLI callback initializes a global Rich console singleton via InitLogging().
  Tests invoke the CLI multiple times across test cases, so we must reset that
  singleton to keep tests isolated.
  """
  clibase.ResetConsole()
  yield  # noqa: PT022


def test_profiler_version_and_run(monkeypatch: pytest.MonkeyPatch) -> None:
  """Check profiler --version and Run() paths work as expected."""
  # Version path in profiler.Main
  with typeguard.suppress_type_checks():
    res: click_testing.Result = testing.CliRunner().invoke(profiler.app, ['--version'])
  assert res.exit_code == 0
  assert profiler.__version__ in res.output  # type: ignore[attr-defined]
  # Run() path
  monkeypatch.setattr(sys, 'argv', ['profiler'])
  with pytest.raises(SystemExit) as exc:
    profiler.Run()
  assert exc.value.code in {0, 2}


def test_primes_serial() -> None:
  """Primes command (serial) prints expected output."""
  res: click_testing.Result = _CallCLI(['-n', '3', '-b', '300,900,300', '-c', '80', 'primes'])
  assert res.exit_code == 0
  lines: list[str] = res.output.strip().splitlines()
  assert len(lines) == 4
  assert lines[0].strip() == 'Starting SERIAL regular primes test'
  assert '300 →' in lines[1] and '80%CI@3' in lines[1]
  assert '600 →' in lines[2] and '80%CI@3' in lines[2]
  assert 'Finished in' in lines[3]


def test_dsa_parallel() -> None:
  """DSA command (parallel) prints expected output."""
  res: click_testing.Result = _CallCLI(
    ['--no-serial', '-n', '2', '-b', '300,800,200', '-c', '70', 'dsa']
  )
  assert res.exit_code == 0
  lines = res.output.strip().splitlines()
  assert len(lines) == 5
  assert lines[0].strip() == 'Starting PARALLEL DSA primes test'
  assert '300 →' in lines[1] and '70%CI@2' in lines[1]
  assert '500 →' in lines[2] and '70%CI@2' in lines[2]
  assert '700 →' in lines[3] and '70%CI@2' in lines[3]
  assert 'Finished in' in lines[4]


def test_dsa_invalid_bits() -> None:
  """DSA with invalid bits argument returns a non-zero exit and error message."""
  res: click_testing.Result = _CallCLI(
    ['--no-serial', '-n', '2', '-b', '300,800', '-c', '70', 'dsa']
  )
  assert res.exit_code != 0
  # Different Click/Typer versions (and Python 3.14) may emit different
  # error output (detailed message vs. generic usage). Accept either the
  # explicit message or a generic usage/error output to be robust.
  assert '-b/--bits should be 3 ints' in res.output or 'Usage:' in res.output


def test_cli_doc_md_has_header() -> None:
  """Test CLI doc md command output has expected header."""
  res: click_testing.Result = _CallCLI(['markdown'])
  assert res.exit_code == 0
  assert '# `profiler`' in res.output
