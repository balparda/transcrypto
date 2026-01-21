# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: build wheel, install into a fresh venv, run the installed CLI.

Why this exists (vs normal unit tests):
- Unit tests (CliRunner) validate CLI wiring while running from the source tree.
- This test validates *packaging*: the wheel builds, installs, and the console script works.

What we verify:
- `mycli --version` prints the expected version.
- `mycli --no-color hello Ada` runs successfully and produces non-ANSI output.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess  # noqa: S404
import sys
import venv

import pytest

import mycli


def _RepoRoot() -> pathlib.Path:
  # tests_integration/test_installed_cli.py -> repo root is parents[1]
  return pathlib.Path(__file__).resolve().parents[1]


def _Run(
  cmd: list[str],
  *,
  cwd: pathlib.Path | None = None,
  env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
  """Run a command; return the completed process; assert success with useful diagnostics.

  Args:
      cmd (list[str]): command
      cwd (Path | None, optional): Path. Defaults to None.
      env (dict[str, str] | None, optional): Environment. Defaults to None.

  Raises:
      AssertionError: invalid return code

  Returns:
      subprocess.CompletedProcess[str]: result

  """
  result: subprocess.CompletedProcess[str] = subprocess.run(  # noqa: S603
    cmd,
    cwd=str(cwd) if cwd is not None else None,
    env=env,
    text=True,
    capture_output=True,
    check=True,
  )
  if result.returncode != 0:
    details: str = (
      f'Command failed (exit={result.returncode}): {cmd}\n\n'
      f'--- stdout ---\n{result.stdout}\n'
      f'--- stderr ---\n{result.stderr}\n'
    )
    raise AssertionError(details)
  return result


def _VenvPaths(venv_dir: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
  """Return virtual environment paths for python and /bin.

  Args:
      venv_dir (Path): path to venv

  Returns:
      tuple[Path, Path]: (venv_python, venv_bin_dir)

  """
  if sys.platform.startswith('win'):
    bin_dir: pathlib.Path = venv_dir / 'Scripts'
    py: pathlib.Path = bin_dir / 'python.exe'
  else:
    bin_dir = venv_dir / 'bin'
    py = bin_dir / 'python'
  return py, bin_dir


def _FindConsoleScript(bin_dir: pathlib.Path, name: str) -> pathlib.Path:
  """Find the installed console script in the venv (platform-specific).

  Args:
      bin_dir (Path): _description_
      name (str): _description_

  Raises:
      FileNotFoundError: _description_

  Returns:
      Path: _description_

  """
  # Windows may have .exe/.cmd; *nix is typically just the name
  candidates: list[pathlib.Path] = [
    bin_dir / name,
    bin_dir / f'{name}.exe',
    bin_dir / f'{name}.cmd',
  ]
  for p in candidates:
    if p.exists():
      return p
  raise FileNotFoundError(f'Could not find console script {name!r} in {bin_dir}')


def _EnsureWheel(repo: pathlib.Path) -> pathlib.Path:
  """Build a wheel if needed; return path to the newest wheel in dist/.

  Args:
      repo (Path): _description_

  Raises:
      AssertionError: _description_

  Returns:
      Path: _description_

  """
  dist_dir: pathlib.Path = repo / 'dist'
  dist_dir.mkdir(exist_ok=True)

  wheels: list[pathlib.Path] = sorted(dist_dir.glob('*.whl'), key=lambda p: p.stat().st_mtime)
  if wheels:
    return wheels[-1]

  poetry: str | None = shutil.which('poetry')
  if poetry is None:
    pytest.skip('Poetry not found on PATH; cannot build wheel for integration test.')

  _Run([poetry, 'build', '-f', 'wheel'], cwd=repo)

  wheels = sorted(dist_dir.glob('*.whl'), key=lambda p: p.stat().st_mtime)
  if not wheels:
    raise AssertionError('Wheel build succeeded but no .whl found in dist/.')
  return wheels[-1]


@pytest.mark.integration
def test_installed_cli_smoke(tmp_path: pathlib.Path) -> None:
  """Build wheel, install into a clean venv, run the installed CLI."""
  repo: pathlib.Path = _RepoRoot()
  wheel: pathlib.Path = _EnsureWheel(repo)

  # 1) Create an isolated venv (not using Poetry's .venv on purpose)
  venv_dir: pathlib.Path = tmp_path / 'venv'
  venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)

  vpy, bin_dir = _VenvPaths(venv_dir)

  # 2) Install the wheel into the venv
  _Run([str(vpy), '-m', 'pip', 'install', '--upgrade', 'pip'])
  _Run([str(vpy), '-m', 'pip', 'install', str(wheel)])

  # 3) Run the installed console script
  cli: pathlib.Path = _FindConsoleScript(bin_dir, 'mycli')

  # Version should match the source version (template keeps these in sync)
  # This specifically validates that the entrypoint works *when installed*.
  r: subprocess.CompletedProcess[str] = _Run([str(cli), '--version'])
  assert r.stdout.strip() == mycli.__version__

  # Basic command smoke test; use --no-color to avoid ANSI codes in asserts.
  r = _Run([str(cli), '--no-color', 'hello', 'Ada'])

  assert 'Hello, Ada!' in r.stdout
  assert '\x1b[' not in r.stdout  # no ANSI escape sequences
  assert '\x1b[' not in r.stderr
