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
import shutil
import subprocess  # noqa: S404
import sys
import venv
import zipfile

import pytest

import transcrypto

_APP_NAMES: set[str] = {'transcrypto', 'profiler'}


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
    check=False,
  )
  if result.returncode != 0:
    details: str = (
      f'Command failed (exit={result.returncode}): {cmd}\n\n'
      f'--- stdout ---\n{result.stdout}\n'
      f'--- stderr ---\n{result.stderr}\n'
    )
    raise AssertionError(details)
  return result


def _WheelHasConsoleScripts(wheel: pathlib.Path, scripts: set[str]) -> bool:
  """Return True if the wheel defines the given console scripts.

  Args:
      wheel (pathlib.Path): wheel path
      scripts (set[str]): set of console script names to check for

  Returns:
      bool: True if all specified console scripts are found in the wheel

  """
  try:
    with zipfile.ZipFile(wheel) as zf:
      entry_points: list[str] = [n for n in zf.namelist() if n.endswith('entry_points.txt')]
      if not entry_points:
        return False
      data: str = zf.read(entry_points[0]).decode('utf-8', errors='replace')
  except (OSError, zipfile.BadZipFile):
    return False
  # Minimal parse: ensure the [console_scripts] section contains the required names.
  in_console_scripts: bool = False
  found: set[str] = set()
  for raw_line in data.splitlines():
    line: str = raw_line.strip()
    if not line or line.startswith(('#', ';')):
      continue
    if line.startswith('[') and line.endswith(']'):
      in_console_scripts = line == '[console_scripts]'
      continue
    if in_console_scripts and '=' in line:
      name: str = line.split('=', 1)[0].strip()
      found.add(name)
  return scripts.issubset(found)


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
      bin_dir (Path): directory containing the console scripts
      name (str): name of the console script to find

  Raises:
      FileNotFoundError: if the console script is not found

  Returns:
      Path: path to the console script

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


def _EnsureWheel(repo: pathlib.Path, expected_version: str, /) -> pathlib.Path:
  """Build a wheel if needed; return path to the newest wheel in dist/.

  Args:
      repo (Path): path to the repository root
      expected_version (str): expected version string to match in the wheel filename

  Raises:
      AssertionError: if no wheel is found after building

  Returns:
      Path: path to the newest wheel in dist/

  """
  dist_dir: pathlib.Path = repo / 'dist'
  dist_dir.mkdir(exist_ok=True)
  # discover existing wheels
  wheels: list[pathlib.Path] = sorted(dist_dir.glob('*.whl'), key=lambda p: p.stat().st_mtime)
  # prefer an existing wheel that matches the current source version; otherwise build a new one.
  matching: list[pathlib.Path] = [w for w in wheels if f'-{expected_version}-' in w.name]
  if matching:
    newest: pathlib.Path = matching[-1]
    # if a stale wheel exists (e.g., built before console scripts were configured), rebuild.
    if _WheelHasConsoleScripts(newest, _APP_NAMES):
      return newest
  # build a new wheel
  poetry: str | None = shutil.which('poetry')
  if poetry is None:
    pytest.skip('Poetry not found on PATH; cannot build wheel for integration test.')
  _Run([poetry, 'build', '-f', 'wheel'], cwd=repo)
  # discover newly built wheels
  wheels = sorted(dist_dir.glob('*.whl'), key=lambda p: p.stat().st_mtime)
  if not wheels:
    raise AssertionError('Wheel build succeeded but no .whl found in dist/.')
  return wheels[-1]


@pytest.mark.integration
def test_installed_cli_smoke(tmp_path: pathlib.Path) -> None:
  """Build wheel, install into a clean venv, run the installed CLIs."""
  repo: pathlib.Path = _RepoRoot()
  expected_version: str = transcrypto.__version__
  wheel: pathlib.Path = _EnsureWheel(repo, expected_version)
  # 1) create an isolated venv (not using Poetry's .venv on purpose)
  venv_dir: pathlib.Path = tmp_path / 'venv'
  venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
  vpy, bin_dir = _VenvPaths(venv_dir)
  # 2) install the wheel into the venv
  _Run([str(vpy), '-m', 'pip', 'install', '--upgrade', 'pip'])
  _Run([str(vpy), '-m', 'pip', 'install', str(wheel)])
  # 3) run the installed console scripts
  transcrypto_cli: pathlib.Path = _FindConsoleScript(bin_dir, 'transcrypto')
  profiler_cli: pathlib.Path = _FindConsoleScript(bin_dir, 'profiler')
  # versions should match the source version (kept in sync with pyproject.toml)
  r: subprocess.CompletedProcess[str] = _Run([str(transcrypto_cli), '--version'])
  assert r.stdout.strip() == expected_version
  r = _Run([str(profiler_cli), '--version'])
  assert r.stdout.strip() == expected_version
  # basic command smoke tests; use --no-color to avoid ANSI codes in asserts.
  r = _Run([str(transcrypto_cli), '--no-color', 'gcd', '462', '1071'])
  assert r.stdout.strip() == '21'
  assert '\x1b[' not in r.stdout  # no ANSI escape sequences
  assert '\x1b[' not in r.stderr
  # simple profiler command
  r = _Run([str(profiler_cli), '--no-color', '-n', '1', '-b', '16,17,1', 'primes'])
  assert 'Finished in' in r.stdout
  assert '\x1b[' not in r.stdout
  assert '\x1b[' not in r.stderr
