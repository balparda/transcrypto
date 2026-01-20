# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""safetrans.py unittest."""

from __future__ import annotations

import io
import runpy
import sys
from contextlib import redirect_stdout

import pytest

from transcrypto import base, safetrans

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = base.__version__  # tests inherit version from module


@pytest.fixture(autouse=True)
def _reset_base_logging() -> None:  # type: ignore
  base.ResetConsole()


def _RunCLI(argv: list[str]) -> tuple[int, str]:
  """Run the CLI with argv, capture stdout, return (exit_code, stdout_stripped)."""
  buf = io.StringIO()
  with redirect_stdout(buf):
    code: int = safetrans.main(argv)
  out: str = buf.getvalue().strip()
  return (code, out)


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
  monkeypatch.setattr(sys, 'argv', ['safetrans.py'])
  # Run the module by *name* with run_name="__main__" so relative imports work.
  with pytest.raises(SystemExit) as exc:
    runpy.run_module('transcrypto.safetrans', run_name='__main__')
  assert exc.value.code == 0


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
