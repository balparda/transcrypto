#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto markdown injector."""

from __future__ import annotations

import pathlib
import re
import sys


INCLUDE_BLOCK_RE = re.compile(
  r'(?P<prefix><!-- INCLUDE:(?P<path>[^>]+)\s+START\s*-->)'
  r'(.*?)'
  r'(?P<suffix><!-- INCLUDE:(?P=path)\s+END\s*-->)',
  flags=re.DOTALL | re.IGNORECASE,
)


def _read(p: pathlib.Path) -> str:
  try:
    return p.read_text(encoding='utf-8')
  except FileNotFoundError:
    raise SystemExit(f'error: file not found: {p}')


def _write(p: pathlib.Path, text: str) -> None:
  p.write_text(text, encoding='utf-8')


def inject_includes(readme_path: str = 'README.md', repo_root: str = '.') -> int:
  root = pathlib.Path(repo_root).resolve()
  readme = root / readme_path
  orig = _read(readme)

  changed = False
  def _repl(match: re.Match[str]) -> str:
    nonlocal changed
    rel_path = match.group('path').strip()
    src = root / rel_path
    content = _read(src)
    # ensure a clean newline sandwich between markers
    injected = f'{match.group("prefix")}\n{content.rstrip()}\n{match.group("suffix")}'
    changed = True
    return injected

  new = INCLUDE_BLOCK_RE.sub(_repl, orig)

  if new == orig:
    # no blocks found OR no change; tell the user what happened
    if '<!-- INCLUDE:' not in orig:
      print('inject: no INCLUDE blocks found; nothing to do')
    else:
      print('inject: INCLUDE blocks present but up-to-date')
    return 0

  _write(readme, new)
  print('inject: README.md updated with included content')
  return 0


if __name__ == '__main__':
  sys.exit(inject_includes())
