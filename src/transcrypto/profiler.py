#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto Profiler command line interface.

See README.md for documentation on how to use.

Notes on the layout (quick mental model):

dsa shared|new|sign|verify|rawsign|rawverify
doc md
"""

from __future__ import annotations

import argparse
import logging
# import pdb
import sys

from . import base

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


def _BuildParser() -> argparse.ArgumentParser:  # pylint: disable=too-many-statements,too-many-locals
  """Construct the CLI argument parser (kept in sync with the docs)."""
  # ========================= main parser ==========================================================
  parser: argparse.ArgumentParser = argparse.ArgumentParser(
      prog='poetry run profiler',
      description=('profiler: CLI for TransCrypto.'),
      epilog=(
          'Examples:\n\n'
          '  # --- Randomness ---\n'
          '  poetry run profiler random bits 16\n'
      ),
      formatter_class=argparse.RawTextHelpFormatter)
  sub = parser.add_subparsers(dest='command')

  # ========================= global flags =========================================================
  # -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG
  parser.add_argument(
      '-v', '--verbose', action='count', default=0,
      help='Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG)')

  # ========================= randomness ===========================================================

  # Cryptographically secure randomness
  p_rand: argparse.ArgumentParser = sub.add_parser(
      'random', help='Cryptographically secure randomness, from the OS CSPRNG.')
  rsub = p_rand.add_subparsers(dest='rand_command')

  # Random bits
  p_rand_bits: argparse.ArgumentParser = rsub.add_parser(
      'bits',
      help='Random integer with exact bit length = `bits` (MSB will be 1).',
      epilog='random bits 16\n36650')
  p_rand_bits.add_argument('bits', type=int, help='Number of bits, ≥ 8')

  # ========================= Markdown Generation ==================================================

  # Documentation generation
  doc: argparse.ArgumentParser = sub.add_parser(
      'doc', help='Documentation utilities. (Not for regular use: these are developer utils.)')
  doc_sub = doc.add_subparsers(dest='doc_command')
  doc_sub.add_parser(
      'md',
      help='Emit Markdown docs for the CLI (see README.md section "Creating a New Version").',
      epilog=('doc md > CLI.md\n'
              '$ ./tools/inject_md_includes.py\n'
              'inject: README.md updated with included content'))

  return parser


def main(argv: list[str] | None = None, /) -> int:  # pylint: disable=invalid-name,too-many-locals,too-many-branches,too-many-statements
  """Main entry point."""
  # build the parser and parse args
  parser: argparse.ArgumentParser = _BuildParser()
  args: argparse.Namespace = parser.parse_args(argv)
  # take care of global options
  levels: list[int] = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
  logging.basicConfig(
      level=levels[min(args.verbose, len(levels) - 1)],  # type: ignore
      format=getattr(base, 'LOG_FORMAT', '%(levelname)s:%(message)s'))
  logging.captureWarnings(True)

  try:
    # get the command, do basic checks and switch
    command: str = args.command.lower().strip() if args.command else ''
    match command:
      # -------- TODO ----------
      case 'TODO':
        pass

      # -------- Documentation ----------
      case 'doc':
        doc_command: str = (
            args.doc_command.lower().strip() if getattr(args, 'doc_command', '') else '')
        match doc_command:
          case 'md':
            print(base.GenerateCLIMarkdown(
                'profiler', _BuildParser(), description=(
                    '`profiler` is a command-line utility that provides stats on TransCrypto '
                    'performance.')))
          case _:
            raise NotImplementedError()

      case _:
        parser.print_help()

  except NotImplementedError as err:
    print(f'Invalid command: {err}')
  except (base.Error, ValueError) as err:
    print(str(err))

  return 0


if __name__ == '__main__':
  sys.exit(main())
