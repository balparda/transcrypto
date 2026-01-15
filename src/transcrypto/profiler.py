#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto Profiler command line interface.

See README.md for documentation on how to use.

Notes on the layout (quick mental model):

primes
dsa
doc md
"""

from __future__ import annotations

import argparse
# import pdb
import sys
from typing import Callable

from rich import console as rich_console

from . import base, modmath, dsa

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


def _BuildParser() -> argparse.ArgumentParser:  # pylint: disable=too-many-statements,too-many-locals
  """Construct the CLI argument parser (kept in sync with the docs)."""
  # ========================= main parser ==========================================================
  parser: argparse.ArgumentParser = argparse.ArgumentParser(
      prog='poetry run profiler',
      description=('profiler: CLI for TransCrypto Profiler, measure library performance.'),
      epilog=(
          'Examples:\n\n'
          '  # --- Primes ---\n'
          '  poetry run profiler -p -n 10 primes\n'
          '  poetry run profiler -n 20 dsa\n'
      ),
      formatter_class=argparse.RawTextHelpFormatter)
  sub = parser.add_subparsers(dest='command')

  # ========================= global flags =========================================================
  # -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG
  parser.add_argument(
      '-v', '--verbose', action='count', default=0,
      help='Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG)')

  thread_grp = parser.add_mutually_exclusive_group()
  thread_grp.add_argument(
      '-s', '--serial', action='store_true',
      help='If test can be serial, do it like that with no parallelization (default)')
  thread_grp.add_argument(
      '-p', '--parallel', action='store_true',
      help='If test can be parallelized into processes, do it like that')

  parser.add_argument(
      '-n', '--number', type=int, default=15,
      help='Number of experiments (repeats) for every measurement')
  parser.add_argument(
      '-c', '--confidence', type=int, default=98,
      help=('Confidence level to evaluate measurements at as int percentage points [50,99], '
            'inclusive, representing 50% to 99%'))

  parser.add_argument(
      '-b', '--bits', type=str, default='1000,9000,1000',
      help=('Bit lengths to investigate as "int,int,int"; behaves like arguments for range(), '
            'i.e., "start,stop,step", eg. "1000,3000,500" will investigate 1000,1500,2000,2500'))

  # ========================= Prime Generation =====================================================

  # Regular prime generation
  sub.add_parser(
      'primes',
      help='Measure regular prime generation.',
      epilog=('-n 30 -b 9000,11000,1000 primes\nStarting SERIAL regular primes test\n'
              '9000 → 38.88 s ± 14.74 s [24.14 s … 53.63 s]98%CI@30\n'
              '10000 → 41.26 s ± 22.82 s [18.44 s … 1.07 min]98%CI@30\nFinished in 40.07 min'))

  # DSA primes generation
  sub.add_parser(
      'dsa',
      help='Measure DSA prime generation.',
      epilog=('-p -n 2 -b 1000,1500,100 -c 80 dsa\nStarting PARALLEL DSA primes test\n'
              '1000 → 236.344 ms ± 273.236 ms [*0.00 s … 509.580 ms]80%CI@2\n'
              '1100 → 319.308 ms ± 639.775 ms [*0.00 s … 959.083 ms]80%CI@2\n'
              '1200 → 523.885 ms ± 879.981 ms [*0.00 s … 1.40 s]80%CI@2\n'
              '1300 → 506.285 ms ± 687.153 ms [*0.00 s … 1.19 s]80%CI@2\n'
              '1400 → 552.840 ms ± 47.012 ms [505.828 ms … 599.852 ms]80%CI@2\nFinished in 4.12 s'))

  # ========================= Markdown Generation ==================================================

  # Documentation generation
  doc: argparse.ArgumentParser = sub.add_parser(
      'doc', help='Documentation utilities. (Not for regular use: these are developer utils.)')
  doc_sub = doc.add_subparsers(dest='doc_command')
  doc_sub.add_parser(
      'md',
      help='Emit Markdown docs for the CLI (see README.md section "Creating a New Version").',
      epilog='doc md > profiler.md\n<<saves file>>')

  return parser


def _PrimeProfiler(
    prime_callable: Callable[[int], int],
    repeats: int, n_bits_range: tuple[int, int, int], confidence: float,
    console: rich_console.Console, /) -> None:
  primes: dict[int, list[float]] = {}
  for n_bits in range(*n_bits_range):
    # investigate for size n_bits
    primes[n_bits] = []
    for _ in range(repeats):
      with base.Timer(emit_log=False) as tmr:
        pr: int = prime_callable(n_bits)
      assert pr and pr.bit_length() == n_bits
      primes[n_bits].append(tmr.elapsed)
    # finished collecting n_bits-sized primes
    measurements: str = base.HumanizedMeasurements(
        primes[n_bits], parser=base.HumanizedSeconds, confidence=confidence)
    console.print(f'{n_bits} → {measurements}')


def main(argv: list[str] | None = None, /) -> int:  # pylint: disable=invalid-name,too-many-locals,too-many-branches,too-many-statements
  """Main entry point."""
  # build the parser and parse args
  parser: argparse.ArgumentParser = _BuildParser()
  args: argparse.Namespace = parser.parse_args(argv)
  # take care of global options
  console: rich_console.Console = base.InitLogging(args.verbose)

  try:
    # get the command, do basic checks and switch
    command: str = args.command.lower().strip() if args.command else ''
    repeats: int = 1 if args.number < 1 else args.number
    confidence: int = 55 if args.confidence < 55 else args.confidence
    confidence = 99 if confidence > 99 else confidence
    args.serial = True if (not args.serial and not args.parallel) else args.serial  # make default
    bits: tuple[int, ...] = tuple(int(x, 10) for x in args.bits.strip().split(','))
    if len(bits) != 3:
      raise base.InputError('-b/--bits should be 3 ints, like: start,stop,step; eg.: 1000,3000,500')
    with base.Timer(emit_log=False) as tmr:
      match command:
        # -------- Primes ----------
        case 'primes':
          console.print(f'Starting {"SERIAL" if args.serial else "PARALLEL"} regular primes test')
          _PrimeProfiler(
              lambda n: modmath.NBitRandomPrimes(n, serial=args.serial, n_primes=1).pop(),
              repeats, bits, confidence / 100.0, console)

        case 'dsa':
          console.print(f'Starting {"SERIAL" if args.serial else "PARALLEL"} DSA primes test')
          _PrimeProfiler(
              lambda n: dsa.NBitRandomDSAPrimes(n, n // 2, serial=args.serial)[0],
              repeats, bits, confidence / 100.0, console)

        # -------- Documentation ----------
        case 'doc':
          doc_command: str = (
              args.doc_command.lower().strip() if getattr(args, 'doc_command', '') else '')
          match doc_command:
            case 'md':
              console.print(base.GenerateCLIMarkdown(
                  'profiler', _BuildParser(), description=(
                      '`profiler` is a command-line utility that provides stats on TransCrypto '
                      'performance.')))
            case _:
              raise NotImplementedError()

        case _:
          parser.print_help()

    if command not in ('doc',):
      console.print(f'Finished in {tmr}')

  except NotImplementedError as err:
    console.print(f'Invalid command: {err}')
  except (base.Error, ValueError) as err:
    console.print(str(err))

  return 0


if __name__ == '__main__':
  sys.exit(main())
