# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto Profiler command line interface.

See <profiler.md> for documentation on how to use. Quick examples:

 --- Primes / DSA ---
poetry run profiler -n 10 primes
poetry run profiler --no-serial -n 20 dsa

 --- Markdown ---
poetry run profiler markdown > profiler.md

Test this CLI with:

poetry run pytest -vvv tests/profiler_test.py
"""

from __future__ import annotations

import dataclasses
from collections import abc

import typer
from rich import console as rich_console

from transcrypto.cli import clibase
from transcrypto.core import dsa, modmath
from transcrypto.utils import human, timer
from transcrypto.utils import logging as tc_logging

from . import __version__


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class ProfilerConfig(clibase.CLIConfig):
  """CLI global context, storing the configuration.

  Attributes:
    serial (bool): Whether to run profiling serially (vs parallel)
    repeats (int): Number of repetitions for each profiling run
    confidence (int): Confidence level percentage for statistical analysis
    bits (tuple[int, int, int]): Bit sizes range (start, stop, step) for profiling

  """

  serial: bool
  repeats: int
  confidence: int
  bits: tuple[int, int, int]


# CLI app setup, this is an important object and can be imported elsewhere and called
app = typer.Typer(
  add_completion=True,
  no_args_is_help=True,
  help='profiler: CLI for TransCrypto Profiler, measure library performance.',
  epilog=(
    'Examples:\n\n\n\n'
    '# --- Primes / DSA ---\n\n'
    'poetry run profiler -n 10 primes\n\n'
    'poetry run profiler --no-serial -n 20 dsa\n\n\n\n'
    '# --- Markdown ---\n\n'
    'poetry run profiler markdown > profiler.md'
  ),
)


def Run() -> None:
  """Run the CLI."""
  app()


@app.callback(
  invoke_without_command=True,  # have only one; this is the "constructor"
  help='Profile TransCrypto library performance.',
)
@clibase.CLIErrorGuard
def Main(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,  # global context
  version: bool = typer.Option(False, '--version', help='Show version and exit.'),
  verbose: int = typer.Option(
    0,
    '-v',
    '--verbose',
    count=True,
    help='Verbosity (nothing=ERROR, -v=WARNING, -vv=INFO, -vvv=DEBUG).',
    min=0,
    max=3,
  ),
  color: bool | None = typer.Option(
    None,
    '--color/--no-color',
    help=(
      'Force enable/disable colored output (respects NO_COLOR env var if not provided). '
      'Defaults to having colors.'  # state default because None default means docs don't show it
    ),
  ),
  serial: bool = typer.Option(
    True,
    '--serial/--no-serial',
    help='Execute operation serially (i.e. do not use threads/multiprocessing).',
  ),
  repeats: int = typer.Option(
    15,
    '-n',
    '--number',
    help='Number of experiments (repeats) for every measurement.',
    min=1,
    max=1000,
  ),
  confidence: int = typer.Option(
    98,
    '-c',
    '--confidence',
    help=(
      'Confidence level to evaluate measurements at as int percentage points [50,99], '
      'inclusive, representing 50% to 99%'
    ),
    min=50,
    max=99,
  ),
  bits: str = typer.Option(
    '1000,9000,1000',
    '-b',
    '--bits',
    help=(
      'Bit lengths to investigate as [green]"int,int,int"[/]; behaves like arguments for range(), '
      'i.e., [green]"start,stop,step"[/], eg. [green]"1000,3000,500"[/] will investigate '
      '[yellow]1000,1500,2000,2500[/]'
    ),
  ),
) -> None:
  if version:
    typer.echo(__version__)
    raise typer.Exit(0)
  # initialize logging and get console
  console: rich_console.Console
  console, verbose, color = tc_logging.InitLogging(
    verbose,
    color=color,
    include_process=False,  # decide if you want process names in logs
    soft_wrap=False,  # decide if you want soft wrapping of long lines
  )
  # create context with the arguments we received
  int_bits: tuple[int, ...] = tuple(int(x, 10) for x in bits.strip().split(','))
  if len(int_bits) != 3:  # noqa: PLR2004
    raise typer.BadParameter(
      '-b/--bits should be 3 ints, like: start,stop,step; eg.: 1000,3000,500'
    )
  ctx.obj = ProfilerConfig(
    console=console,
    verbose=verbose,
    color=color,
    serial=serial,
    repeats=repeats,
    confidence=confidence,
    bits=(int_bits[0], int_bits[1], int_bits[2]),
  )


@app.command(
  'primes',
  help='Measure regular prime generation.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run profiler -n 30 -b 9000,11000,1000 primes\n\n'
    'Starting [yellow]SERIAL regular primes[/] test\n\n'
    '9000 → 38.88 s ± 14.74 s [24.14 s … 53.63 s]98%CI@30\n\n'
    '10000 → 41.26 s ± 22.82 s [18.44 s … 1.07 min]98%CI@30\n\n'
    'Finished in 40.07 min'
  ),
)
@clibase.CLIErrorGuard
def Primes(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: ProfilerConfig = ctx.obj  # get application global config
  config.console.print(
    f'Starting [yellow]{"SERIAL" if config.serial else "PARALLEL"} regular primes[/] test'
  )
  _PrimeProfiler(
    lambda n: modmath.NBitRandomPrimes(n, serial=config.serial, n_primes=1).pop(),
    config.console,
    config.repeats,
    config.bits,
    config.confidence / 100.0,
  )


@app.command(
  'dsa',
  help='Measure DSA prime generation.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run profiler --no-serial -n 2 -b 1000,1500,100 -c 80 dsa\n\n'
    'Starting [yellow]PARALLEL DSA primes[/] test\n\n'
    '1000 → 236.344 ms ± 273.236 ms [*0.00 s … 509.580 ms]80%CI@2\n\n'
    '1100 → 319.308 ms ± 639.775 ms [*0.00 s … 959.083 ms]80%CI@2\n\n'
    '1200 → 523.885 ms ± 879.981 ms [*0.00 s … 1.40 s]80%CI@2\n\n'
    '1300 → 506.285 ms ± 687.153 ms [*0.00 s … 1.19 s]80%CI@2\n\n'
    '1400 → 552.840 ms ± 47.012 ms [505.828 ms … 599.852 ms]80%CI@2\n\n'
    'Finished in 4.12 s'
  ),
)
@clibase.CLIErrorGuard
def DSA(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: ProfilerConfig = ctx.obj  # get application global config
  config.console.print(
    f'Starting [yellow]{"SERIAL" if config.serial else "PARALLEL"} DSA primes[/] test'
  )
  _PrimeProfiler(
    lambda n: dsa.NBitRandomDSAPrimes(n, n // 2, serial=config.serial)[0],
    config.console,
    config.repeats,
    config.bits,
    config.confidence / 100.0,
  )


@app.command(
  'markdown',
  help='Emit Markdown docs for the CLI (see README.md section "Creating a New Version").',
  epilog='Example:\n\n\n\n$ poetry run profiler markdown > profiler.md\n\n<<saves CLI doc>>',
)
@clibase.CLIErrorGuard
def Markdown() -> None:  # documentation is help/epilog/args # noqa: D103
  console: rich_console.Console = tc_logging.Console()
  console.print(clibase.GenerateTyperHelpMarkdown(app, prog_name='profiler'))


def _PrimeProfiler(
  prime_callable: abc.Callable[[int], int],
  console: rich_console.Console,
  repeats: int,
  n_bits_range: tuple[int, int, int],
  confidence: float,
  /,
) -> None:
  with timer.Timer(emit_log=False) as total_time:
    primes: dict[int, list[float]] = {}
    for n_bits in range(*n_bits_range):
      # investigate for size n_bits
      primes[n_bits] = []
      for _ in range(repeats):
        with timer.Timer(emit_log=False) as run_time:
          pr: int = prime_callable(n_bits)
        assert pr  # noqa: S101
        assert pr.bit_length() == n_bits  # noqa: S101
        primes[n_bits].append(run_time.elapsed)
      # finished collecting n_bits-sized primes
      measurements: str = human.HumanizedMeasurements(
        primes[n_bits], parser=human.HumanizedSeconds, confidence=confidence
      )
      console.print(f'{n_bits} → {measurements}')
  console.print(f'Finished in {total_time}')
