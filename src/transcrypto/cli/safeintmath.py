# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto safe CLI: Integer mathematics commands."""

from __future__ import annotations

import click
import typer

from transcrypto import safecrypto
from transcrypto.cli import clibase
from transcrypto.core import modmath
from transcrypto.utils import saferandom

# ================================= "RANDOM" COMMAND ===============================================


random_app = typer.Typer(
  no_args_is_help=True,
  help='Cryptographically secure randomness, from the OS CSPRNG.',
)
safecrypto.app.add_typer(random_app, name='random')


@random_app.command(
  'bits',
  help='Random integer with exact bit length = `bits` (MSB will be 1).',
  epilog=('Example:\n\n\n\n$ poetry run safecrypto random bits 16\n\n36650'),
)
@clibase.CLIErrorGuard
def RandomBits(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  bits: int = typer.Argument(..., min=8, help='Number of bits, ≥ 8'),
) -> None:
  config: safecrypto.TransConfig = ctx.obj
  config.console.print(saferandom.RandBits(bits))


@random_app.command(
  'int',
  help='Uniform random integer in `[min, max]` range, inclusive.',
  epilog=('Example:\n\n\n\n$ poetry run safecrypto random int 1000 2000\n\n1628'),
)
@clibase.CLIErrorGuard
def RandomInt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  min_: str = typer.Argument(..., help='Minimum, ≥ 0'),
  max_: str = typer.Argument(..., help='Maximum, > `min`'),
) -> None:
  config: safecrypto.TransConfig = ctx.obj
  min_i: int = safecrypto.ParseInt(min_, min_value=0)
  max_i: int = safecrypto.ParseInt(max_, min_value=min_i + 1)
  config.console.print(saferandom.RandInt(min_i, max_i))


@random_app.command(
  'bytes',
  help='Generates `n` cryptographically secure random bytes.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safecrypto random bytes 32\n\n'
    '6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f'
  ),
)
@clibase.CLIErrorGuard
def RandomBytes(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  n: int = typer.Argument(..., min=1, help='Number of bytes, ≥ 1'),
) -> None:
  config: safecrypto.TransConfig = ctx.obj
  config.console.print(safecrypto.BytesToText(saferandom.RandBytes(n), config.output_format))


@random_app.command(
  'prime',
  help='Generate a random prime with exact bit length = `bits` (MSB will be 1).',
  epilog=('Example:\n\n\n\n$ poetry run safecrypto random prime 32\n\n2365910551'),
)
@clibase.CLIErrorGuard
def RandomPrime(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  bits: int = typer.Argument(..., min=11, help='Bit length, ≥ 11'),
) -> None:
  config: safecrypto.TransConfig = ctx.obj
  config.console.print(modmath.NBitRandomPrimes(bits).pop())
