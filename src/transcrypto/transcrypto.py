# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto command line interface.

See <transcrypto.md> for documentation on how to use. Quick examples:

 --- Randomness ---
poetry run transcrypto random bits 16
poetry run transcrypto random int 1000 2000
poetry run transcrypto random bytes 32
poetry run transcrypto random prime 64

 --- Primes ---
poetry run transcrypto isprime 428568761
poetry run transcrypto primegen 100 -c 3
poetry run transcrypto mersenne -k 2 -C 17

 --- Integer / Modular Math ---
poetry run transcrypto gcd 462 1071
poetry run transcrypto xgcd 127 13
poetry run transcrypto mod inv 17 97
poetry run transcrypto mod div 6 127 13
poetry run transcrypto mod exp 438 234 127
poetry run transcrypto mod poly 12 17 10 20 30
poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1
poetry run transcrypto mod crt 6 7 127 13

 --- Hashing ---
poetry run transcrypto hash sha256 xyz
poetry run transcrypto --input-format b64 hash sha512 -- eHl6
poetry run transcrypto hash file /etc/passwd --digest sha512

 --- AES ---
poetry run transcrypto --output-format b64 aes key "correct horse battery staple"
poetry run transcrypto -i b64 -o b64 aes encrypt -k "<b64key>" -- "secret"
poetry run transcrypto -i b64 -o b64 aes decrypt -k "<b64key>" -- "<ciphertext>"
poetry run transcrypto aes ecb -k "<b64key>" encrypt "<128bithexblock>"  # cspell:disable-line
poetry run transcrypto aes ecb -k "<b64key>" decrypt "<128bithexblock>"  # cspell:disable-line

 --- RSA ---
poetry run transcrypto -p rsa-key rsa new --bits 2048
poetry run transcrypto -p rsa-key.pub rsa rawencrypt <plaintext>
poetry run transcrypto -p rsa-key.priv rsa rawdecrypt <ciphertext>
poetry run transcrypto -p rsa-key.priv rsa rawsign <message>
poetry run transcrypto -p rsa-key.pub rsa rawverify <message> <signature>
poetry run transcrypto -i bin -o b64 -p rsa-key.pub rsa encrypt -a <aad> <plaintext>
poetry run transcrypto -i b64 -o bin -p rsa-key.priv rsa decrypt -a <aad> -- <ciphertext>
poetry run transcrypto -i bin -o b64 -p rsa-key.priv rsa sign <message>
poetry run transcrypto -i b64 -p rsa-key.pub rsa verify -- <message> <signature>

 --- ElGamal ---
poetry run transcrypto -p eg-key elgamal shared --bits 2048
poetry run transcrypto -p eg-key elgamal new
poetry run transcrypto -p eg-key.pub elgamal rawencrypt <plaintext>
poetry run transcrypto -p eg-key.priv elgamal rawdecrypt <c1:c2>
poetry run transcrypto -p eg-key.priv elgamal rawsign <message>
poetry run transcrypto -p eg-key.pub elgamal rawverify <message> <s1:s2>
poetry run transcrypto -i bin -o b64 -p eg-key.pub elgamal encrypt <plaintext>
poetry run transcrypto -i b64 -o bin -p eg-key.priv elgamal decrypt -- <ciphertext>
poetry run transcrypto -i bin -o b64 -p eg-key.priv elgamal sign <message>
poetry run transcrypto -i b64 -p eg-key.pub elgamal verify -- <message> <signature>

 --- DSA ---
poetry run transcrypto -p dsa-key dsa shared --p-bits 2048 --q-bits 256
poetry run transcrypto -p dsa-key dsa new
poetry run transcrypto -p dsa-key.priv dsa rawsign <message>
poetry run transcrypto -p dsa-key.pub dsa rawverify <message> <s1:s2>
poetry run transcrypto -i bin -o b64 -p dsa-key.priv dsa sign <message>
poetry run transcrypto -i b64 -p dsa-key.pub dsa verify -- <message> <signature>

 --- Public Bid ---
poetry run transcrypto -i bin bid new "tomorrow it will rain"
poetry run transcrypto -o bin bid verify

 --- Shamir Secret Sharing (SSS) ---
poetry run transcrypto -p sss-key sss new 3 --bits 1024
poetry run transcrypto -p sss-key sss rawshares <secret> <n>
poetry run transcrypto -p sss-key sss rawrecover
poetry run transcrypto -p sss-key sss rawverify <secret>'
poetry run transcrypto -i bin -p sss-key sss shares <secret> <n>
poetry run transcrypto -o bin -p sss-key sss recover

 --- Markdown ---
poetry run transcrypto markdown > transcrypto.md

Test this CLI with:

poetry run pytest -vvv tests/transcrypto_test.py
"""

from __future__ import annotations

import dataclasses
import enum
import glob
import logging
import pathlib
import re
from collections import abc
from typing import Any

import click
import typer
from rich import console as rich_console

from . import (
  __version__,
  aes,
  base,
  dsa,
  elgamal,
  modmath,
  rsa,
  sss,
)

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')


def _ParseIntCLI(s: str, /, *, what: str = 'integer') -> int:
  """Parse integer literals accepted by `_ParseInt`.

  Returns:
      int: Parsed integer.

  Raises:
      base.InputError: If the value is empty or not a valid integer literal.

  """
  raw = s.strip()
  if not raw:
    raise base.InputError(f'invalid {what}: {s!r}')
  try:
    return _ParseInt(raw)
  except ValueError as exc:
    raise base.InputError(f'invalid {what}: {s!r}') from exc


def _RequireIntRange(
  value: int,
  /,
  *,
  what: str = 'value',
  min_value: int | None = None,
  max_value: int | None = None,
) -> int:
  if min_value is not None and value < min_value:
    raise base.InputError(f'{what} must be ≥ {min_value}')
  if max_value is not None and value > max_value:
    raise base.InputError(f'{what} must be ≤ {max_value}')
  return value


def _ParseIntCLIInRange(
  s: str,
  /,
  *,
  what: str = 'integer',
  min_value: int | None = None,
  max_value: int | None = None,
) -> int:
  return _RequireIntRange(
    _ParseIntCLI(s, what=what),
    what=what,
    min_value=min_value,
    max_value=max_value,
  )


def _ParseIntPairCLI(s: str, /, *, what: str = 'pair') -> tuple[int, int]:
  raw = s.strip()
  parts = raw.split(':')
  if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():  # noqa: PLR2004
    raise base.InputError(f'invalid {what}: {s!r} (expected a:b)')
  a_s, b_s = parts[0].strip(), parts[1].strip()
  return (_ParseIntCLI(a_s, what=f'{what} left'), _ParseIntCLI(b_s, what=f'{what} right'))


def _RequireHexExactLen(value: str, /, *, length: int, what: str) -> str:
  v = value.strip()
  if len(v) != length:
    raise base.InputError(f'{what} must be exactly {length} hex chars')
  if _HEX_RE.match(v) is None:
    raise base.InputError(f'{what} must be hexadecimal')
  return v


_NULL_AES_KEY = aes.AESKey(key256=b'\x00' * 32)


class IOFormat(enum.Enum):
  """Input/output data format for CLI commands."""

  hex = 'hex'
  b64 = 'b64'
  bin = 'bin'


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class TransConfig(base.CLIConfig):
  """CLI global context, storing the configuration."""

  input_format: IOFormat
  output_format: IOFormat
  key_path: pathlib.Path | None
  protect: str


# CLI app setup, this is an important object and can be imported elsewhere and called
app = typer.Typer(
  add_completion=True,
  no_args_is_help=True,
  help=(
    'transcrypto: CLI for number theory, hash, AES, RSA, El-Gamal, DSA, bidding, SSS, and more.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '# --- Randomness ---\n\n'
    'poetry run transcrypto random bits 16\n\n'
    'poetry run transcrypto random int 1000 2000\n\n'
    'poetry run transcrypto random bytes 32\n\n'
    'poetry run transcrypto random prime 64\n\n\n\n'
    '# --- Primes ---\n\n'
    'poetry run transcrypto isprime 428568761\n\n'
    'poetry run transcrypto primegen 100 -c 3\n\n'
    'poetry run transcrypto mersenne -k 2 -C 17\n\n\n\n'
    '# --- Integer / Modular Math ---\n\n'
    'poetry run transcrypto gcd 462 1071\n\n'
    'poetry run transcrypto xgcd 127 13\n\n'
    'poetry run transcrypto mod inv 17 97\n\n'
    'poetry run transcrypto mod div 6 127 13\n\n'
    'poetry run transcrypto mod exp 438 234 127\n\n'
    'poetry run transcrypto mod poly 12 17 10 20 30\n\n'
    'poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1\n\n'
    'poetry run transcrypto mod crt 6 7 127 13\n\n\n\n'
    '# --- Hashing ---\n\n'
    'poetry run transcrypto hash sha256 xyz\n\n'
    'poetry run transcrypto --input-format b64 hash sha512 -- eHl6\n\n'
    'poetry run transcrypto hash file /etc/passwd --digest sha512\n\n\n\n'
    '# --- AES ---\n\n'
    'poetry run transcrypto --output-format b64 aes key "correct horse battery staple"\n\n'
    'poetry run transcrypto -i b64 -o b64 aes encrypt -k "<b64key>" -- "secret"\n\n'
    'poetry run transcrypto -i b64 -o b64 aes decrypt -k "<b64key>" -- "<ciphertext>"\n\n'
    'poetry run transcrypto aes ecb -k "<b64key>" encrypt "<128bithexblock>"\n\n'
    'poetry run transcrypto aes ecb -k "<b64key>" decrypt "<128bithexblock>"\n\n\n\n'
    '# --- RSA ---\n\n'
    'poetry run transcrypto -p rsa-key rsa new --bits 2048\n\n'
    'poetry run transcrypto -p rsa-key.pub rsa rawencrypt <plaintext>\n\n'
    'poetry run transcrypto -p rsa-key.priv rsa rawdecrypt <ciphertext>\n\n'
    'poetry run transcrypto -p rsa-key.priv rsa rawsign <message>\n\n'
    'poetry run transcrypto -p rsa-key.pub rsa rawverify <message> <signature>\n\n'
    'poetry run transcrypto -i bin -o b64 -p rsa-key.pub rsa encrypt -a <aad> <plaintext>\n\n'
    'poetry run transcrypto -i b64 -o bin -p rsa-key.priv rsa decrypt -a <aad> -- <ciphertext>\n\n'
    'poetry run transcrypto -i bin -o b64 -p rsa-key.priv rsa sign <message>\n\n'
    'poetry run transcrypto -i b64 -p rsa-key.pub rsa verify -- <message> <signature>\n\n\n\n'
    '# --- ElGamal ---\n\n'
    'poetry run transcrypto -p eg-key elgamal shared --bits 2048\n\n'
    'poetry run transcrypto -p eg-key elgamal new\n\n'
    'poetry run transcrypto -p eg-key.pub elgamal rawencrypt <plaintext>\n\n'
    'poetry run transcrypto -p eg-key.priv elgamal rawdecrypt <c1:c2>\n\n'
    'poetry run transcrypto -p eg-key.priv elgamal rawsign <message>\n\n'
    'poetry run transcrypto -p eg-key.pub elgamal rawverify <message> <s1:s2>\n\n'
    'poetry run transcrypto -i bin -o b64 -p eg-key.pub elgamal encrypt <plaintext>\n\n'
    'poetry run transcrypto -i b64 -o bin -p eg-key.priv elgamal decrypt -- <ciphertext>\n\n'
    'poetry run transcrypto -i bin -o b64 -p eg-key.priv elgamal sign <message>\n\n'
    'poetry run transcrypto -i b64 -p eg-key.pub elgamal verify -- <message> <signature>\n\n\n\n'
    '# --- DSA ---\n\n'
    'poetry run transcrypto -p dsa-key dsa shared --p-bits 2048 --q-bits 256\n\n'
    'poetry run transcrypto -p dsa-key dsa new\n\n'
    'poetry run transcrypto -p dsa-key.priv dsa rawsign <message>\n\n'
    'poetry run transcrypto -p dsa-key.pub dsa rawverify <message> <s1:s2>\n\n'
    'poetry run transcrypto -i bin -o b64 -p dsa-key.priv dsa sign <message>\n\n'
    'poetry run transcrypto -i b64 -p dsa-key.pub dsa verify -- <message> <signature>\n\n\n\n'
    '# --- Public Bid ---\n\n'
    'poetry run transcrypto -i bin bid new "tomorrow it will rain"\n\n'
    'poetry run transcrypto -o bin bid verify\n\n\n\n'
    '# --- Shamir Secret Sharing (SSS) ---\n\n'
    'poetry run transcrypto -p sss-key sss new 3 --bits 1024\n\n'
    'poetry run transcrypto -p sss-key sss rawshares <secret> <n>\n\n'
    'poetry run transcrypto -p sss-key sss rawrecover\n\n'
    'poetry run transcrypto -p sss-key sss rawverify <secret>\n\n'
    'poetry run transcrypto -i bin -p sss-key sss shares <secret> <n>\n\n'
    'poetry run transcrypto -o bin -p sss-key sss recover\n\n\n\n'
    '# --- Markdown ---\n\n'
    'poetry run transcrypto markdown > transcrypto.md\n\n'
  ),
)


def Run() -> None:
  """Run the CLI."""
  app()


@app.callback(
  invoke_without_command=True,  # have only one; this is the "constructor"
  help='TransCrypto CLI: cryptographic operations and key management.',
)
def Main(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,  # global context
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
  input_format: IOFormat = typer.Option(  # noqa: B008
    IOFormat.hex,
    '-i',
    '--input-format',
    help='How to parse inputs: hex (default), b64, or bin.',
  ),
  output_format: IOFormat = typer.Option(  # noqa: B008
    IOFormat.hex,
    '-o',
    '--output-format',
    help='How to format outputs: hex (default), b64, or bin.',
  ),
  # key loading/saving from/to file, with optional password; will only work with some commands
  key_path: pathlib.Path | None = typer.Option(  # noqa: B008
    None,
    '-p',
    '--key-path',
    resolve_path=True,
    help='File path to serialized key object, if key is needed for operation',
  ),
  protect: str = typer.Option(
    '',
    # '-p',
    '--protect',
    help='Password to encrypt/decrypt key file if using the `-p`/`--key-path` option',
  ),
) -> None:
  if version:
    typer.echo(__version__)
    raise typer.Exit(0)
  console, verbose, color = base.InitLogging(
    verbose,
    color=color,
    include_process=False,  # decide if you want process names in logs
  )
  # create context with the arguments we received.
  ctx.obj = TransConfig(
    console=console,
    verbose=verbose,
    color=color,
    input_format=input_format,
    output_format=output_format,
    key_path=key_path,
    protect=protect,
  )


@app.command(
  'isprime',
  help='Primality test with safe defaults, useful for any integer size.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto isprime 2305843009213693951\n\n'
    'True\n\n'
    '$ poetry run transcrypto isprime 2305843009213693953\n\n'
    'False'
  ),
)
@base.CLIErrorGuard
def IsPrimeCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  n: str = typer.Argument(..., help='Integer to test, ≥ 1'),
) -> None:
  config: TransConfig = ctx.obj
  n_i = _ParseIntCLIInRange(n, what='n', min_value=1)
  config.console.print(str(modmath.IsPrime(n_i)))


@app.command(
  'primegen',
  help='Generate (stream) primes ≥ `start` (prints a limited `count` by default).',
  epilog=('Example:\n\n\n\n$ poetry run transcrypto primegen 100 -c 3\n\n101\n\n103\n\n107'),
)
@base.CLIErrorGuard
def PrimeGenCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  start: str = typer.Argument(..., help='Starting integer (inclusive), ≥ 0'),
  count: int = typer.Option(
    1,
    '-c',
    '--count',
    min=1,
    help='How many to print',
  ),
) -> None:
  config: TransConfig = ctx.obj
  start_i = _ParseIntCLIInRange(start, what='start', min_value=0)
  for i, pr in enumerate(modmath.PrimeGenerator(start_i)):
    if i >= count:
      return
    config.console.print(pr)


@app.command(
  'mersenne',
  help=(
    'Generate (stream) Mersenne prime exponents `k`, also outputting `2^k-1` '
    '(the Mersenne prime, `M`) and `M×2^(k-1)` (the associated perfect number), '  # noqa: RUF001
    'starting at `min-k` and stopping once `k` > `cutoff-k`.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mersenne -k 0 -C 15\n\n'
    'k=2  M=3  perfect=6\n\n'
    'k=3  M=7  perfect=28\n\n'
    'k=5  M=31  perfect=496\n\n'
    'k=7  M=127  perfect=8128\n\n'
    'k=13  M=8191  perfect=33550336\n\n'
    'k=17  M=131071  perfect=8589869056'
  ),
)
@base.CLIErrorGuard
def MersenneCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  min_k: int = typer.Option(1, '-k', '--min-k', min=1, help='Starting exponent `k`, ≥ 1'),
  cutoff_k: int = typer.Option(
    10000,
    '-C',
    '--cutoff-k',
    min=1,
    help='Stop once `k` > `cutoff-k`',
  ),
) -> None:
  config: TransConfig = ctx.obj
  for k, m, perfect in modmath.MersennePrimesGenerator(min_k):
    if k > cutoff_k:
      return
    config.console.print(f'k={k}  M={m}  perfect={perfect}')


@app.command(
  'gcd',
  help='Greatest Common Divisor (GCD) of integers `a` and `b`.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto gcd 462 1071\n\n'
    '21\n\n'
    '$ poetry run transcrypto gcd 0 5\n\n'
    '5\n\n'
    '$ poetry run transcrypto gcd 127 13\n\n'
    '1'
  ),
)
@base.CLIErrorGuard
def GcdCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer, ≥ 0'),
  b: str = typer.Argument(..., help="Integer, ≥ 0 (can't be both zero)"),
) -> None:
  config: TransConfig = ctx.obj
  a_i = _ParseIntCLIInRange(a, what='a', min_value=0)
  b_i = _ParseIntCLIInRange(b, what='b', min_value=0)
  if a_i == 0 and b_i == 0:
    raise base.InputError("a and b can't both be zero")
  config.console.print(base.GCD(a_i, b_i))


@app.command(
  'xgcd',
  help=(
    'Extended Greatest Common Divisor (x-GCD) of integers `a` and `b`, '
    'will return `(g, x, y)` where `a×x+b×y==g`.'  # noqa: RUF001
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto xgcd 462 1071\n\n'
    '(21, 7, -3)\n\n'
    '$ poetry run transcrypto xgcd 0 5\n\n'
    '(5, 0, 1)\n\n'
    '$ poetry run transcrypto xgcd 127 13\n\n'
    '(1, 4, -39)'
  ),
)
@base.CLIErrorGuard
def XgcdCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer, ≥ 0'),
  b: str = typer.Argument(..., help="Integer, ≥ 0 (can't be both zero)"),
) -> None:
  config: TransConfig = ctx.obj
  a_i = _ParseIntCLIInRange(a, what='a', min_value=0)
  b_i = _ParseIntCLIInRange(b, what='b', min_value=0)
  if a_i == 0 and b_i == 0:
    raise base.InputError("a and b can't both be zero")
  config.console.print(str(base.ExtendedGCD(a_i, b_i)))


# ========================= Typer command groups ==================================================

random_app = typer.Typer(
  no_args_is_help=True,
  help='Cryptographically secure randomness, from the OS CSPRNG.',
)
app.add_typer(random_app, name='random')


@random_app.command(
  'bits',
  help='Random integer with exact bit length = `bits` (MSB will be 1).',
  epilog=('Example:\n\n\n\n$ poetry run transcrypto random bits 16\n\n36650'),
)
@base.CLIErrorGuard
def RandomBits(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  bits: int = typer.Argument(..., min=8, help='Number of bits, ≥ 8'),
) -> None:
  config: TransConfig = ctx.obj
  config.console.print(base.RandBits(bits))


@random_app.command(
  'int',
  help='Uniform random integer in `[min, max]` range, inclusive.',
  epilog=('Example:\n\n\n\n$ poetry run transcrypto random int 1000 2000\n\n1628'),
)
@base.CLIErrorGuard
def RandomInt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  min_: str = typer.Argument(..., help='Minimum, ≥ 0'),
  max_: str = typer.Argument(..., help='Maximum, > `min`'),
) -> None:
  config: TransConfig = ctx.obj
  min_i = _ParseIntCLIInRange(min_, what='min', min_value=0)
  max_i = _ParseIntCLIInRange(max_, what='max', min_value=0)
  if max_i <= min_i:
    raise base.InputError('max must be > min')
  config.console.print(base.RandInt(min_i, max_i))


@random_app.command(
  'bytes',
  help='Generates `n` cryptographically secure random bytes.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto random bytes 32\n\n'
    '6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f'
  ),
)
@base.CLIErrorGuard
def RandomBytes(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  n: int = typer.Argument(..., min=1, help='Number of bytes, ≥ 1'),
) -> None:
  config: TransConfig = ctx.obj
  out_format = config.output_format
  config.console.print(_BytesToText(base.RandBytes(n), out_format))


@random_app.command(
  'prime',
  help='Generate a random prime with exact bit length = `bits` (MSB will be 1).',
  epilog=('Example:\n\n\n\n$ poetry run transcrypto random prime 32\n\n2365910551'),
)
@base.CLIErrorGuard
def RandomPrime(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  bits: int = typer.Argument(..., min=11, help='Bit length, ≥ 11'),
) -> None:
  config: TransConfig = ctx.obj
  config.console.print(modmath.NBitRandomPrimes(bits).pop())


mod_app = typer.Typer(
  no_args_is_help=True,
  help='Modular arithmetic helpers.',
)
app.add_typer(mod_app, name='mod')


@mod_app.command(
  'inv',
  help=(
    'Modular inverse: find integer 0≤`i`<`m` such that `a×i ≡ 1 (mod m)`. '  # noqa: RUF001
    'Will only work if `gcd(a,m)==1`, else will fail with a message.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mod inv 127 13\n\n'
    '4\n\n'
    '$ poetry run transcrypto mod inv 17 3120\n\n'
    '2753\n\n'
    '$ poetry run transcrypto mod inv 462 1071\n\n'
    '<<INVALID>> no modular inverse exists (ModularDivideError)'
  ),
)
@base.CLIErrorGuard
def ModInv(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer to invert'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
) -> None:
  config: TransConfig = ctx.obj
  a_i = _ParseIntCLI(a, what='a')
  m_i = _ParseIntCLIInRange(m, what='m', min_value=2)
  try:
    config.console.print(modmath.ModInv(a_i, m_i))
  except modmath.ModularDivideError:
    config.console.print('<<INVALID>> no modular inverse exists (ModularDivideError)')


@mod_app.command(
  'div',
  help=(
    'Modular division: find integer 0≤`z`<`m` such that `z×y ≡ x (mod m)`. '  # noqa: RUF001
    'Will only work if `gcd(y,m)==1` and `y!=0`, else will fail with a message.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mod div 6 127 13\n\n'
    '11\n\n'
    '$ poetry run transcrypto mod div 6 0 13\n\n'
    '<<INVALID>> no modular inverse exists (ModularDivideError)'
  ),
)
@base.CLIErrorGuard
def ModDiv(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  x: str = typer.Argument(..., help='Integer'),
  y: str = typer.Argument(..., help='Integer, cannot be zero'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
) -> None:
  config: TransConfig = ctx.obj
  x_i = _ParseIntCLI(x, what='x')
  y_i = _ParseIntCLI(y, what='y')
  m_i = _ParseIntCLIInRange(m, what='m', min_value=2)
  try:
    config.console.print(modmath.ModDiv(x_i, y_i, m_i))
  except modmath.ModularDivideError:
    config.console.print('<<INVALID>> no modular inverse exists (ModularDivideError)')


@mod_app.command(
  'exp',
  help='Modular exponentiation: `a^e mod m`. Efficient, can handle huge values.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mod exp 438 234 127\n\n'
    '32\n\n'
    '$ poetry run transcrypto mod exp 438 234 89854\n\n'
    '60622'
  ),
)
@base.CLIErrorGuard
def ModExp(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer'),
  e: str = typer.Argument(..., help='Integer, ≥ 0'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
) -> None:
  config: TransConfig = ctx.obj
  a_i = _ParseIntCLI(a, what='a')
  e_i = _ParseIntCLIInRange(e, what='e', min_value=0)
  m_i = _ParseIntCLIInRange(m, what='m', min_value=2)
  config.console.print(modmath.ModExp(a_i, e_i, m_i))


@mod_app.command(
  'poly',
  help=(
    'Efficiently evaluate polynomial with `coeff` coefficients at point `x` modulo `m` '
    '(`c₀+c₁×x+c₂×x²+…+cₙ×xⁿ mod m`).'  # noqa: RUF001
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mod poly 12 17 10 20 30\n\n'
    '14  # (10+20×12+30×12² ≡ 14 (mod 17))\n\n'  # noqa: RUF001
    '$ poetry run transcrypto mod poly 10 97 3 0 0 1 1\n\n'
    '42  # (3+1×10³+1×10⁴ ≡ 42 (mod 97))'  # noqa: RUF001
  ),
)
@base.CLIErrorGuard
def ModPoly(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  x: str = typer.Argument(..., help='Evaluation point `x`'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
  coeff: list[str] = typer.Argument(  # noqa: B008
    ...,
    help='Coefficients (constant-term first: `c₀+c₁×x+c₂×x²+…+cₙ×xⁿ`)',  # noqa: RUF001
  ),
) -> None:
  config: TransConfig = ctx.obj
  x_i = _ParseIntCLI(x, what='x')
  m_i = _ParseIntCLIInRange(m, what='m', min_value=2)
  config.console.print(modmath.ModPolynomial(x_i, _ParseIntList(coeff), m_i))


@mod_app.command(
  'lagrange',
  help=(
    'Lagrange interpolation over modulus `m`: find the `f(x)` solution for the '
    'given `x` and `zₙ:f(zₙ)` points `pt`. The modulus `m` must be a prime.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1\n\n'
    '3  # passes through (2,4), (6,3), (7,1)\n\n'
    '$ poetry run transcrypto mod lagrange 11 97 1:1 2:4 3:9 4:16 5:25\n\n'
    '24  # passes through (1,1), (2,4), (3,9), (4,16), (5,25)'
  ),
)
@base.CLIErrorGuard
def ModLagrange(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  x: str = typer.Argument(..., help='Evaluation point `x`'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
  pt: list[str] = typer.Argument(  # noqa: B008
    ...,
    help='Points `zₙ:f(zₙ)` as `key:value` pairs (e.g., `2:4 5:3 7:1`)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  x_i = _ParseIntCLI(x, what='x')
  m_i = _ParseIntCLIInRange(m, what='m', min_value=2)
  pts: dict[int, int] = {}
  for kv in pt:
    k_s, v_s = kv.split(':', 1)
    pts[_ParseIntCLI(k_s, what='point key')] = _ParseIntCLI(v_s, what='point value')
  config.console.print(modmath.ModLagrangeInterpolate(x_i, pts, m_i))


@mod_app.command(
  'crt',
  help=(
    'Solves Chinese Remainder Theorem (CRT) Pair: finds the unique integer 0≤`x`<`(m1×m2)` '  # noqa: RUF001
    'satisfying both `x ≡ a1 (mod m1)` and `x ≡ a2 (mod m2)`, if `gcd(m1,m2)==1`.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mod crt 6 7 127 13\n\n'
    '62\n\n'
    '$ poetry run transcrypto mod crt 12 56 17 19\n\n'
    '796\n\n'
    '$ poetry run transcrypto mod crt 6 7 462 1071\n\n'
    '<<INVALID>> moduli m1/m2 not co-prime (ModularDivideError)'
  ),
)
@base.CLIErrorGuard
def ModCRT(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a1: str = typer.Argument(..., help='Integer residue for first congruence'),
  m1: str = typer.Argument(..., help='Modulus `m1`, ≥ 2 and `gcd(m1,m2)==1`'),
  a2: str = typer.Argument(..., help='Integer residue for second congruence'),
  m2: str = typer.Argument(..., help='Modulus `m2`, ≥ 2 and `gcd(m1,m2)==1`'),
) -> None:
  config: TransConfig = ctx.obj
  a1_i = _ParseIntCLI(a1, what='a1')
  m1_i = _ParseIntCLIInRange(m1, what='m1', min_value=2)
  a2_i = _ParseIntCLI(a2, what='a2')
  m2_i = _ParseIntCLIInRange(m2, what='m2', min_value=2)
  try:
    config.console.print(modmath.CRTPair(a1_i, m1_i, a2_i, m2_i))
  except modmath.ModularDivideError:
    config.console.print('<<INVALID>> moduli m1/m2 not co-prime (ModularDivideError)')


hash_app = typer.Typer(
  no_args_is_help=True,
  help='Cryptographic Hashing (SHA-256 / SHA-512 / file).',
)
app.add_typer(hash_app, name='hash')


@hash_app.command(
  'sha256',
  help='SHA-256 of input `data`.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --bin hash sha256 xyz\n\n'
    '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282\n\n'
    '$ poetry run transcrypto --b64 hash sha256 -- eHl6  # "xyz" in base-64\n\n'
    '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282'
  ),
)
@base.CLIErrorGuard
def Hash256(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  data: str = typer.Argument(..., help='Input data (raw text; or use --hex/--b64/--bin)'),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  bt = _BytesFromText(data, in_format)
  config.console.print(_BytesToText(base.Hash256(bt), out_format))


@hash_app.command(
  'sha512',
  help='SHA-512 of input `data`.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --bin hash sha512 xyz\n\n'
    '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
    '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728\n\n'
    '$ poetry run transcrypto --b64 hash sha512 -- eHl6  # "xyz" in base-64\n\n'
    '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
    '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728'
  ),
)
@base.CLIErrorGuard
def Hash512(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  data: str = typer.Argument(..., help='Input data (raw text; or use --hex/--b64/--bin)'),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  bt = _BytesFromText(data, in_format)
  config.console.print(_BytesToText(base.Hash512(bt), out_format))


@hash_app.command(
  'file',
  help='SHA-256/512 hash of file contents, defaulting to SHA-256.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto hash file /etc/passwd --digest sha512\n\n'
    '8966f5953e79f55dfe34d3dc5b160ac4a4a3f9cbd1c36695a54e28d77c7874df'
    'f8595502f8a420608911b87d336d9e83c890f0e7ec11a76cb10b03e757f78aea'
  ),
)
@base.CLIErrorGuard
def HashFile(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  path: pathlib.Path = typer.Argument(  # noqa: B008
    ...,
    exists=True,
    file_okay=True,
    dir_okay=False,
    readable=True,
    resolve_path=True,
    help='Path to existing file',
  ),
  digest: str = typer.Option(
    'sha256',
    '--digest',
    click_type=click.Choice(['sha256', 'sha512'], case_sensitive=False),
    help='Digest type, SHA-256 ("sha256") or SHA-512 ("sha512")',
  ),
) -> None:
  config: TransConfig = ctx.obj
  out_format = config.output_format
  config.console.print(_BytesToText(base.FileHash(str(path), digest=digest), out_format))


aes_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'AES-256 operations (GCM/ECB) and key derivation. '
    'No measures are taken here to prevent timing attacks.'
  ),
)
app.add_typer(aes_app, name='aes')


@aes_app.command(
  'key',
  help=(
    'Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive '
    'salt and iterations. Very good/safe for simple password-to-key but not for '
    'passwords databases (because of constant salt).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --out-b64 aes key "correct horse battery staple"\n\n'
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es=\n\n'  # cspell:disable-line
    '$ poetry run transcrypto -p keyfile.out --protect hunter aes key '
    '"correct horse battery staple"\n\n'
    "AES key saved to 'keyfile.out'"
  ),
)
@base.CLIErrorGuard
def AESKeyFromPass(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  password: str = typer.Argument(..., help='Password (leading/trailing spaces ignored)'),
) -> None:
  config: TransConfig = ctx.obj
  out_format = config.output_format
  aes_key = aes.AESKey.FromStaticPassword(password)
  if config.key_path is not None:
    _SaveObj(aes_key, str(config.key_path), config.protect or None)
    config.console.print(f'AES key saved to {str(config.key_path)!r}')
  else:
    config.console.print(_BytesToText(aes_key.key256, out_format))


@aes_app.command(
  'encrypt',
  help=(
    'AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with '
    '`-p`/`--key-path` keyfile. All inputs are raw, or you '
    'can use `--bin`/`--hex`/`--b64` flags. Attention: if you provide `-a`/`--aad` '
    '(associated data, AAD), you will need to provide the same AAD when decrypting '
    'and it is NOT included in the `ciphertext`/CT returned by this method!'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --b64 --out-b64 aes encrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- AAAAAAB4eXo=\n\n'  # cspell:disable-line
    'F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==\n\n'  # cspell:disable-line
    '$ poetry run transcrypto --b64 --out-b64 aes encrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 -- AAAAAAB4eXo=\n\n'  # cspell:disable-line
    'xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA=='  # cspell:disable-line
  ),
)
@base.CLIErrorGuard
def AESEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='Input data to encrypt (PT)'),
  key: str | None = typer.Option(
    None, '-k', '--key', help="Key if `-p`/`--key-path` wasn't used (32 bytes)"
  ),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  aes_key: aes.AESKey
  if key:
    key_bytes = _BytesFromText(key, in_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = _LoadObj(str(config.key_path), config.protect or None, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')

  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(plaintext, in_format)
  ct: bytes = aes_key.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(_BytesToText(ct, out_format))


@aes_app.command(
  'decrypt',
  help=(
    'AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with '
    '`-p`/`--key-path` keyfile. All inputs are raw, or you '
    'can use `--bin`/`--hex`/`--b64` flags. Attention: if you provided `-a`/`--aad` '
    '(associated data, AAD) during encryption, you will need to provide the same AAD now!'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --b64 --out-b64 aes decrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- '  # cspell:disable-line
    'F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==\n\n'  # cspell:disable-line
    'AAAAAAB4eXo=\n\n'  # cspell:disable-line
    '$ poetry run transcrypto --b64 --out-b64 aes decrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 -- '  # cspell:disable-line
    'xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==\n\n'  # cspell:disable-line
    'AAAAAAB4eXo='  # cspell:disable-line
  ),
)
@base.CLIErrorGuard
def AESDecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='Input data to decrypt (CT)'),
  key: str | None = typer.Option(
    None, '-k', '--key', help="Key if `-p`/`--key-path` wasn't used (32 bytes)"
  ),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during encryption)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  aes_key: aes.AESKey
  if key:
    key_bytes = _BytesFromText(key, in_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = _LoadObj(str(config.key_path), config.protect or None, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')
  # associated data, if any
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  ct: bytes = _BytesFromText(ciphertext, in_format)
  pt: bytes = aes_key.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(_BytesToText(pt, out_format))


aes_ecb_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'AES-256-ECB: encrypt/decrypt 128 bit (16 bytes) hexadecimal blocks. UNSAFE, except '
    'for specifically encrypting hash blocks which are very much expected to look random. '
    'ECB mode will have the same output for the same input (no IV/nonce is used).'
  ),
)
aes_app.add_typer(aes_ecb_app, name='ecb')


@aes_ecb_app.callback(invoke_without_command=True, help='AES ECB mode subcommands.')
def AESECBMain(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  key: str | None = typer.Option(
    None,
    '-k',
    '--key',
    help=(
      "Key if `-p`/`--key-path` wasn't used (32 bytes; raw, or you "
      'can use `--bin`/`--hex`/`--b64` flags)'
    ),
  ),
) -> None:
  ctx.meta['aes_ecb_key'] = key


@aes_ecb_app.command(
  'encrypt',
  help=(
    'AES-256-ECB: encrypt 16-bytes hex `plaintext` with `-k`/`--key` or with '
    '`-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash blocks.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --b64 aes ecb -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= encrypt '  # cspell:disable-line
    '00112233445566778899aabbccddeeff\n\n'  # cspell:disable-line
    '54ec742ca3da7b752e527b74e3a798d7'
  ),
)
@base.CLIErrorGuard
def AESEcbEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='Plaintext block as 32 hex chars (16-bytes)'),
) -> None:
  config: TransConfig = ctx.obj
  plaintext = _RequireHexExactLen(plaintext, length=32, what='plaintext')
  in_format = config.input_format
  key_s: str | None = ctx.meta.get('aes_ecb_key')
  aes_key: aes.AESKey
  if key_s:
    key_bytes = _BytesFromText(key_s, in_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = _LoadObj(str(config.key_path), config.protect or None, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')

  ecb: aes.AESKey.ECBEncoderClass = aes_key.ECBEncoder()
  config.console.print(ecb.EncryptHex(plaintext))


@aes_ecb_app.command(
  'decrypt',
  help=(
    'AES-256-ECB: decrypt 16-bytes hex `ciphertext` with `-k`/`--key` or with '
    '`-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash blocks.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --b64 aes ecb -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= decrypt '  # cspell:disable-line
    '54ec742ca3da7b752e527b74e3a798d7\n\n'  # cspell:disable-line
    '00112233445566778899aabbccddeeff'  # cspell:disable-line
  ),
)
@base.CLIErrorGuard
def AESEcbDecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='Ciphertext block as 32 hex chars (16-bytes)'),
) -> None:
  config: TransConfig = ctx.obj
  ciphertext = _RequireHexExactLen(ciphertext, length=32, what='ciphertext')
  in_format = config.input_format
  key_s: str | None = ctx.meta.get('aes_ecb_key')
  aes_key: aes.AESKey
  if key_s:
    key_bytes = _BytesFromText(key_s, in_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = _LoadObj(str(config.key_path), config.protect or None, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')

  ecb: aes.AESKey.ECBEncoderClass = aes_key.ECBEncoder()
  config.console.print(ecb.DecryptHex(ciphertext))


rsa_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'RSA (Rivest-Shamir-Adleman) asymmetric cryptography. '
    'No measures are taken here to prevent timing attacks. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'
  ),
)
app.add_typer(rsa_app, name='rsa')


@rsa_app.command(
  'new',
  help=(
    'Generate RSA private/public key pair with `bits` modulus size '
    '(prime sizes will be `bits`/2). '
    'Requires `-p`/`--key-path` to set the basename for output files.'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p rsa-key rsa new --bits 64  # NEVER use such a small key: example only!\n\n'
    "RSA private/public keys saved to 'rsa-key.priv/.pub'"
  ),
)
@base.CLIErrorGuard
def RSANew(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  bits: int = typer.Option(
    2048,
    '--bits',
    min=16,
    help='Modulus size in bits; the default is a safe size',
  ),
) -> None:
  config: TransConfig = ctx.obj
  base_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(bits)
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(rsa_priv)
  _SaveObj(rsa_priv, base_path + '.priv', config.protect or None)
  _SaveObj(rsa_pub, base_path + '.pub', config.protect or None)
  config.console.print(f'RSA private/public keys saved to {base_path + ".priv/.pub"!r}')


@rsa_app.command(
  'rawencrypt',
  help=(
    'Raw encrypt *integer* `message` with public key (BEWARE: no OAEP/PSS padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p rsa-key.pub rsa rawencrypt 999\n\n6354905961171348600'
  ),
)
@base.CLIErrorGuard
def RSARawEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to encrypt, 1≤`message`<*modulus*'),
) -> None:
  config: TransConfig = ctx.obj
  message_i = _ParseIntCLIInRange(message, what='message', min_value=1)
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, rsa.RSAPublicKey)
  )
  config.console.print(rsa_pub.RawEncrypt(message_i))


@rsa_app.command(
  'rawdecrypt',
  help=(
    'Raw decrypt *integer* `ciphertext` with private key '
    '(BEWARE: no OAEP/PSS padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p rsa-key.priv rsa rawdecrypt 6354905961171348600\n\n999'
  ),
)
@base.CLIErrorGuard
def RSARawDecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(
    ..., help='Integer ciphertext to decrypt, 1≤`ciphertext`<*modulus*'
  ),
) -> None:
  config: TransConfig = ctx.obj
  ciphertext_i = _ParseIntCLIInRange(ciphertext, what='ciphertext', min_value=1)
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = _LoadObj(key_path, config.protect or None, rsa.RSAPrivateKey)
  config.console.print(rsa_priv.RawDecrypt(ciphertext_i))


@rsa_app.command(
  'rawsign',
  help='Raw sign *integer* `message` with private key (BEWARE: no OAEP/PSS padding or validation).',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p rsa-key.priv rsa rawsign 999\n\n'
    '7632909108672871784'
  ),
)
@base.CLIErrorGuard
def RSARawSign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to sign, 1≤`message`<*modulus*'),
) -> None:
  config: TransConfig = ctx.obj
  message_i = _ParseIntCLIInRange(message, what='message', min_value=1)
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = _LoadObj(key_path, config.protect or None, rsa.RSAPrivateKey)
  config.console.print(rsa_priv.RawSign(message_i))


@rsa_app.command(
  'rawverify',
  help=(
    'Raw verify *integer* `signature` for *integer* `message` with public key '
    '(BEWARE: no OAEP/PSS padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p rsa-key.pub rsa rawverify 999 7632909108672871784\n\n'
    'RSA signature: OK\n\n'
    '$ poetry run transcrypto -p rsa-key.pub rsa rawverify 999 7632909108672871785\n\n'
    'RSA signature: INVALID'
  ),
)
@base.CLIErrorGuard
def RSARawVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(
    ..., help='Integer message that was signed earlier, 1≤`message`<*modulus*'
  ),
  signature: str = typer.Argument(
    ..., help='Integer putative signature for `message`, 1≤`signature`<*modulus*'
  ),
) -> None:
  config: TransConfig = ctx.obj
  message_i = _ParseIntCLIInRange(message, what='message', min_value=1)
  signature_i = _ParseIntCLIInRange(signature, what='signature', min_value=1)
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, rsa.RSAPublicKey)
  )
  config.console.print(
    'RSA signature: ' + ('OK' if rsa_pub.RawVerify(message_i, signature_i) else 'INVALID')
  )


@rsa_app.command(
  'encrypt',
  help='Encrypt `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --bin --out-b64 -p rsa-key.pub rsa encrypt "abcde" -a "xyz"\n\n'
    'AO6knI6xwq6TGR…Qy22jiFhXi1eQ=='
  ),
)
@base.CLIErrorGuard
def RSAEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='Message to encrypt'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = _LoadObj(key_path, config.protect or None, rsa.RSAPublicKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(plaintext, in_format)
  ct: bytes = rsa_pub.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(_BytesToText(ct, out_format))


@rsa_app.command(
  'decrypt',
  help='Decrypt `ciphertext` with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --b64 --out-bin -p rsa-key.priv rsa decrypt -a eHl6 -- '
    'AO6knI6xwq6TGR…Qy22jiFhXi1eQ==\n\n'
    'abcde'
  ),
)
@base.CLIErrorGuard
def RSADecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='Ciphertext to decrypt'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during encryption)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = _LoadObj(key_path, config.protect or None, rsa.RSAPrivateKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  ct: bytes = _BytesFromText(ciphertext, in_format)
  pt: bytes = rsa_priv.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(_BytesToText(pt, out_format))


@rsa_app.command(
  'sign',
  help='Sign `message` with private key.',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '--bin --out-b64 -p rsa-key.priv rsa sign "xyz"\n\n91TS7gC6LORiL…6RD23Aejsfxlw=='  # cspell:disable-line
  ),
)
@base.CLIErrorGuard
def RSASign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message to sign'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = _LoadObj(key_path, config.protect or None, rsa.RSAPrivateKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(message, in_format)
  sig: bytes = rsa_priv.Sign(pt, associated_data=aad_bytes)
  config.console.print(_BytesToText(sig, out_format))


@rsa_app.command(
  'verify',
  help='Verify `signature` for `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --b64 -p rsa-key.pub rsa verify -- eHl6 '
    '91TS7gC6LORiL…6RD23Aejsfxlw==\n\n'  # cspell:disable-line
    'RSA signature: OK\n\n'
    '$ poetry run transcrypto --b64 -p rsa-key.pub rsa verify -- eLl6 '
    '91TS7gC6LORiL…6RD23Aejsfxlw==\n\n'  # cspell:disable-line
    'RSA signature: INVALID'
  ),
)
@base.CLIErrorGuard
def RSAVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message that was signed earlier'),
  signature: str = typer.Argument(..., help='Putative signature for `message`'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during signing)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format = config.input_format
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = _LoadObj(key_path, config.protect or None, rsa.RSAPublicKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(message, in_format)
  sig: bytes = _BytesFromText(signature, in_format)
  config.console.print(
    'RSA signature: ' + ('OK' if rsa_pub.Verify(pt, sig, associated_data=aad_bytes) else 'INVALID')
  )


eg_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'El-Gamal asymmetric cryptography. '
    'No measures are taken here to prevent timing attacks. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'
  ),
)
app.add_typer(eg_app, name='elgamal')


@eg_app.command(
  'shared',
  help=(
    'Generate a shared El-Gamal key with `bits` prime modulus size, which is the '
    'first step in key generation. '
    'The shared key can safely be used by any number of users to generate their '
    'private/public key pairs (with the `new` command). The shared keys are "public". '
    'Requires `-p`/`--key-path` to set the basename for output files.'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p eg-key elgamal shared --bits 64  # NEVER use such a small key: example only!\n\n'
    "El-Gamal shared key saved to 'eg-key.shared'"
  ),
)
@base.CLIErrorGuard
def ElGamalShared(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  bits: int = typer.Option(
    2048,
    '--bits',
    min=16,
    help='Prime modulus (`p`) size in bits; the default is a safe size',
  ),
) -> None:
  config: TransConfig = ctx.obj
  base_path = _RequireKeyPath(config, 'elgamal')
  shared_eg: elgamal.ElGamalSharedPublicKey = elgamal.ElGamalSharedPublicKey.NewShared(bits)
  _SaveObj(shared_eg, base_path + '.shared', config.protect or None)
  config.console.print(f'El-Gamal shared key saved to {base_path + ".shared"!r}')


@eg_app.command(
  'new',
  help='Generate an individual El-Gamal private/public key pair from a shared key.',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    "-p eg-key elgamal new\n\nEl-Gamal private/public keys saved to 'eg-key.priv/.pub'"
  ),
)
@base.CLIErrorGuard
def ElGamalNew(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: TransConfig = ctx.obj
  base_path = _RequireKeyPath(config, 'elgamal')
  shared_eg: elgamal.ElGamalSharedPublicKey = _LoadObj(
    base_path + '.shared', config.protect or None, elgamal.ElGamalSharedPublicKey
  )
  eg_priv: elgamal.ElGamalPrivateKey = elgamal.ElGamalPrivateKey.New(shared_eg)
  eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(eg_priv)
  _SaveObj(eg_priv, base_path + '.priv', config.protect or None)
  _SaveObj(eg_pub, base_path + '.pub', config.protect or None)
  config.console.print(f'El-Gamal private/public keys saved to {base_path + ".priv/.pub"!r}')


@eg_app.command(
  'rawencrypt',
  help=(
    'Raw encrypt *integer* `message` with public key '
    '(BEWARE: no ECIES-style KEM/DEM padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p eg-key.pub elgamal rawencrypt 999\n\n2948854810728206041:15945988196340032688'
  ),
)
@base.CLIErrorGuard
def ElGamalRawEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to encrypt, 1≤`message`<*modulus*'),
) -> None:
  config: TransConfig = ctx.obj
  message_i = _ParseIntCLIInRange(message, what='message', min_value=1)
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, elgamal.ElGamalPublicKey)
  )
  c1, c2 = eg_pub.RawEncrypt(message_i)
  config.console.print(f'{c1}:{c2}')


@eg_app.command(
  'rawdecrypt',
  help=(
    'Raw decrypt *integer* `ciphertext` with private key '
    '(BEWARE: no ECIES-style KEM/DEM padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p eg-key.priv elgamal rawdecrypt 2948854810728206041:15945988196340032688\n\n999'
  ),
)
@base.CLIErrorGuard
def ElGamalRawDecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(
    ...,
    help=(
      'Integer ciphertext to decrypt; expects `c1:c2` format with 2 integers, `c1`,`c2`<*modulus*'
    ),
  ),
) -> None:
  config: TransConfig = ctx.obj
  ciphertext_i = _ParseIntPairCLI(ciphertext, what='ciphertext')
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = _LoadObj(
    key_path, config.protect or None, elgamal.ElGamalPrivateKey
  )
  config.console.print(eg_priv.RawDecrypt(ciphertext_i))


@eg_app.command(
  'rawsign',
  help=(
    'Raw sign *integer* message with private key '
    '(BEWARE: no ECIES-style KEM/DEM padding or validation). '
    'Output will 2 *integers* in a `s1:s2` format.'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p eg-key.priv elgamal rawsign 999\n\n4674885853217269088:14532144906178302633'
  ),
)
@base.CLIErrorGuard
def ElGamalRawSign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to sign, 1≤`message`<*modulus*'),
) -> None:
  config: TransConfig = ctx.obj
  message_i = _ParseIntCLIInRange(message, what='message', min_value=1)
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = _LoadObj(
    key_path, config.protect or None, elgamal.ElGamalPrivateKey
  )
  s1, s2 = eg_priv.RawSign(message_i)
  config.console.print(f'{s1}:{s2}')


@eg_app.command(
  'rawverify',
  help=(
    'Raw verify *integer* `signature` for *integer* `message` with public key '
    '(BEWARE: no ECIES-style KEM/DEM padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p eg-key.pub elgamal rawverify 999 '
    '4674885853217269088:14532144906178302633\n\n'
    'El-Gamal signature: OK\n\n'
    '$ poetry run transcrypto -p eg-key.pub elgamal rawverify 999 '
    '4674885853217269088:14532144906178302632\n\n'
    'El-Gamal signature: INVALID'
  ),
)
@base.CLIErrorGuard
def ElGamalRawVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(
    ..., help='Integer message that was signed earlier, 1≤`message`<*modulus*'
  ),
  signature: str = typer.Argument(
    ...,
    help=(
      'Integer putative signature for `message`; expects `s1:s2` format with 2 integers, '
      '`s1`,`s2`<*modulus*'
    ),
  ),
) -> None:
  config: TransConfig = ctx.obj
  message_i = _ParseIntCLIInRange(message, what='message', min_value=1)
  signature_i = _ParseIntPairCLI(signature, what='signature')
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, elgamal.ElGamalPublicKey)
  )
  config.console.print(
    'El-Gamal signature: ' + ('OK' if eg_pub.RawVerify(message_i, signature_i) else 'INVALID')
  )


@eg_app.command(
  'encrypt',
  help='Encrypt `message` with public key.',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '--bin --out-b64 -p eg-key.pub elgamal encrypt "abcde" -a "xyz"\n\n'
    'CdFvoQ_IIPFPZLua…kqjhcUTspISxURg=='  # cspell:disable-line
  ),
)
@base.CLIErrorGuard
def ElGamalEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='Message to encrypt'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = _LoadObj(
    key_path, config.protect or None, elgamal.ElGamalPublicKey
  )
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(plaintext, in_format)
  ct: bytes = eg_pub.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(_BytesToText(ct, out_format))


@eg_app.command(
  'decrypt',
  help='Decrypt `ciphertext` with private key.',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '--b64 --out-bin -p eg-key.priv elgamal decrypt -a eHl6 -- '
    'CdFvoQ_IIPFPZLua…kqjhcUTspISxURg==\n\nabcde'  # cspell:disable-line
  ),
)
@base.CLIErrorGuard
def ElGamalDecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='Ciphertext to decrypt'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during encryption)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = _LoadObj(
    key_path, config.protect or None, elgamal.ElGamalPrivateKey
  )
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  ct: bytes = _BytesFromText(ciphertext, in_format)
  pt: bytes = eg_priv.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(_BytesToText(pt, out_format))


@eg_app.command(
  'sign',
  help='Sign message with private key.',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '--bin --out-b64 -p eg-key.priv elgamal sign "xyz"\n\nXl4hlYK8SHVGw…0fCKJE1XVzA=='  # cspell:disable-line
  ),
)
@base.CLIErrorGuard
def ElGamalSign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message to sign'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = _LoadObj(
    key_path, config.protect or None, elgamal.ElGamalPrivateKey
  )
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(message, in_format)
  sig: bytes = eg_priv.Sign(pt, associated_data=aad_bytes)
  config.console.print(_BytesToText(sig, out_format))


@eg_app.command(
  'verify',
  help='Verify `signature` for `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --b64 -p eg-key.pub elgamal verify -- eHl6 '
    'Xl4hlYK8SHVGw…0fCKJE1XVzA==\n\n'  # cspell:disable-line
    'El-Gamal signature: OK\n\n'
    '$ poetry run transcrypto --b64 -p eg-key.pub elgamal verify -- eLl6 '
    'Xl4hlYK8SHVGw…0fCKJE1XVzA==\n\n'  # cspell:disable-line
    'El-Gamal signature: INVALID'
  ),
)
@base.CLIErrorGuard
def ElGamalVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message that was signed earlier'),
  signature: str = typer.Argument(..., help='Putative signature for `message`'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during signing)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format = config.input_format
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = _LoadObj(
    key_path, config.protect or None, elgamal.ElGamalPublicKey
  )
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(message, in_format)
  sig: bytes = _BytesFromText(signature, in_format)
  config.console.print(
    'El-Gamal signature: '
    + ('OK' if eg_pub.Verify(pt, sig, associated_data=aad_bytes) else 'INVALID')
  )


dsa_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'DSA (Digital Signature Algorithm) asymmetric signing/verifying. '
    'No measures are taken here to prevent timing attacks. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'
  ),
)
app.add_typer(dsa_app, name='dsa')


@dsa_app.command(
  'shared',
  help=(
    'Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is '
    'the first step in key generation. `q-bits` should be larger than the secrets that '
    'will be protected and `p-bits` should be much larger than `q-bits` (e.g. 4096/544). '
    'The shared key can safely be used by any number of users to generate their '
    'private/public key pairs (with the `new` command). The shared keys are "public". '
    'Requires `-p`/`--key-path` to set the basename for output files.'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p dsa-key dsa shared --p-bits 128 --q-bits 32  '
    '# NEVER use such a small key: example only!\n\n'
    "DSA shared key saved to 'dsa-key.shared'"
  ),
)
@base.CLIErrorGuard
def DSAShared(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  p_bits: int = typer.Option(
    2048,
    '--p-bits',
    min=16,
    help='Prime modulus (`p`) size in bits; the default is a safe size',
  ),
  q_bits: int = typer.Option(
    256,
    '--q-bits',
    min=8,
    help=(
      'Prime modulus (`q`) size in bits; the default is a safe size ***IFF*** you '
      'are protecting symmetric keys or regular hashes'
    ),
  ),
) -> None:
  config: TransConfig = ctx.obj
  base_path = _RequireKeyPath(config, 'dsa')
  dsa_shared: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(p_bits, q_bits)
  _SaveObj(dsa_shared, base_path + '.shared', config.protect or None)
  config.console.print(f'DSA shared key saved to {base_path + ".shared"!r}')


@dsa_app.command(
  'new',
  help='Generate an individual DSA private/public key pair from a shared key.',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    "-p dsa-key dsa new\n\nDSA private/public keys saved to 'dsa-key.priv/.pub'"
  ),
)
@base.CLIErrorGuard
def DSANew(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: TransConfig = ctx.obj
  base_path = _RequireKeyPath(config, 'dsa')
  dsa_shared: dsa.DSASharedPublicKey = _LoadObj(
    base_path + '.shared', config.protect or None, dsa.DSASharedPublicKey
  )
  dsa_priv: dsa.DSAPrivateKey = dsa.DSAPrivateKey.New(dsa_shared)
  dsa_pub: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(dsa_priv)
  _SaveObj(dsa_priv, base_path + '.priv', config.protect or None)
  _SaveObj(dsa_pub, base_path + '.pub', config.protect or None)
  config.console.print(f'DSA private/public keys saved to {base_path + ".priv/.pub"!r}')


@dsa_app.command(
  'rawsign',
  help=(
    'Raw sign *integer* message with private key '
    '(BEWARE: no ECDSA/EdDSA padding or validation). '
    'Output will 2 *integers* in a `s1:s2` format.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p dsa-key.priv dsa rawsign 999\n\n2395961484:3435572290'
  ),
)
@base.CLIErrorGuard
def DSARawSign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to sign, 1≤`message`<`q`'),
) -> None:
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  key_path = _RequireKeyPath(config, 'dsa')
  dsa_priv: dsa.DSAPrivateKey = _LoadObj(key_path, config.protect or None, dsa.DSAPrivateKey)
  message_i = _ParseIntCLIInRange(message, what='message', min_value=1)
  m = message_i % dsa_priv.prime_seed
  s1, s2 = dsa_priv.RawSign(m)
  console.print(f'{s1}:{s2}')


@dsa_app.command(
  'rawverify',
  help=(
    'Raw verify *integer* `signature` for *integer* `message` with public key '
    '(BEWARE: no ECDSA/EdDSA padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p dsa-key.pub dsa rawverify 999 2395961484:3435572290\n\n'
    'DSA signature: OK\n\n'
    '$ poetry run transcrypto -p dsa-key.pub dsa rawverify 999 2395961484:3435572291\n\n'
    'DSA signature: INVALID'
  ),
)
@base.CLIErrorGuard
def DSARawVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(
    ..., help='Integer message that was signed earlier, 1≤`message`<`q`'
  ),
  signature: str = typer.Argument(
    ...,
    help=(
      'Integer putative signature for `message`; expects `s1:s2` format with 2 integers, '
      '`s1`,`s2`<`q`'
    ),
  ),
) -> None:
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  key_path = _RequireKeyPath(config, 'dsa')
  dsa_pub: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, dsa.DSAPublicKey)
  )
  message_i = _ParseIntCLIInRange(message, what='message', min_value=1)
  signature_i = _ParseIntPairCLI(signature, what='signature')
  m = message_i % dsa_pub.prime_seed
  console.print('DSA signature: ' + ('OK' if dsa_pub.RawVerify(m, signature_i) else 'INVALID'))


@dsa_app.command(
  'sign',
  help='Sign message with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --bin --out-b64 -p dsa-key.priv dsa '
    'sign "xyz"\n\nyq8InJVpViXh9…BD4par2XuA='
  ),
)
@base.CLIErrorGuard
def DSASign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message to sign'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  console: rich_console.Console = base.Console()
  key_path = _RequireKeyPath(config, 'dsa')
  dsa_priv: dsa.DSAPrivateKey = _LoadObj(key_path, config.protect or None, dsa.DSAPrivateKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(message, in_format)
  sig: bytes = dsa_priv.Sign(pt, associated_data=aad_bytes)
  console.print(_BytesToText(sig, out_format))


@dsa_app.command(
  'verify',
  help='Verify `signature` for `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --b64 -p dsa-key.pub dsa verify -- eHl6 yq8InJVpViXh9…BD4par2XuA=\n\n'
    'DSA signature: OK\n\n'
    '$ poetry run transcrypto --b64 -p dsa-key.pub dsa verify -- eLl6 yq8InJVpViXh9…BD4par2XuA=\n\n'
    'DSA signature: INVALID'
  ),
)
@base.CLIErrorGuard
def DSAVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message that was signed earlier'),
  signature: str = typer.Argument(..., help='Putative signature for `message`'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during signing)',
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format = config.input_format
  console: rich_console.Console = base.Console()
  key_path = _RequireKeyPath(config, 'dsa')
  dsa_pub: dsa.DSAPublicKey = _LoadObj(key_path, config.protect or None, dsa.DSAPublicKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(message, in_format)
  sig: bytes = _BytesFromText(signature, in_format)
  console.print(
    'DSA signature: ' + ('OK' if dsa_pub.Verify(pt, sig, associated_data=aad_bytes) else 'INVALID')
  )


bid_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'Bidding on a `secret` so that you can cryptographically convince a neutral '
    'party that the `secret` that was committed to previously was not changed. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'
  ),
)
app.add_typer(bid_app, name='bid')


@bid_app.command(
  'new',
  help=(
    'Generate the bid files for `secret`. '
    'Requires `-p`/`--key-path` to set the basename for output files.'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '--bin -p my-bid bid new "tomorrow it will rain"\n\n'
    "Bid private/public commitments saved to 'my-bid.priv/.pub'"
  ),
)
@base.CLIErrorGuard
def BidNew(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Input data to bid to, the protected "secret"'),
) -> None:
  config: TransConfig = ctx.obj
  in_format = config.input_format
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'bid')
  secret_bytes: bytes = _BytesFromText(secret, in_format)
  bid_priv: base.PrivateBid512 = base.PrivateBid512.New(secret_bytes)
  bid_pub: base.PublicBid512 = base.PublicBid512.Copy(bid_priv)
  _SaveObj(bid_priv, base_path + '.priv', config.protect or None)
  _SaveObj(bid_pub, base_path + '.pub', config.protect or None)
  console.print(f'Bid private/public commitments saved to {base_path + ".priv/.pub"!r}')


@bid_app.command(
  'verify',
  help=(
    'Verify the bid files for correctness and reveal the `secret`. '
    'Requires `-p`/`--key-path` to set the basename for output files.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto --out-bin -p my-bid bid verify\n\n'
    'Bid commitment: OK\n\n'
    'Bid secret:\n\n'
    'tomorrow it will rain'
  ),
)
@base.CLIErrorGuard
def BidVerify(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: TransConfig = ctx.obj
  out_format = config.output_format
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'bid')
  bid_priv: base.PrivateBid512 = _LoadObj(
    base_path + '.priv', config.protect or None, base.PrivateBid512
  )
  bid_pub: base.PublicBid512 = _LoadObj(
    base_path + '.pub', config.protect or None, base.PublicBid512
  )
  bid_pub_expect: base.PublicBid512 = base.PublicBid512.Copy(bid_priv)
  console.print(
    'Bid commitment: '
    + (
      'OK'
      if (
        bid_pub.VerifyBid(bid_priv.private_key, bid_priv.secret_bid) and bid_pub == bid_pub_expect
      )
      else 'INVALID'
    )
  )
  console.print('Bid secret:')
  console.print(_BytesToText(bid_priv.secret_bid, out_format))


sss_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'SSS (Shamir Shared Secret) secret sharing crypto scheme. '
    'No measures are taken here to prevent timing attacks. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'
  ),
)
app.add_typer(sss_app, name='sss')


@sss_app.command(
  'new',
  help=(
    'Generate the private keys with `bits` prime modulus size and so that at least a '
    '`minimum` number of shares are needed to recover the secret. '
    'This key will be used to generate the shares later (with the `shares` command). '
    'Requires `-p`/`--key-path` to set the basename for output files.'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p sss-key sss new 3 --bits 64  # NEVER use such a small key: example only!\n\n'
    "SSS private/public keys saved to 'sss-key.priv/.pub'"
  ),
)
@base.CLIErrorGuard
def SSSNew(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  minimum: int = typer.Argument(
    ..., min=2, help='Minimum number of shares required to recover secret, ≥ 2'
  ),
  bits: int = typer.Option(
    1024,
    '--bits',
    min=16,
    help=(
      'Prime modulus (`p`) size in bits; the default is a safe size ***IFF*** you '
      'are protecting symmetric keys; the number of bits should be comfortably larger '
      'than the size of the secret you want to protect with this scheme'
    ),
  ),
) -> None:
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = sss.ShamirSharedSecretPrivate.New(minimum, bits)
  sss_pub: sss.ShamirSharedSecretPublic = sss.ShamirSharedSecretPublic.Copy(sss_priv)
  _SaveObj(sss_priv, base_path + '.priv', config.protect or None)
  _SaveObj(sss_pub, base_path + '.pub', config.protect or None)
  console.print(f'SSS private/public keys saved to {base_path + ".priv/.pub"!r}')


@sss_app.command(
  'rawshares',
  help=(
    'Raw shares: Issue `count` private shares for an *integer* `secret` '
    '(BEWARE: no modern message wrapping, padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p sss-key sss rawshares 999 5\n\n'
    "SSS 5 individual (private) shares saved to 'sss-key.share.1…5'\n\n"
    '$ rm sss-key.share.2 sss-key.share.4  '
    '# this is to simulate only having shares 1,3,5'
  ),
)
@base.CLIErrorGuard
def SSSRawShares(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Integer secret to be protected, 1≤`secret`<*modulus*'),
  count: int = typer.Argument(
    ...,
    min=1,
    help=(
      'How many shares to produce; must be ≥ `minimum` used in `new` command or else the '
      '`secret` would become unrecoverable'
    ),
  ),
) -> None:
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = _LoadObj(
    base_path + '.priv', config.protect or None, sss.ShamirSharedSecretPrivate
  )
  secret_i = _ParseIntCLIInRange(secret, what='secret', min_value=1)
  for i, share in enumerate(sss_priv.RawShares(secret_i, max_shares=count)):
    _SaveObj(share, f'{base_path}.share.{i + 1}', config.protect or None)
  console.print(
    f'SSS {count} individual (private) shares saved to {base_path + ".share.1…" + str(count)!r}'
  )


@sss_app.command(
  'rawrecover',
  help=(
    'Raw recover *integer* secret from shares; will use any available shares '
    'that were found (BEWARE: no modern message wrapping, padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '-p sss-key sss rawrecover\n\n'
    "Loaded SSS share: 'sss-key.share.3'\n\n"
    "Loaded SSS share: 'sss-key.share.5'\n\n"
    "Loaded SSS share: 'sss-key.share.1'  "
    '# using only 3 shares: number 2/4 are missing\n\n'
    'Secret:\n\n999'
  ),
)
@base.CLIErrorGuard
def SSSRawRecover(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  sss_pub: sss.ShamirSharedSecretPublic = _LoadObj(
    base_path + '.pub', config.protect or None, sss.ShamirSharedSecretPublic
  )
  subset: list[sss.ShamirSharePrivate] = []
  for fname in glob.glob(base_path + '.share.*'):  # noqa: PTH207
    share = _LoadObj(fname, config.protect or None, sss.ShamirSharePrivate)
    subset.append(share)
    console.print(f'Loaded SSS share: {fname!r}')
  console.print('Secret:')
  console.print(sss_pub.RawRecoverSecret(subset))


@sss_app.command(
  'rawverify',
  help=(
    'Raw verify shares against a secret (private params; '
    'BEWARE: no modern message wrapping, padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p sss-key sss rawverify 999\n\n'
    "SSS share 'sss-key.share.3' verification: OK\n\n"
    "SSS share 'sss-key.share.5' verification: OK\n\n"
    "SSS share 'sss-key.share.1' verification: OK\n\n"
    '$ poetry run transcrypto -p sss-key sss rawverify 998\n\n'
    "SSS share 'sss-key.share.3' verification: INVALID\n\n"
    "SSS share 'sss-key.share.5' verification: INVALID\n\n"
    "SSS share 'sss-key.share.1' verification: INVALID"
  ),
)
@base.CLIErrorGuard
def SSSRawVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Integer secret used to generate the shares, ≥ 1'),
) -> None:
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = _LoadObj(
    base_path + '.priv', config.protect or None, sss.ShamirSharedSecretPrivate
  )
  secret_i = _ParseIntCLIInRange(secret, what='secret', min_value=1)
  for fname in glob.glob(base_path + '.share.*'):  # noqa: PTH207
    share = _LoadObj(fname, config.protect or None, sss.ShamirSharePrivate)
    console.print(
      f'SSS share {fname!r} verification: '
      f'{"OK" if sss_priv.RawVerifyShare(secret_i, share) else "INVALID"}'
    )


@sss_app.command(
  'shares',
  help='Shares: Issue `count` private shares for a `secret`.',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '--bin -p sss-key sss shares "abcde" 5\n\n'
    "SSS 5 individual (private) shares saved to 'sss-key.share.1…5'\n\n"
    '$ rm sss-key.share.2 sss-key.share.4  '
    '# this is to simulate only having shares 1,3,5'
  ),
)
@base.CLIErrorGuard
def SSSShares(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Secret to be protected'),
  count: int = typer.Argument(
    ...,
    help=(
      'How many shares to produce; must be ≥ `minimum` used in `new` command or else the '
      '`secret` would become unrecoverable'
    ),
  ),
) -> None:
  config: TransConfig = ctx.obj
  in_format = config.input_format
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = _LoadObj(
    base_path + '.priv', config.protect or None, sss.ShamirSharedSecretPrivate
  )
  pt: bytes = _BytesFromText(secret, in_format)
  for i, data_share in enumerate(sss_priv.MakeDataShares(pt, count)):
    _SaveObj(data_share, f'{base_path}.share.{i + 1}', config.protect or None)
  console.print(
    f'SSS {count} individual (private) shares saved to {base_path + ".share.1…" + str(count)!r}'
  )


@sss_app.command(
  'recover',
  help='Recover secret from shares; will use any available shares that were found.',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto '
    '--out-bin -p sss-key sss recover\n\n'
    "Loaded SSS share: 'sss-key.share.3'\n\n"
    "Loaded SSS share: 'sss-key.share.5'\n\n"
    "Loaded SSS share: 'sss-key.share.1'  "
    '# using only 3 shares: number 2/4 are missing\n\n'
    'Secret:\n\nabcde'
  ),
)
@base.CLIErrorGuard
def SSSRecover(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: TransConfig = ctx.obj
  out_format = config.output_format
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  subset: list[sss.ShamirSharePrivate] = []
  data_share: sss.ShamirShareData | None = None
  for fname in glob.glob(base_path + '.share.*'):  # noqa: PTH207
    share = _LoadObj(fname, config.protect or None, sss.ShamirSharePrivate)
    subset.append(share)
    if isinstance(share, sss.ShamirShareData):
      data_share = share
    console.print(f'Loaded SSS share: {fname!r}')
  if data_share is None:
    raise base.InputError('no data share found among the available shares')
  pt = data_share.RecoverData(subset)
  console.print('Secret:')
  console.print(_BytesToText(pt, out_format))


@app.command(
  'markdown',
  help='Emit Markdown docs for the CLI (see README.md section "Creating a New Version").',
  epilog=(
    'Example:\n\n\n\n$ poetry run transcrypto markdown > transcrypto.md\n\n<<saves CLI doc>>'
  ),
)
@base.CLIErrorGuard
def Markdown() -> None:  # documentation is help/epilog/args # noqa: D103
  console: rich_console.Console = base.Console()
  console.print(base.GenerateTyperHelpMarkdown(app, prog_name='transcrypto'))


def _RequireKeyPath(config: TransConfig, command: str, /) -> str:
  if config.key_path is None:
    raise base.InputError(f'you must provide -p/--key-path option for {command!r}')
  if config.key_path.exists() and config.key_path.is_dir():
    raise base.InputError(f'-p/--key-path must not be a directory: {str(config.key_path)!r}')
  return str(config.key_path)


def _ParseInt(s: str, /) -> int:
  """Parse int, try to determine if binary, octal, decimal, or hexadecimal.

  Args:
      s (str): putative int

  Returns:
      int: parsed int

  """
  s = s.strip().lower().replace('_', '')
  base_guess = 10
  if s.startswith('0x'):
    base_guess = 16
  elif s.startswith('0b'):
    base_guess = 2
  elif s.startswith('0o'):
    base_guess = 8
  return int(s, base_guess)


def _ParseIntList(items: abc.Iterable[str], /) -> list[int]:
  """Parse list of strings into list of ints.

  Args:
      items (Iterable[str]): putative int list

  Returns:
      list[int]: parsed list

  """
  return [_ParseInt(x) for x in items]


def _BytesFromText(text: str, fmt: IOFormat, /) -> bytes:
  """Parse bytes according to `fmt` (IOFormat.hex|b64|bin).

  Args:
      text (str): text
      fmt (IOFormat): input format

  Returns:
      bytes: parsed bytes

  """
  match fmt:
    case IOFormat.bin:
      return text.encode('utf-8')
    case IOFormat.hex:
      return base.HexToBytes(text)
    case IOFormat.b64:
      return base.EncodedToBytes(text)


def _BytesToText(b: bytes, fmt: IOFormat, /) -> str:
  """Format bytes according to `fmt` (IOFormat.hex|b64|bin).

  Args:
      b (bytes): blob
      fmt (IOFormat): output format

  Returns:
      str: formatted string

  """
  match fmt:
    case IOFormat.bin:
      return b.decode('utf-8', errors='replace')
    case IOFormat.hex:
      return base.BytesToHex(b)
    case IOFormat.b64:
      return base.BytesToEncoded(b)


def _MaybePasswordKey(password: str | None, /) -> aes.AESKey | None:
  """Generate a key if there is a password.

  Args:
      password (str | None): password string

  Returns:
      aes.AESKey | None: AES key

  """
  return aes.AESKey.FromStaticPassword(password) if password else None


def _SaveObj(obj: Any, path: str, password: str | None, /) -> None:  # noqa: ANN401
  """Save object."""
  key: aes.AESKey | None = _MaybePasswordKey(password)
  blob: bytes = base.Serialize(obj, file_path=path, key=key)
  logging.info('saved object: %s (%s)', path, base.HumanizedBytes(len(blob)))


def _LoadObj(path: str, password: str | None, expect: type, /) -> Any:  # noqa: ANN401
  """Load object.

  Args:
      path (str): path
      password (str | None): password
      expect (type): type to expect

  Raises:
      base.InputError: input error

  Returns:
      Any: loaded object

  """
  key: aes.AESKey | None = _MaybePasswordKey(password)
  obj: Any = base.DeSerialize(file_path=path, key=key)
  if not isinstance(obj, expect):
    raise base.InputError(
      f'Object loaded from {path} is of invalid type {type(obj)}, expected {expect}'
    )
  return obj
