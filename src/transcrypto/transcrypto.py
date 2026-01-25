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
from collections import abc
from typing import Any

import click
import typer
from rich import console as rich_console

from . import __version__, aes, base, dsa, elgamal, modmath, rsa, sss

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
    'Examples:\n\n\n\n'
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
    'poetry run transcrypto-p eg-key.pub elgamal rawverify <message> <s1:s2>\n\n'
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


@app.callback(invoke_without_command=True)  # have only one; this is the "constructor"
def Main(
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
  # leave this docstring without args/return/raise sections as it shows up in `--help`
  # one way or another the args are well documented in the CLI help and in the code above
  """Set things up; Main CLI entry point."""  # noqa: DOC501
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
  'isprime', epilog='Example:\n\n\n\n$ poetry run transcrypto isprime 2305843009213693951\nTrue'
)
@base.CLIErrorGuard
def IsPrimeCLI(*, ctx: typer.Context, n: str = typer.Argument(..., help='Integer n, ≥ 1')) -> None:
  """Primality test for integer `n`."""
  config: TransConfig = ctx.obj
  config.console.print(str(modmath.IsPrime(_ParseInt(n))))


@app.command(
  'primegen', epilog='Example:\n\n\n\n$ poetry run transcrypto primegen 10 -c 5\n11\n13\n17\n19\n23'
)
@base.CLIErrorGuard
def PrimeGenCLI(
  *,
  ctx: typer.Context,
  start: str = typer.Argument(..., help='Starting integer, ≥ 0'),
  count: int = typer.Option(
    1,
    '-c',
    '--count',
    min=1,
    help='Number of primes to print, ≥ 1',
  ),
) -> None:
  """Generate primes starting at `start`."""
  config: TransConfig = ctx.obj
  n_start = _ParseInt(start)
  for i, pr in enumerate(modmath.PrimeGenerator(n_start)):
    if i >= count:
      return
    config.console.print(pr)


@app.command(
  'mersenne',
  epilog='Example:\n\n\n\n$ poetry run transcrypto mersenne -k 2 -C 13\nk=2  M=3  perfect=6\n...',
)
@base.CLIErrorGuard
def MersenneCLI(
  *,
  ctx: typer.Context,
  min_k: int = typer.Option(1, '-k', '--min-k', min=1, help='Starting exponent k, ≥ 1'),
  cutoff_k: int = typer.Option(
    10000,
    '-C',
    '--cutoff-k',
    min=1,
    help='Stop once k > cutoff-k',
  ),
) -> None:
  """Generate Mersenne primes and their perfect numbers."""
  config: TransConfig = ctx.obj
  for k, m, perfect in modmath.MersennePrimesGenerator(min_k):
    if k > cutoff_k:
      return
    config.console.print(f'k={k}  M={m}  perfect={perfect}')


@app.command('gcd', epilog='Example:\n\n\n\n$ poetry run transcrypto gcd 462 1071\n21')
@base.CLIErrorGuard
def GcdCLI(
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer a, ≥ 0'),
  b: str = typer.Argument(..., help='Integer b, ≥ 0 (not both zero)'),
) -> None:
  """Greatest common divisor of `a` and `b`."""
  config: TransConfig = ctx.obj
  config.console.print(base.GCD(_ParseInt(a), _ParseInt(b)))


@app.command('xgcd', epilog='Example:\n\n\n\n$ poetry run transcrypto xgcd 100 24\n(4, 1, -4)')
@base.CLIErrorGuard
def XgcdCLI(
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer a, ≥ 0'),
  b: str = typer.Argument(..., help='Integer b, ≥ 0 (not both zero)'),
) -> None:
  """Compute extended gcd: returns (gcd, x, y) such that a*x + b*y = gcd."""
  config: TransConfig = ctx.obj
  config.console.print(str(base.ExtendedGCD(_ParseInt(a), _ParseInt(b))))


# ========================= Typer command groups ==================================================

random_app = typer.Typer(
  no_args_is_help=True,
  help='Cryptographically secure randomness, from the OS CSPRNG.',
)
app.add_typer(random_app, name='random')


@random_app.command(
  'bits',
  epilog='Example:\n\n\n\n$ poetry run transcrypto random bits 16\n36650',
)
@base.CLIErrorGuard
def RandomBits(
  *,
  ctx: typer.Context,
  bits: int = typer.Argument(..., min=8, help='Number of bits, ≥ 8'),
) -> None:
  """Random integer with exact bit length = `bits` (MSB will be 1)."""
  config: TransConfig = ctx.obj
  config.console.print(base.RandBits(bits))


@random_app.command(
  'int',
  epilog='Example:\n\n\n\n$ poetry run transcrypto random int 1000 2000\n1628',
)
@base.CLIErrorGuard
def RandomInt(
  *,
  ctx: typer.Context,
  min_: str = typer.Argument(..., help='Minimum, ≥ 0'),
  max_: str = typer.Argument(..., help='Maximum, > `min`'),
) -> None:
  """Uniform random integer in `[min, max]` range, inclusive."""
  config: TransConfig = ctx.obj
  config.console.print(base.RandInt(_ParseInt(min_), _ParseInt(max_)))


@random_app.command(
  'bytes',
  epilog='Example:\n\n\n\n$ poetry run transcrypto random bytes 32\n6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f',
)
@base.CLIErrorGuard
def RandomBytes(
  *,
  ctx: typer.Context,
  n: int = typer.Argument(..., min=1, help='Number of bytes, ≥ 1'),
) -> None:
  """Generate `n` cryptographically secure random bytes."""
  config: TransConfig = ctx.obj
  out_format = config.output_format
  config.console.print(_BytesToText(base.RandBytes(n), out_format))


@random_app.command(
  'prime',
  epilog='Example:\n\n\n\n$ poetry run transcrypto random prime 64\n17588931907757630417',
)
@base.CLIErrorGuard
def RandomPrime(
  *,
  ctx: typer.Context,
  bits: int = typer.Argument(..., min=11, help='Number of bits, ≥ 11'),
) -> None:
  """Generate a random prime with exact bit length = `bits`."""
  config: TransConfig = ctx.obj
  config.console.print(modmath.NBitRandomPrimes(bits).pop())


mod_app = typer.Typer(
  no_args_is_help=True,
  help='Modular arithmetic helpers.',
)
app.add_typer(mod_app, name='mod')


@mod_app.command(
  'inv',
  epilog='Example:\n\n\n\n$ poetry run transcrypto mod inv 17 97\n40',
)
@base.CLIErrorGuard
def ModInv(
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer a'),
  m: str = typer.Argument(..., help='Modulus m'),
) -> None:
  """Modular inverse."""
  config: TransConfig = ctx.obj
  try:
    config.console.print(modmath.ModInv(_ParseInt(a), _ParseInt(m)))
  except modmath.ModularDivideError:
    config.console.print('<<INVALID>> no modular inverse exists (ModularDivideError)')


@mod_app.command(
  'div',
  epilog='Example:\n\n\n\n$ poetry run transcrypto mod div 6 127 13\n4',
)
@base.CLIErrorGuard
def ModDiv(
  *,
  ctx: typer.Context,
  x: str = typer.Argument(..., help='Integer x'),
  y: str = typer.Argument(..., help='Integer y'),
  m: str = typer.Argument(..., help='Modulus m'),
) -> None:
  """Modular division x/y mod m."""
  config: TransConfig = ctx.obj
  try:
    config.console.print(modmath.ModDiv(_ParseInt(x), _ParseInt(y), _ParseInt(m)))
  except modmath.ModularDivideError:
    config.console.print('<<INVALID>> no modular inverse exists (ModularDivideError)')


@mod_app.command('exp', epilog='Example:\n\n\n\n$ poetry run transcrypto mod exp 438 234 127\n1')
@base.CLIErrorGuard
def ModExp(
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer a'),
  e: str = typer.Argument(..., help='Exponent e'),
  m: str = typer.Argument(..., help='Modulus m'),
) -> None:
  """Modular exponentiation a^e mod m."""
  config: TransConfig = ctx.obj
  config.console.print(modmath.ModExp(_ParseInt(a), _ParseInt(e), _ParseInt(m)))


@mod_app.command(
  'poly', epilog='Example:\n\n\n\n$ poetry run transcrypto mod poly 12 17 10 20 30\n2'
)
@base.CLIErrorGuard
def ModPoly(
  *,
  ctx: typer.Context,
  x: str = typer.Argument(..., help='Integer x'),
  m: str = typer.Argument(..., help='Modulus m'),
  coeff: list[str] = typer.Argument(..., help='Polynomial coefficients c0 c1 ...'),  # noqa: B008
) -> None:
  """Polynomial evaluation in mod m."""
  config: TransConfig = ctx.obj
  config.console.print(modmath.ModPolynomial(_ParseInt(x), _ParseIntList(coeff), _ParseInt(m)))


@mod_app.command(
  'lagrange', epilog='Example:\n\n\n\n$ poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1\n9'
)
@base.CLIErrorGuard
def ModLagrange(
  *,
  ctx: typer.Context,
  x: str = typer.Argument(..., help='Integer x'),
  m: str = typer.Argument(..., help='Modulus m'),
  pt: list[str] = typer.Argument(..., help='Points as x:y pairs'),  # noqa: B008
) -> None:
  """Lagrange interpolation (mod m)."""
  config: TransConfig = ctx.obj
  pts: dict[int, int] = {}
  for kv in pt:
    k_s, v_s = kv.split(':', 1)
    pts[_ParseInt(k_s)] = _ParseInt(v_s)
  config.console.print(modmath.ModLagrangeInterpolate(_ParseInt(x), pts, _ParseInt(m)))


@mod_app.command('crt', epilog='Example:\n\n\n\n$ poetry run transcrypto mod crt 6 7 127 13\n97')
@base.CLIErrorGuard
def ModCRT(
  *,
  ctx: typer.Context,
  a1: str = typer.Argument(..., help='Residue a1'),
  m1: str = typer.Argument(..., help='Modulus m1'),
  a2: str = typer.Argument(..., help='Residue a2'),
  m2: str = typer.Argument(..., help='Modulus m2'),
) -> None:
  """Chinese Remainder Theorem (pair)."""
  config: TransConfig = ctx.obj
  try:
    config.console.print(
      modmath.CRTPair(_ParseInt(a1), _ParseInt(m1), _ParseInt(a2), _ParseInt(m2))
    )
  except modmath.ModularDivideError:
    config.console.print('<<INVALID>> moduli m1/m2 not co-prime (ModularDivideError)')


hash_app = typer.Typer(
  no_args_is_help=True,
  help='Hashing helpers.',
)
app.add_typer(hash_app, name='hash')


@hash_app.command(
  'sha256', epilog='Example:\n\n\n\n$ poetry run transcrypto hash sha256 xyz\nd3e6b1...'
)
@base.CLIErrorGuard
def Hash256(*, ctx: typer.Context, data: str = typer.Argument(..., help='Data to hash')) -> None:
  """SHA-256 hashing."""
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  bt = _BytesFromText(data, in_format)
  config.console.print(_BytesToText(base.Hash256(bt), out_format))


@hash_app.command(
  'sha512', epilog='Example:\n\n\n\n$ poetry run transcrypto hash sha512 xyz\n4b68ab...'
)
@base.CLIErrorGuard
def Hash512(*, ctx: typer.Context, data: str = typer.Argument(..., help='Data to hash')) -> None:
  """SHA-512 hashing."""
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  bt = _BytesFromText(data, in_format)
  config.console.print(_BytesToText(base.Hash512(bt), out_format))


@hash_app.command(
  'file',
  epilog='Example:\n\n\n\n$ poetry run transcrypto hash file /etc/passwd --digest sha512\n4b68ab...',
)
@base.CLIErrorGuard
def HashFile(
  *,
  ctx: typer.Context,
  path: pathlib.Path = typer.Argument(  # noqa: B008
    ...,
    exists=True,
    file_okay=True,
    dir_okay=False,
    readable=True,
    resolve_path=True,
    help='File path to hash',
  ),
  digest: str = typer.Option('sha256', '--digest', help='Digest algorithm: sha256 or sha512'),
) -> None:
  """Hash a file."""
  config: TransConfig = ctx.obj
  out_format = config.output_format
  config.console.print(_BytesToText(base.FileHash(str(path), digest=digest), out_format))


aes_app = typer.Typer(
  no_args_is_help=True,
  help='Advanced Encryption Standard (AES) operations.',
)
app.add_typer(aes_app, name='aes')


@aes_app.command(
  'key',
  epilog='Example:\n\n\n\n$ poetry run transcrypto aes key "correct horse battery staple"\n<key>',
)
@base.CLIErrorGuard
def AESKeyFromPass(
  *,
  ctx: typer.Context,
  password: str = typer.Argument(..., help='Password string to derive key'),
) -> None:
  """Generate AES-256 key from a password."""
  config: TransConfig = ctx.obj
  out_format = config.output_format
  aes_key = aes.AESKey.FromStaticPassword(password)
  if config.key_path is not None:
    _SaveObj(aes_key, str(config.key_path), config.protect or None)
    config.console.print(f'AES key saved to {str(config.key_path)!r}')
  else:
    config.console.print(_BytesToText(aes_key.key256, out_format))


@aes_app.command('encrypt')
@base.CLIErrorGuard
def AESEncrypt(
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='Plaintext to encrypt'),
  key: str | None = typer.Option(
    None, '-k', '--key', help='AES key (32 bytes), encoded per input format'
  ),
  aad: str = typer.Option(
    '', '-a', '--aad', help='Optional associated data (AAD), encoded per input format'
  ),
) -> None:
  """Encrypt using AES-256-GCM."""  # noqa: DOC501
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


@aes_app.command('decrypt')
@base.CLIErrorGuard
def AESDecrypt(
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='Ciphertext to decrypt'),
  key: str | None = typer.Option(
    None, '-k', '--key', help='AES key (32 bytes), encoded per input format'
  ),
  aad: str = typer.Option(
    '', '-a', '--aad', help='Optional associated data (AAD), encoded per input format'
  ),
) -> None:
  """Decrypt using AES-256-GCM."""  # noqa: DOC501
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
  ct: bytes = _BytesFromText(ciphertext, in_format)
  pt: bytes = aes_key.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(_BytesToText(pt, out_format))


aes_ecb_app = typer.Typer(
  no_args_is_help=True,
  help='AES-ECB 128-bit block encrypt/decrypt (unsafe).',
)
aes_app.add_typer(aes_ecb_app, name='ecb')


@aes_ecb_app.callback(invoke_without_command=True)
def AESECBMain(
  *,
  ctx: typer.Context,
  key: str | None = typer.Option(
    None, '-k', '--key', help='AES key (32 bytes), encoded per input format'
  ),
) -> None:
  """AES ECB mode subcommands."""
  ctx.meta['aes_ecb_key'] = key


@aes_ecb_app.command('encrypt')
@base.CLIErrorGuard
def AESEcbEncrypt(
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='128-bit hex block to encrypt'),
) -> None:
  """Encrypt a 128-bit hex block using AES-ECB."""  # noqa: DOC501
  config: TransConfig = ctx.obj
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


@aes_ecb_app.command('decrypt')
@base.CLIErrorGuard
def AESEcbDecrypt(
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='128-bit hex block to decrypt'),
) -> None:
  """Decrypt a 128-bit hex block using AES-ECB."""  # noqa: DOC501
  config: TransConfig = ctx.obj
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
  help='RSA (Rivest-Shamir-Adleman) operations.',
)
app.add_typer(rsa_app, name='rsa')


@rsa_app.command('new')
@base.CLIErrorGuard
def RSANew(
  *,
  ctx: typer.Context,
  bits: int = typer.Option(2048, '--bits', help='Modulus bit length'),
) -> None:
  """Generate new RSA key pair."""
  config: TransConfig = ctx.obj

  base_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(bits)
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(rsa_priv)
  _SaveObj(rsa_priv, base_path + '.priv', config.protect or None)
  _SaveObj(rsa_pub, base_path + '.pub', config.protect or None)
  config.console.print(f'RSA private/public keys saved to {base_path + ".priv/.pub"!r}')


@rsa_app.command('rawencrypt')
@base.CLIErrorGuard
def RSARawEncrypt(
  *, ctx: typer.Context, message: str = typer.Argument(..., help='Integer message')
) -> None:
  """Raw RSA encrypt (pedagogical; unsafe if misused)."""
  config: TransConfig = ctx.obj
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, rsa.RSAPublicKey)
  )
  m = _ParseInt(message)
  config.console.print(rsa_pub.RawEncrypt(m))


@rsa_app.command('rawdecrypt')
@base.CLIErrorGuard
def RSARawDecrypt(
  *, ctx: typer.Context, ciphertext: str = typer.Argument(..., help='Integer ciphertext')
) -> None:
  """Raw RSA decrypt (pedagogical; unsafe if misused)."""
  config: TransConfig = ctx.obj
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = _LoadObj(key_path, config.protect or None, rsa.RSAPrivateKey)
  c = _ParseInt(ciphertext)
  config.console.print(rsa_priv.RawDecrypt(c))


@rsa_app.command('rawsign')
@base.CLIErrorGuard
def RSARawSign(
  *, ctx: typer.Context, message: str = typer.Argument(..., help='Integer message')
) -> None:
  """Raw RSA sign (pedagogical; unsafe if misused)."""
  config: TransConfig = ctx.obj
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = _LoadObj(key_path, config.protect or None, rsa.RSAPrivateKey)
  m = _ParseInt(message)
  config.console.print(rsa_priv.RawSign(m))


@rsa_app.command('rawverify')
@base.CLIErrorGuard
def RSARawVerify(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message'),
  signature: str = typer.Argument(..., help='Integer signature'),
) -> None:
  """Raw RSA verify (pedagogical; unsafe if misused)."""
  config: TransConfig = ctx.obj
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, rsa.RSAPublicKey)
  )
  m = _ParseInt(message)
  sig = _ParseInt(signature)
  config.console.print('RSA signature: ' + ('OK' if rsa_pub.RawVerify(m, sig) else 'INVALID'))


@rsa_app.command('encrypt')
@base.CLIErrorGuard
def RSAEncrypt(
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='Plaintext, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe RSA-KEM + AEAD encrypt."""
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = _LoadObj(key_path, config.protect or None, rsa.RSAPublicKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(plaintext, in_format)
  ct: bytes = rsa_pub.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(_BytesToText(ct, out_format))


@rsa_app.command('decrypt')
@base.CLIErrorGuard
def RSADecrypt(
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='Ciphertext, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe RSA-KEM + AEAD decrypt."""
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = _LoadObj(key_path, config.protect or None, rsa.RSAPrivateKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  ct: bytes = _BytesFromText(ciphertext, in_format)
  pt: bytes = rsa_priv.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(_BytesToText(pt, out_format))


@rsa_app.command('sign')
@base.CLIErrorGuard
def RSASign(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe RSA signature."""
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  key_path = _RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = _LoadObj(key_path, config.protect or None, rsa.RSAPrivateKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(message, in_format)
  sig: bytes = rsa_priv.Sign(pt, associated_data=aad_bytes)
  config.console.print(_BytesToText(sig, out_format))


@rsa_app.command('verify')
@base.CLIErrorGuard
def RSAVerify(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message, encoded per input format'),
  signature: str = typer.Argument(..., help='Signature, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe RSA signature verification."""
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
  help='ElGamal operations.',
)
app.add_typer(eg_app, name='elgamal')


@eg_app.command('shared')
@base.CLIErrorGuard
def ElGamalShared(
  *,
  ctx: typer.Context,
  bits: int = typer.Option(2048, '--bits', help='Prime size in bits'),
) -> None:
  """Generate El-Gamal shared parameters."""
  config: TransConfig = ctx.obj
  base_path = _RequireKeyPath(config, 'elgamal')
  shared_eg: elgamal.ElGamalSharedPublicKey = elgamal.ElGamalSharedPublicKey.NewShared(bits)
  _SaveObj(shared_eg, base_path + '.shared', config.protect or None)
  config.console.print(f'El-Gamal shared key saved to {base_path + ".shared"!r}')


@eg_app.command('new')
@base.CLIErrorGuard
def ElGamalNew(*, ctx: typer.Context) -> None:
  """Generate El-Gamal private/public key pair."""
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


@eg_app.command('rawencrypt')
@base.CLIErrorGuard
def ElGamalRawEncrypt(
  *, ctx: typer.Context, message: str = typer.Argument(..., help='Integer message')
) -> None:
  """Raw El-Gamal encrypt (pedagogical)."""
  config: TransConfig = ctx.obj
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, elgamal.ElGamalPublicKey)
  )
  m = _ParseInt(message)
  c1, c2 = eg_pub.RawEncrypt(m)
  config.console.print(f'{c1}:{c2}')


@eg_app.command('rawdecrypt')
@base.CLIErrorGuard
def ElGamalRawDecrypt(
  *, ctx: typer.Context, ciphertext: str = typer.Argument(..., help='Ciphertext as c1:c2')
) -> None:
  """Raw El-Gamal decrypt (pedagogical)."""
  config: TransConfig = ctx.obj
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = _LoadObj(
    key_path, config.protect or None, elgamal.ElGamalPrivateKey
  )
  c1_s, c2_s = ciphertext.split(':')
  ss = (_ParseInt(c1_s), _ParseInt(c2_s))
  config.console.print(eg_priv.RawDecrypt(ss))


@eg_app.command('rawsign')
@base.CLIErrorGuard
def ElGamalRawSign(
  *, ctx: typer.Context, message: str = typer.Argument(..., help='Integer message')
) -> None:
  """Raw El-Gamal sign (pedagogical)."""
  config: TransConfig = ctx.obj
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = _LoadObj(
    key_path, config.protect or None, elgamal.ElGamalPrivateKey
  )
  m = _ParseInt(message)
  s1, s2 = eg_priv.RawSign(m)
  config.console.print(f'{s1}:{s2}')


@eg_app.command('rawverify')
@base.CLIErrorGuard
def ElGamalRawVerify(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message'),
  signature: str = typer.Argument(..., help='Signature as s1:s2'),
) -> None:
  """Raw El-Gamal verify (pedagogical)."""
  config: TransConfig = ctx.obj
  key_path = _RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, elgamal.ElGamalPublicKey)
  )
  m = _ParseInt(message)
  s1_s, s2_s = signature.split(':')
  ss = (_ParseInt(s1_s), _ParseInt(s2_s))
  config.console.print('El-Gamal signature: ' + ('OK' if eg_pub.RawVerify(m, ss) else 'INVALID'))


@eg_app.command('encrypt')
@base.CLIErrorGuard
def ElGamalEncrypt(
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='Plaintext, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe El-Gamal encrypt."""
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


@eg_app.command('decrypt')
@base.CLIErrorGuard
def ElGamalDecrypt(
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='Ciphertext, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe El-Gamal decrypt."""
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


@eg_app.command('sign')
@base.CLIErrorGuard
def ElGamalSign(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe El-Gamal sign."""
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


@eg_app.command('verify')
@base.CLIErrorGuard
def ElGamalVerify(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message, encoded per input format'),
  signature: str = typer.Argument(..., help='Signature, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe El-Gamal verify."""
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
  help='DSA operations.',
)
app.add_typer(dsa_app, name='dsa')


@dsa_app.command('shared')
@base.CLIErrorGuard
def DSAShared(
  *,
  ctx: typer.Context,
  p_bits: int = typer.Option(2048, '--p-bits', help='p bit length'),
  q_bits: int = typer.Option(256, '--q-bits', help='q bit length'),
) -> None:
  """Generate DSA shared parameters."""
  config: TransConfig = ctx.obj
  base_path = _RequireKeyPath(config, 'dsa')
  dsa_shared: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(p_bits, q_bits)
  _SaveObj(dsa_shared, base_path + '.shared', config.protect or None)
  config.console.print(f'DSA shared key saved to {base_path + ".shared"!r}')


@dsa_app.command('new')
@base.CLIErrorGuard
def DSANew(*, ctx: typer.Context) -> None:
  """Generate DSA private/public key pair."""
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


@dsa_app.command('rawsign')
@base.CLIErrorGuard
def DSARawSign(
  *, ctx: typer.Context, message: str = typer.Argument(..., help='Integer message')
) -> None:
  """Raw DSA sign (pedagogical)."""
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  key_path = _RequireKeyPath(config, 'dsa')
  dsa_priv: dsa.DSAPrivateKey = _LoadObj(key_path, config.protect or None, dsa.DSAPrivateKey)
  m = _ParseInt(message) % dsa_priv.prime_seed
  s1, s2 = dsa_priv.RawSign(m)
  console.print(f'{s1}:{s2}')


@dsa_app.command('rawverify')
@base.CLIErrorGuard
def DSARawVerify(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message'),
  signature: str = typer.Argument(..., help='Signature as s1:s2'),
) -> None:
  """Raw DSA verify (pedagogical)."""
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  key_path = _RequireKeyPath(config, 'dsa')
  dsa_pub: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(
    _LoadObj(key_path, config.protect or None, dsa.DSAPublicKey)
  )
  m = _ParseInt(message) % dsa_pub.prime_seed
  c1_s, c2_s = signature.split(':')
  ss = (_ParseInt(c1_s), _ParseInt(c2_s))
  console.print('DSA signature: ' + ('OK' if dsa_pub.RawVerify(m, ss) else 'INVALID'))


@dsa_app.command('sign')
@base.CLIErrorGuard
def DSASign(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe DSA sign."""
  config: TransConfig = ctx.obj
  in_format, out_format = config.input_format, config.output_format
  console: rich_console.Console = base.Console()
  key_path = _RequireKeyPath(config, 'dsa')
  dsa_priv: dsa.DSAPrivateKey = _LoadObj(key_path, config.protect or None, dsa.DSAPrivateKey)
  aad_bytes: bytes | None = _BytesFromText(aad, in_format) if aad else None
  pt: bytes = _BytesFromText(message, in_format)
  sig: bytes = dsa_priv.Sign(pt, associated_data=aad_bytes)
  console.print(_BytesToText(sig, out_format))


@dsa_app.command('verify')
@base.CLIErrorGuard
def DSAVerify(
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Message, encoded per input format'),
  signature: str = typer.Argument(..., help='Signature, encoded per input format'),
  aad: str = typer.Option('', '-a', '--aad', help='Associated data, encoded per input format'),
) -> None:
  """Safe DSA verify."""
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
  help='Public bid operations.',
)
app.add_typer(bid_app, name='bid')


@bid_app.command('new')
@base.CLIErrorGuard
def BidNew(
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Bid secret, encoded per input format'),
) -> None:
  """Create a new public bid commitment."""
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


@bid_app.command('verify')
@base.CLIErrorGuard
def BidVerify(*, ctx: typer.Context) -> None:
  """Verify bid commitment and reveal secret (developer utility)."""
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
  help='Shamir Secret Sharing (SSS) operations.',
)
app.add_typer(sss_app, name='sss')


@sss_app.command('new')
@base.CLIErrorGuard
def SSSNew(
  *,
  ctx: typer.Context,
  minimum: int = typer.Argument(..., help='Minimum shares needed to recover (threshold)'),
  bits: int = typer.Option(1024, '--bits', help='Prime modulus size in bits'),
) -> None:
  """Generate SSS parameters."""
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = sss.ShamirSharedSecretPrivate.New(minimum, bits)
  sss_pub: sss.ShamirSharedSecretPublic = sss.ShamirSharedSecretPublic.Copy(sss_priv)
  _SaveObj(sss_priv, base_path + '.priv', config.protect or None)
  _SaveObj(sss_pub, base_path + '.pub', config.protect or None)
  console.print(f'SSS private/public keys saved to {base_path + ".priv/.pub"!r}')


@sss_app.command('rawshares')
@base.CLIErrorGuard
def SSSRawShares(
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Integer secret used to generate the shares'),
  count: int = typer.Argument(..., help='How many shares to create'),
) -> None:
  """Raw shares for integer secrets (pedagogical)."""
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = _LoadObj(
    base_path + '.priv', config.protect or None, sss.ShamirSharedSecretPrivate
  )
  secret_int: int = _ParseInt(secret)
  for i, share in enumerate(sss_priv.RawShares(secret_int, max_shares=count)):
    _SaveObj(share, f'{base_path}.share.{i + 1}', config.protect or None)
  console.print(
    f'SSS {count} individual (private) shares saved to {base_path + ".share.1…" + str(count)!r}'
  )


@sss_app.command('rawrecover')
@base.CLIErrorGuard
def SSSRawRecover(*, ctx: typer.Context) -> None:
  """Raw recover integer secret from shares."""
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


@sss_app.command('rawverify')
@base.CLIErrorGuard
def SSSRawVerify(
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Integer secret used to generate the shares'),
) -> None:
  """Raw verify shares against an integer secret."""
  config: TransConfig = ctx.obj
  console: rich_console.Console = base.Console()
  base_path = _RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = _LoadObj(
    base_path + '.priv', config.protect or None, sss.ShamirSharedSecretPrivate
  )
  secret_int: int = _ParseInt(secret)
  for fname in glob.glob(base_path + '.share.*'):  # noqa: PTH207
    share = _LoadObj(fname, config.protect or None, sss.ShamirSharePrivate)
    console.print(
      f'SSS share {fname!r} verification: '
      f'{"OK" if sss_priv.RawVerifyShare(secret_int, share) else "INVALID"}'
    )


@sss_app.command('shares')
@base.CLIErrorGuard
def SSSShares(
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Secret (bytes) to split, encoded per input format'),
  count: int = typer.Argument(..., help='How many shares to create'),
) -> None:
  """Create data shares for a byte secret."""
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


@sss_app.command('recover')
@base.CLIErrorGuard
def SSSRecover(*, ctx: typer.Context) -> None:
  """Recover a byte secret from shares."""  # noqa: DOC501
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
  epilog='Example:\n\n\n\n$ poetry run transcrypto markdown > transcrypto.md\n\n<<saves CLI doc>>',
)
@base.CLIErrorGuard
def Markdown() -> None:
  # leave this docstring without args/return/raise sections as it shows up in `--help`
  # one way or another the args are well documented in the CLI help and in the code above
  """Emit Markdown docs for the CLI (see README.md section "Creating a New Version")."""
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


def Run() -> None:
  """Run the CLI."""
  app()
