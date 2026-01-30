# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto CLI: Integer mathematics commands."""

from __future__ import annotations

import typer

from transcrypto import transcrypto
from transcrypto.cli import clibase
from transcrypto.core import modmath
from transcrypto.utils import base, saferandom

# =============================== "PRIME"-like COMMANDS ============================================


@transcrypto.app.command(
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
@clibase.CLIErrorGuard
def IsPrimeCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  n: str = typer.Argument(..., help='Integer to test, ≥ 1'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  n_i: int = transcrypto.ParseInt(n, min_value=1)
  config.console.print(str(modmath.IsPrime(n_i)))


@transcrypto.app.command(
  'primegen',
  help='Generate (stream) primes ≥ `start` (prints a limited `count` by default).',
  epilog=('Example:\n\n\n\n$ poetry run transcrypto primegen 100 -c 3\n\n101\n\n103\n\n107'),
)
@clibase.CLIErrorGuard
def PrimeGenCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  start: str = typer.Argument(..., help='Starting integer (inclusive), ≥ 0'),
  count: int = typer.Option(1, '-c', '--count', min=1, help='How many to print, ≥ 1'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  start_i: int = transcrypto.ParseInt(start, min_value=0)
  for i, pr in enumerate(modmath.PrimeGenerator(start_i)):
    if i >= count:
      return
    config.console.print(pr)


@transcrypto.app.command(
  'mersenne',
  help=(
    'Generate (stream) Mersenne prime exponents `k`, also outputting `2^k-1` '
    '(the Mersenne prime, `M`) and `M×2^(k-1)` (the associated perfect number), '  # noqa: RUF001
    'starting at `min-k` and stopping once `k` > `max-k`.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mersenne -k 0 -m 15\n\n'
    'k=2  M=3  perfect=6\n\n'
    'k=3  M=7  perfect=28\n\n'
    'k=5  M=31  perfect=496\n\n'
    'k=7  M=127  perfect=8128\n\n'
    'k=13  M=8191  perfect=33550336\n\n'
    'k=17  M=131071  perfect=8589869056'
  ),
)
@clibase.CLIErrorGuard
def MersenneCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  min_k: int = typer.Option(2, '-k', '--min-k', min=1, help='Starting exponent `k`, ≥ 2'),
  max_k: int = typer.Option(10000, '-m', '--max-k', min=1, help='Stop once `k` > `max-k`, ≥ 2'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  if max_k < min_k:
    raise base.InputError(f'max-k ({max_k}) must be >= min-k ({min_k})')
  for k, m, perfect in modmath.MersennePrimesGenerator(min_k):
    if k > max_k:
      return
    config.console.print(f'k={k}  M={m}  perfect={perfect}')


# ================================== "*GCD" COMMANDS ===============================================


@transcrypto.app.command(
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
@clibase.CLIErrorGuard
def GcdCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer, ≥ 0'),
  b: str = typer.Argument(..., help="Integer, ≥ 0 (can't be both zero)"),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  a_i: int = transcrypto.ParseInt(a, min_value=0)
  b_i: int = transcrypto.ParseInt(b, min_value=0)
  if a_i == 0 and b_i == 0:
    raise base.InputError("`a` and `b` can't both be zero")
  config.console.print(modmath.GCD(a_i, b_i))


@transcrypto.app.command(
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
@clibase.CLIErrorGuard
def XgcdCLI(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer, ≥ 0'),
  b: str = typer.Argument(..., help="Integer, ≥ 0 (can't be both zero)"),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  a_i: int = transcrypto.ParseInt(a, min_value=0)
  b_i: int = transcrypto.ParseInt(b, min_value=0)
  if a_i == 0 and b_i == 0:
    raise base.InputError("`a` and `b` can't both be zero")
  config.console.print(str(modmath.ExtendedGCD(a_i, b_i)))


# ================================= "RANDOM" COMMAND ===============================================


random_app = typer.Typer(
  no_args_is_help=True,
  help='Cryptographically secure randomness, from the OS CSPRNG.',
)
transcrypto.app.add_typer(random_app, name='random')


@random_app.command(
  'bits',
  help='Random integer with exact bit length = `bits` (MSB will be 1).',
  epilog=('Example:\n\n\n\n$ poetry run transcrypto random bits 16\n\n36650'),
)
@clibase.CLIErrorGuard
def RandomBits(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  bits: int = typer.Argument(..., min=8, help='Number of bits, ≥ 8'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  config.console.print(saferandom.RandBits(bits))


@random_app.command(
  'int',
  help='Uniform random integer in `[min, max]` range, inclusive.',
  epilog=('Example:\n\n\n\n$ poetry run transcrypto random int 1000 2000\n\n1628'),
)
@clibase.CLIErrorGuard
def RandomInt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  min_: str = typer.Argument(..., help='Minimum, ≥ 0'),
  max_: str = typer.Argument(..., help='Maximum, > `min`'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  min_i: int = transcrypto.ParseInt(min_, min_value=0)
  max_i: int = transcrypto.ParseInt(max_, min_value=min_i + 1)
  config.console.print(saferandom.RandInt(min_i, max_i))


@random_app.command(
  'bytes',
  help='Generates `n` cryptographically secure random bytes.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto random bytes 32\n\n'
    '6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f'
  ),
)
@clibase.CLIErrorGuard
def RandomBytes(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  n: int = typer.Argument(..., min=1, help='Number of bytes, ≥ 1'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  config.console.print(transcrypto.BytesToText(saferandom.RandBytes(n), config.output_format))


@random_app.command(
  'prime',
  help='Generate a random prime with exact bit length = `bits` (MSB will be 1).',
  epilog=('Example:\n\n\n\n$ poetry run transcrypto random prime 32\n\n2365910551'),
)
@clibase.CLIErrorGuard
def RandomPrime(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  bits: int = typer.Argument(..., min=11, help='Bit length, ≥ 11'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  config.console.print(modmath.NBitRandomPrimes(bits).pop())


# =================================== "MOD" COMMAND ================================================


mod_app = typer.Typer(
  no_args_is_help=True,
  help='Modular arithmetic helpers.',
)
transcrypto.app.add_typer(mod_app, name='mod')


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
@clibase.CLIErrorGuard
def ModInv(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer to invert'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  a_i: int = transcrypto.ParseInt(a)
  m_i: int = transcrypto.ParseInt(m, min_value=2)
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
    '<<INVALID>> divide-by-zero or not invertible (ModularDivideError)'
  ),
)
@clibase.CLIErrorGuard
def ModDiv(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  x: str = typer.Argument(..., help='Integer'),
  y: str = typer.Argument(..., help='Integer, cannot be zero'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  x_i: int = transcrypto.ParseInt(x)
  y_i: int = transcrypto.ParseInt(y)
  m_i: int = transcrypto.ParseInt(m, min_value=2)
  try:
    config.console.print(modmath.ModDiv(x_i, y_i, m_i))
  except modmath.ModularDivideError:
    config.console.print('<<INVALID>> divide-by-zero or not invertible (ModularDivideError)')


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
@clibase.CLIErrorGuard
def ModExp(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a: str = typer.Argument(..., help='Integer value'),
  e: str = typer.Argument(..., help='Integer exponent, ≥ 0'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  a_i: int = transcrypto.ParseInt(a)
  e_i: int = transcrypto.ParseInt(e, min_value=0)
  m_i: int = transcrypto.ParseInt(m, min_value=2)
  config.console.print(modmath.ModExp(a_i, e_i, m_i))


@mod_app.command(
  'poly',
  help=(
    'Efficiently evaluate polynomial with `coeff` coefficients at point `x` modulo `m` '
    '(`c₀+c₁×x+c₂×x²+…+cₙ×x^n mod m`).'  # noqa: RUF001
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto mod poly 12 17 10 20 30\n\n'
    '14  # (10+20×12+30×12² ≡ 14 (mod 17))\n\n'  # noqa: RUF001
    '$ poetry run transcrypto mod poly 10 97 3 0 0 1 1\n\n'
    '42  # (3+1×10³+1×10⁴ ≡ 42 (mod 97))'  # noqa: RUF001
  ),
)
@clibase.CLIErrorGuard
def ModPoly(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  x: str = typer.Argument(..., help='Evaluation point `x`'),
  m: str = typer.Argument(..., help='Modulus `m`, ≥ 2'),
  coeff: list[str] = typer.Argument(  # noqa: B008
    ...,
    help='Coefficients (constant-term first: `c₀+c₁×x+c₂×x²+…+cₙ×x^n`)',  # noqa: RUF001
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  x_i: int = transcrypto.ParseInt(x)
  m_i: int = transcrypto.ParseInt(m, min_value=2)
  coeff_i: list[int] = [transcrypto.ParseInt(z) for z in coeff]
  config.console.print(modmath.ModPolynomial(x_i, coeff_i, m_i))


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
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  x_i: int = transcrypto.ParseInt(x)
  m_i: int = transcrypto.ParseInt(m, min_value=2)
  pts: dict[int, int] = dict(transcrypto.ParseIntPairCLI(kv) for kv in pt)
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
@clibase.CLIErrorGuard
def ModCRT(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  a1: str = typer.Argument(..., help='Integer residue for first congruence'),
  m1: str = typer.Argument(..., help='Modulus `m1`, ≥ 2'),
  a2: str = typer.Argument(..., help='Integer residue for second congruence'),
  m2: str = typer.Argument(..., help='Modulus `m2`, ≥ 2, !=`m1`, and `gcd(m1,m2)==1`'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  a1_i: int = transcrypto.ParseInt(a1)
  m1_i: int = transcrypto.ParseInt(m1, min_value=2)
  a2_i: int = transcrypto.ParseInt(a2)
  m2_i: int = transcrypto.ParseInt(m2, min_value=2)
  try:
    config.console.print(modmath.CRTPair(a1_i, m1_i, a2_i, m2_i))
  except modmath.ModularDivideError:
    config.console.print('<<INVALID>> moduli `m1`/`m2` not co-prime (ModularDivideError)')
