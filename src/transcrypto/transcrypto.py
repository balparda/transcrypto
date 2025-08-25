#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto command line interface.

See README.md for documentation on how to use.

Notes on the layout (quick mental model):

isprime, mr, randomprime, primegen, mersenne
gcd, xgcd, and grouped mod inv|div|exp|poly|lagrange|crt
rand bits|int|bytes, hash sha256|sha512|file
aes key frompass, aes encrypt|decrypt (GCM), aes ecb encrypthex|decrypthex
rsa new|encrypt|decrypt|sign|verify (integer messages)
elgamal shared|new|encrypt|decrypt|sign|verify
dsa shared|new|sign|verify
sss new|shares|recover|verify
"""

from __future__ import annotations

import argparse
import enum
import logging
# import pdb
import sys
from typing import Any, Iterable, Sequence

from . import base, modmath, rsa, sss, elgamal, dsa, aes

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


def _ParseInt(s: str) -> int:
  """Parse int, try to determine if binary, octal, decimal, or hexadecimal."""
  s = s.strip().lower().replace('_', '')
  base_guess = 10
  if s.startswith('0x'):
    base_guess = 16
  elif s.startswith('0b'):
    base_guess = 2
  elif s.startswith('0o'):
    base_guess = 8
  return int(s, base_guess)


def _ParseIntList(items: Iterable[str]) -> list[int]:
  """Parse list of strings into list of ints."""
  return [_ParseInt(x) for x in items]


class _StrBytesType(enum.Enum):
  """Type of bytes encoded as string."""
  RAW = 0
  HEXADECIMAL = 1
  BASE64 = 2

  @staticmethod
  def FromFlags(is_hex: bool, is_base64: bool, is_bin: bool) -> _StrBytesType:
    """Use flags to determine the type."""
    if sum((is_hex, is_base64, is_bin)) > 1:
      raise base.InputError('Only one of --hex, --b64, --bin can be set, if any.')
    if is_bin:
      return _StrBytesType.RAW
    if is_base64:
      return _StrBytesType.BASE64
    return _StrBytesType.HEXADECIMAL  # default


def _BytesFromText(text: str, tp: _StrBytesType) -> bytes:
  """Parse bytes as hex, base64, or raw."""
  match tp:
    case _StrBytesType.RAW:
      return text.encode('utf-8')
    case _StrBytesType.HEXADECIMAL:
      return base.HexToBytes(text)
    case _StrBytesType.BASE64:
      return base.EncodedToBytes(text)


def _BytesToText(b: bytes, tp: _StrBytesType) -> str:
  """Output bytes as hex, base64, or raw."""
  match tp:
    case _StrBytesType.RAW:
      return b.decode('utf-8', errors='replace')
    case _StrBytesType.HEXADECIMAL:
      return base.BytesToHex(b)
    case _StrBytesType.BASE64:
      return base.BytesToEncoded(b)


def _MaybePasswordKey(password: str | None) -> aes.AESKey | None:
  """Generate a key if there is a password."""
  return aes.AESKey.FromStaticPassword(password) if password else None


def _SaveObj(obj: Any, path: str, password: str | None) -> None:
  """Save object."""
  key: aes.AESKey | None = _MaybePasswordKey(password)
  blob: bytes = base.Serialize(obj, file_path=path, key=key)
  logging.info('saved object: %s (%s)', path, base.HumanizedBytes(len(blob)))


def _LoadObj(path: str, password: str | None) -> Any:
  """Load object."""
  key: aes.AESKey | None = _MaybePasswordKey(password)
  return base.DeSerialize(file_path=path, key=key)


def _FlagNames(a: argparse.Action) -> list[str]:
  # Positional args have empty 'option_strings'; otherwise use them (e.g., ['-v','--verbose'])
  if a.option_strings:
    return list(a.option_strings)
  if a.nargs:
    if isinstance(a.metavar, str) and a.metavar:
      # e.g., nargs=2, metavar='FILE'
      return [a.metavar]
    if isinstance(a.metavar, tuple):
      # e.g., nargs=2, metavar=('FILE1', 'FILE2')
      return list(a.metavar)
  # Otherwise, it’s a positional arg with no flags, so return the destination name
  return [a.dest]


def _ActionIsSubparser(a: argparse.Action) -> bool:
  return isinstance(a, argparse._SubParsersAction)  # type: ignore[attr-defined]  # pylint: disable=protected-access


def _FormatDefault(a: argparse.Action) -> str:
  if a.default is argparse.SUPPRESS:
    return ''
  if isinstance(a.default, bool):
    return ' (default: on)' if a.default else ''
  if a.default in (None, '', 0, False):
    return ''
  return f' (default: {a.default})'


def _FormatChoices(a: argparse.Action) -> str:
  return f' choices: {list(a.choices)}' if getattr(a, 'choices', None) else ''  # type:ignore


def _FormatType(a: argparse.Action) -> str:
  t: Any | None = getattr(a, 'type', None)
  if t is None:
    return ''
  # Show clean type names (int, str, float); for callables, just say 'custom'
  return f' type: {t.__name__ if hasattr(t, "__name__") else "custom"}'


def _FormatNArgs(a: argparse.Action) -> str:
  return f' nargs: {a.nargs}' if getattr(a, 'nargs', None) not in (None, 0) else ''


def _RowsForActions(actions: Sequence[argparse.Action]) -> list[tuple[str, str]]:
  rows: list[tuple[str, str]] = []
  for a in actions:
    if _ActionIsSubparser(a):
      continue
    # skip the built-in help action; it’s implied
    if getattr(a, 'help', '') == argparse.SUPPRESS or isinstance(a, argparse._HelpAction):  # type: ignore[attr-defined]  # pylint: disable=protected-access
      continue
    flags: str = ', '.join(_FlagNames(a))
    meta: str = ''.join(
        (_FormatType(a), _FormatNArgs(a), _FormatChoices(a), _FormatDefault(a))).strip()
    desc: str = (a.help or '').strip()
    if meta:
      desc = f'{desc} [{meta}]' if desc else f'[{meta}]'
    rows.append((flags, desc))
  return rows


def _MarkdownTable(
    rows: Sequence[tuple[str, str]],
    headers: tuple[str, str] = ('Option/Arg', 'Description')) -> str:
  if not rows:
    return ''
  out: list[str] = ['| ' + headers[0] + ' | ' + headers[1] + ' |', '|---|---|']
  for left, right in rows:
    out.append(f'| `{left}` | {right} |')
  return '\n'.join(out)


def _WalkSubcommands(
    parser: argparse.ArgumentParser, path: list[str] | None = None) -> list[
    tuple[list[str], argparse.ArgumentParser, Any]]:
  path = path or []
  items: list[tuple[list[str], argparse.ArgumentParser, Any]] = []
  # sub_action = None
  name: str
  sp: argparse.ArgumentParser
  for action in parser._actions:  # type: ignore[attr-defined]  # pylint: disable=protected-access
    if _ActionIsSubparser(action):
      # sub_action = a  # type: ignore[assignment]
      for name, sp in action.choices.items():              # type:ignore
        items.append((path + [name], sp, action))          # type:ignore
        items.extend(_WalkSubcommands(sp, path + [name]))  # type:ignore
  return items


def _HelpText(sub_parser: argparse.ArgumentParser, parent_sub_action: Any) -> str:
  if parent_sub_action is not None:
    for choice_action in parent_sub_action._choices_actions:  # type: ignore  # pylint: disable=protected-access
      if choice_action.dest == sub_parser.prog.split()[-1]:
        return choice_action.help or ''
  return ''


def _GenerateCLIMarkdown() -> str:  # pylint: disable=too-many-locals
  """Return a Markdown doc section that reflects the current _BuildParser() tree.

  Will treat epilog strings as examples, splitting on '$$' to get multiple examples.
  """
  parser: argparse.ArgumentParser = _BuildParser()
  assert parser.prog == 'poetry run transcrypto', 'should never happen: module name changed?'
  prog: str = 'transcrypto'  # no '.py' needed because poetry run has an alias
  lines: list[str] = ['']
  # Header + global flags
  lines.append('## Command-Line Interface\n')
  lines.append(
      f'`{prog}` is a command-line utility that provides access to all core functionality '
      'described in this documentation. It serves as a convenient wrapper over the Python APIs, '
      'enabling **cryptographic operations**, **number theory functions**, **secure randomness '
      'generation**, **hashing**, and other utilities without writing code.\n')
  lines.append('Invoke with:\n')
  lines.append('```bash')
  lines.append(f'poetry run {prog} <command> [sub-command] [options...]')
  lines.append('```\n')
  # Global options table
  global_rows: list[tuple[str, str]] = _RowsForActions(parser._actions)  # type: ignore[attr-defined]  # pylint: disable=protected-access
  if global_rows:
    lines.append('### Global Options\n')
    lines.append(_MarkdownTable(global_rows))
    lines.append('')
  # Top-level commands summary
  lines.append('### Top-Level Commands\n')
  # Find top-level subparsers to list available commands
  top_subs: list[argparse.Action] = [a for a in parser._actions if _ActionIsSubparser(a)]  # type: ignore[attr-defined]  # pylint: disable=protected-access
  for action in top_subs:
    for name, sp in action.choices.items():  # type: ignore[union-attr]
      help_text: str = (sp.description or sp.format_usage().splitlines()[0]).strip()  # type:ignore
      short: str = (sp.help if hasattr(sp, 'help') else '') or ''                     # type:ignore
      help_text = short or help_text                                                  # type:ignore
      help_text = help_text.replace('usage: ', '').strip()  # type:ignore
      lines.append(f'- **`{name}`** — `{help_text}`')
  lines.append('')
  # Detailed sections per (sub)command
  for path, sub_parser, parent_sub_action in _WalkSubcommands(parser):
    if len(path) == 1:
      lines.append('---\n')  # horizontal rule between top-level commands
    header: str = ' '.join(path)
    lines.append(f'###{"" if len(path) == 1 else "#"} `{header}`')  # (header level 3 or 4)
    # Usage block
    help_text = _HelpText(sub_parser, parent_sub_action)
    if help_text:
      lines.append(f'\n{help_text}')
    usage: str = sub_parser.format_usage().replace('usage: ', '').strip()
    lines.append('\n```bash')
    lines.append(str(usage))
    lines.append('```\n')
    # Options/args table
    rows: list[tuple[str, str]] = _RowsForActions(sub_parser._actions)  # type: ignore[attr-defined]  # pylint: disable=protected-access
    if rows:
      lines.append(_MarkdownTable(rows))
      lines.append('')
    # Examples (if any) - stored in epilog argument
    epilog: str = sub_parser.epilog.strip() if sub_parser.epilog else ''
    if epilog:
      lines.append('**Example:**\n')
      lines.append('```bash')
      for epilog_line in epilog.split('$$'):
        lines.append(f'$ poetry run {prog} {epilog_line.strip()}')
      lines.append('```\n')
  # join all lines as the markdown string
  return '\n'.join(lines)


def _BuildParser() -> argparse.ArgumentParser:  # pylint: disable=too-many-statements,too-many-locals
  """Construct the CLI argument parser (kept in sync with the docs)."""
  # ========================= main parser ==========================================================
  parser: argparse.ArgumentParser = argparse.ArgumentParser(
      prog='poetry run transcrypto',
      description=('transcrypto: CLI for number theory, hashing, '
                   'AES, RSA, ElGamal, DSA, SSS, and utilities.'),
      epilog=(
          'Examples:\n'
          '  poetry run transcrypto isprime 428568761\n'
          '  poetry run transcrypto rsa new 2048 --out rsa.priv --protect hunter2\n'
          '  poetry run transcrypto aes key frompass "correct horse" --print-b64\n'
          '  poetry run transcrypto aes encrypt "secret" -k "<b64key>" -a "aad" --out-b64\n'
          '  poetry run transcrypto mod inv 17 97\n'
          '  poetry run transcrypto sss new 3 128 --out /tmp/sss\n'
      ),
      formatter_class=argparse.RawTextHelpFormatter)
  sub = parser.add_subparsers(dest='command')

  # ========================= global flags =========================================================
  # -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG
  parser.add_argument(
      '-v', '--verbose', action='count', default=0,
      help='Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG)')
  # --hex/--b64/--bin for input mode (default hex)
  in_grp = parser.add_mutually_exclusive_group()
  in_grp.add_argument('--hex', action='store_true', help='Treat inputs as hex string (default)')
  in_grp.add_argument('--b64', action='store_true', help='Treat inputs as base64url')
  in_grp.add_argument('--bin', action='store_true', help='Treat inputs as binary (bytes)')
  # --out-hex/--out-b64/--out-bin for output mode (default hex)
  out_grp = parser.add_mutually_exclusive_group()
  out_grp.add_argument('--out-hex', action='store_true', help='Outputs as hex (default)')
  out_grp.add_argument('--out-b64', action='store_true', help='Outputs as base64url')
  out_grp.add_argument('--out-bin', action='store_true', help='Outputs as binary (bytes)')

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

  # Random integer in [min, max]
  p_rand_int: argparse.ArgumentParser = rsub.add_parser(
      'int',
      help='Uniform random integer in `[min, max]` range, inclusive.',
      epilog='random int 1000 2000\n1628')
  p_rand_int.add_argument('min', type=str, help='Minimum, ≥ 0')
  p_rand_int.add_argument('max', type=str, help='Maximum, > `min`')

  # Random bytes
  p_rand_bytes: argparse.ArgumentParser = rsub.add_parser(
      'bytes',
      help='Generates `n` cryptographically secure random bytes.',
      epilog='random bytes 32\n6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f')
  p_rand_bytes.add_argument('n', type=int, help='Number of bytes, ≥ 1')

  # Random prime with given bit length
  p_rand_prime: argparse.ArgumentParser = rsub.add_parser(
      'prime',
      help='Generate a random prime with exact bit length = `bits` (MSB will be 1).',
      epilog='random prime 32\n2365910551')
  p_rand_prime.add_argument('bits', type=int, help='Bit length, ≥ 11')

  # ========================= primes ===============================================================

  # Primality test with safe defaults
  p_isprime: argparse.ArgumentParser = sub.add_parser(
      'isprime',
      help='Primality test with safe defaults, useful for any integer size.',
      epilog='isprime 2305843009213693951\nTrue $$ isprime 2305843009213693953\nFalse')
  p_isprime.add_argument(
      'n', type=str, help='Integer to test, ≥ 1')

  # Primes generator
  p_pg: argparse.ArgumentParser = sub.add_parser(
      'primegen',
      help='Generate (stream) primes ≥ `start` (prints a limited `count` by default).',
      epilog='primegen 100 -c 3\n101\n103\n107')
  p_pg.add_argument('start', type=str, help='Starting integer (inclusive)')
  p_pg.add_argument(
      '-c', '--count', type=int, default=10, help='How many to print (0 = unlimited)')

  # Mersenne primes generator
  p_mersenne: argparse.ArgumentParser = sub.add_parser(
      'mersenne',
      help=('Generate (stream) Mersenne prime exponents `k`, also outputting `2^k-1` '
            '(the Mersenne prime, `M`) and `M×2^(k-1)` (the associated perfect number), '
            'starting at `min-k` and stopping once `k` > `cutoff-k`.'),
      epilog=('mersenne -k 0 -C 15\nk=2  M=3  perfect=6\nk=3  M=7  perfect=28\n'
              'k=5  M=31  perfect=496\nk=7  M=127  perfect=8128\n'
              'k=13  M=8191  perfect=33550336\nk=17  M=131071  perfect=8589869056'))
  p_mersenne.add_argument(
      '-k', '--min-k', type=int, default=1, help='Starting exponent `k`, ≥ 1')
  p_mersenne.add_argument(
      '-C', '--cutoff-k', type=int, default=10000, help='Stop once `k` > `cutoff-k`')

  # ========================= integer / modular math ===============================================

  # GCD
  p_gcd: argparse.ArgumentParser = sub.add_parser(
      'gcd',
      help='Greatest Common Divisor (GCD) of integers `a` and `b`.',
      epilog='gcd 462 1071\n21 $$ gcd 0 5\n5 $$ gcd 127 13\n1')
  p_gcd.add_argument('a', type=str, help='Integer, ≥ 0')
  p_gcd.add_argument('b', type=str, help='Integer, ≥ 0 (can\'t be both zero)')

  # Extended GCD
  p_xgcd: argparse.ArgumentParser = sub.add_parser(
      'xgcd',
      help=('Extended Greatest Common Divisor (x-GCD) of integers `a` and `b`, '
            'will return `(g, x, y)` where `a×x+b×y==g`.'),
      epilog='xgcd 462 1071\n(21, 7, -3) $$ gcd 0 5\n(5, 0, 1) $$ xgcd 127 13\n(1, 4, -39)')
  p_xgcd.add_argument('a', type=str, help='Integer, ≥ 0')
  p_xgcd.add_argument('b', type=str, help='Integer, ≥ 0 (can\'t be both zero)')

  # Modular math group
  p_mod: argparse.ArgumentParser = sub.add_parser('mod', help='Modular arithmetic helpers.')
  mod_sub = p_mod.add_subparsers(dest='mod_command')

  # Modular inverse
  p_mi: argparse.ArgumentParser = mod_sub.add_parser(
      'inv',
      help=('Modular inverse: find integer 0≤`i`<`m` such that `a×i ≡ 1 (mod m)`. '
            'Will only work if `gcd(a,m)==1`, else will fail with a message.'),
      epilog=('mod inv 127 13\n4 $$ mod inv 17 3120\n2753  $$ '
              'mod inv 462 1071\n<<INVALID>> no modular inverse exists (ModularDivideError)'))
  p_mi.add_argument('a', type=str, help='Integer to invert')
  p_mi.add_argument('m', type=str, help='Modulus `m`, ≥ 2')

  # Modular division
  p_md: argparse.ArgumentParser = mod_sub.add_parser(
      'div',
      help=('Modular division: find integer 0≤`z`<`m` such that `z×y ≡ x (mod m)`. '
            'Will only work if `gcd(y,m)==1` and `y!=0`, else will fail with a message.'),
      epilog=('mod div 6 127 13\n11 $$ '
              'mod div 6 0 13\n<<INVALID>> no modular inverse exists (ModularDivideError)'))
  p_md.add_argument('x', type=str, help='Integer')
  p_md.add_argument('y', type=str, help='Integer, cannot be zero')
  p_md.add_argument('m', type=str, help='Modulus `m`, ≥ 2')

  # Modular exponentiation
  p_me: argparse.ArgumentParser = mod_sub.add_parser(
      'exp',
      help='Modular exponentiation: `a^e mod m`. Efficient, can handle huge values.',
      epilog='mod exp 438 234 127\n32 $$ mod exp 438 234 89854\n60622')
  p_me.add_argument('a', type=str, help='Integer')
  p_me.add_argument('e', type=str, help='Integer, ≥ 0')
  p_me.add_argument('m', type=str, help='Modulus `m`, ≥ 2')

  # Polynomial evaluation mod m
  p_mp: argparse.ArgumentParser = mod_sub.add_parser(
      'poly',
      help=('Efficiently evaluate polynomial with `coeff` coefficients at point `x` modulo `m` '
            '(`c₀+c₁×x+c₂×x²+…+cₙ×xⁿ mod m`).'),
      epilog=('mod poly 12 17 10 20 30\n14  # (10+20×12+30×12² ≡ 14 (mod 17)) $$ '
              'mod poly 10 97 3 0 0 1 1\n42  # (3+1×10³+1×10⁴ ≡ 42 (mod 97))'))
  p_mp.add_argument('x', type=str, help='Evaluation point `x`')
  p_mp.add_argument('m', type=str, help='Modulus `m`, ≥ 2')
  p_mp.add_argument(
      'coeff', nargs='+', help='Coefficients (constant-term first: `c₀+c₁×x+c₂×x²+…+cₙ×xⁿ`)')

  # Lagrange interpolation mod m
  p_ml: argparse.ArgumentParser = mod_sub.add_parser(
      'lagrange',
      help=('Lagrange interpolation over modulus `m`: find the `f(x)` solution for the '
            'given `x` and `zₙ:f(zₙ)` points `pt`. The modulus `m` must be a prime.'),
      epilog=('mod lagrange 5 13 2:4 6:3 7:1\n3  # passes through (2,4), (6,3), (7,1) $$ '
              'mod lagrange 11 97 1:1 2:4 3:9 4:16 5:25\n24  '
              '# passes through (1,1), (2,4), (3,9), (4,16), (5,25)'))
  p_ml.add_argument('x', type=str, help='Evaluation point `x`')
  p_ml.add_argument('m', type=str, help='Modulus `m`, ≥ 2')
  p_ml.add_argument(
      'pt', nargs='+', help='Points `zₙ:f(zₙ)` as `key:value` pairs (e.g., `2:4 5:3 7:1`)')

  # Chinese Remainder Theorem for 2 equations
  p_crt: argparse.ArgumentParser = mod_sub.add_parser(
      'crt',
      help=('Solves Chinese Remainder Theorem (CRT) Pair: finds the unique integer 0≤`x`<`(m1×m2)` '
            'satisfying both `x ≡ a1 (mod m1)` and `x ≡ a2 (mod m2)`, if `gcd(m1,m2)==1`.'),
      epilog=('mod crt 6 7 127 13\n62 $$ mod crt 12 56 17 19\n796 $$ '
              'mod crt 6 7 462 1071\n<<INVALID>> moduli m1/m2 not co-prime (ModularDivideError)'))
  p_crt.add_argument('a1', type=str, help='Integer residue for first congruence')
  p_crt.add_argument('m1', type=str, help='Modulus `m1`, ≥ 2 and `gcd(m1,m2)==1`')
  p_crt.add_argument('a2', type=str, help='Integer residue for second congruence')
  p_crt.add_argument('m2', type=str, help='Modulus `m2`, ≥ 2 and `gcd(m1,m2)==1`')

  # ========================= hashing ==============================================================

  # Hashing group
  p_hash: argparse.ArgumentParser = sub.add_parser(
      'hash', help='Cryptographic Hashing (SHA-256 / SHA-512 / file).')
  hash_sub = p_hash.add_subparsers(dest='hash_command')

  # SHA-256
  p_h256: argparse.ArgumentParser = hash_sub.add_parser(
      'sha256',
      help='SHA-256 of input `data`.',
      epilog=('--bin hash sha256 xyz\n'
              '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282 $$'
              '--b64 hash sha256 eHl6  # "xyz" in base-64\n'
              '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282'))
  p_h256.add_argument('data', type=str, help='Input data (raw text; or use --hex/--b64/--bin)')

  # SHA-512
  p_h512 = hash_sub.add_parser(
      'sha512',
      help='SHA-512 of input `data`.',
      epilog=('--bin hash sha256 xyz\n'
              '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
              '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728 $$'
              '--b64 hash sha256 eHl6  # "xyz" in base-64\n'
              '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
              '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728'))
  p_h512.add_argument('data', type=str, help='Input data (raw text; or use --hex/--b64/--bin)')

  # Hash file contents (streamed)
  p_hf: argparse.ArgumentParser = hash_sub.add_parser(
      'file',
      help='SHA-256/512 hash of file contents, defaulting to SHA-256.',
      epilog=('hash file /etc/passwd --digest sha512\n'
              '8966f5953e79f55dfe34d3dc5b160ac4a4a3f9cbd1c36695a54e28d77c7874df'
              'f8595502f8a420608911b87d336d9e83c890f0e7ec11a76cb10b03e757f78aea'))
  p_hf.add_argument('path', type=str, help='Path to existing file')
  p_hf.add_argument('--digest', choices=['sha256', 'sha512'], default='sha256',
                    help='Digest type, SHA-256 ("sha256") or SHA-512 ("sha512")')

  # ========================= AES (GCM + ECB helper) ===============================================

  # AES group
  p_aes: argparse.ArgumentParser = sub.add_parser(
      'aes', help='AES-256 operations (GCM/ECB) and key derivation.')
  aes_sub = p_aes.add_subparsers(dest='aes_command')

  # Derive key from password
  p_aes_key_pass: argparse.ArgumentParser = aes_sub.add_parser(
      'key',
      help=('Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive '
            'salt and iterations. Very good/safe for simple password-to-key but not for '
            'passwords databases (because of constant salt).'),
      epilog=('--out-b64 aes key "correct horse battery staple"\n'
              'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= $$ '  # cspell:disable-line
              'aes key "correct horse battery staple" --out keyfile.out --protect hunter\n$'))
  p_aes_key_pass.add_argument(
      'password', type=str, help='Password (leading/trailing spaces ignored)')
  p_aes_key_pass.add_argument('--out', type=str, default='', help='Save serialized AESKey to path')
  p_aes_key_pass.add_argument(
      '--protect', type=str, default='', help='Password to encrypt the saved key file (Serialize)')

  # AES-256-GCM encrypt
  p_aes_enc: argparse.ArgumentParser = aes_sub.add_parser(
      'encrypt', help='AES-256-GCM: encrypt (outputs IV||ct||tag).')
  p_aes_enc.add_argument('plaintext', type=str, help='Input data (raw; or use --in-hex/--in-b64)')
  p_aes_enc.add_argument(
      '-k', '--key-b64', type=str, default='', help='Key as base64url (32 bytes)')
  p_aes_enc.add_argument(
      '-p', '--key-path', type=str, default='', help='Path to serialized AESKey')
  p_aes_enc.add_argument('-a', '--aad', type=str, default='', help='Associated data (optional)')
  p_aes_enc.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if using --key-path')

  # AES-256-GCM decrypt
  p_aes_dec: argparse.ArgumentParser = aes_sub.add_parser(
      'decrypt', help='AES-256-GCM: decrypt IV||ct||tag.')
  p_aes_dec.add_argument('ciphertext', type=str, help='Input blob (use --in-hex/--in-b64)')
  p_aes_dec.add_argument(
      '-k', '--key-b64', type=str, default='', help='Key as base64url (32 bytes)')
  p_aes_dec.add_argument(
      '-p', '--key-path', type=str, default='', help='Path to serialized AESKey')
  p_aes_dec.add_argument('-a', '--aad', type=str, default='', help='Associated data (must match)')
  p_aes_dec.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if using --key-path')

  # AES-ECB
  p_aes_ecb: argparse.ArgumentParser = aes_sub.add_parser(
      'ecb', help='AES-ECB (unsafe; fixed 16-byte blocks only).')
  p_aes_ecb.add_argument(
      '-k', '--key-b64', type=str, default='', help='Key as base64url (32 bytes)')
  p_aes_ecb.add_argument(
      '-p', '--key-path', type=str, default='', help='Path to serialized AESKey')
  p_aes_ecb.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if using --key-path')
  aes_ecb_sub = p_aes_ecb.add_subparsers(dest='aes_ecb_command')

  # AES-ECB encrypt 16-byte hex block
  p_aes_ecb_e: argparse.ArgumentParser = aes_ecb_sub.add_parser(
      'encrypthex', help='Encrypt 16-byte hex block with AES-ECB.')
  p_aes_ecb_e.add_argument('block_hex', type=str, help='Plaintext block as 32 hex chars')

  # AES-ECB decrypt 16-byte hex block
  p_aes_scb_d: argparse.ArgumentParser = aes_ecb_sub.add_parser(
      'decrypthex', help='Decrypt 16-byte hex block with AES-ECB.')
  p_aes_scb_d.add_argument('block_hex', type=str, help='Ciphertext block as 32 hex chars')

  # ========================= RSA ==================================================================

  # RSA group
  p_rsa: argparse.ArgumentParser = sub.add_parser('rsa', help='Raw RSA over integers (no OAEP/PSS).')
  rsa_sub = p_rsa.add_subparsers(dest='rsa_command')

  # Generate new RSA private key
  p_rsa_new: argparse.ArgumentParser = rsa_sub.add_parser('new', help='Generate RSA private key.')
  p_rsa_new.add_argument('bits', type=int, help='Modulus size in bits (e.g., 2048)')
  p_rsa_new.add_argument(
      '--out', type=str, default='', help='Save private key to path (Serialize)')
  p_rsa_new.add_argument(
      '--protect', type=str, default='', help='Password to encrypt saved key file')

  # Encrypt integer with public key
  p_rsa_enc: argparse.ArgumentParser = rsa_sub.add_parser(
      'encrypt', help='Encrypt integer with public key.')
  p_rsa_enc.add_argument('message', type=str, help='Integer message (e.g., "12345" or "0x...")')
  p_rsa_enc.add_argument(
      '--key', type=str, required=True, help='Path to private/public key (Serialize)')
  p_rsa_enc.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Decrypt integer ciphertext with private key
  p_rsa_dec: argparse.ArgumentParser = rsa_sub.add_parser(
      'decrypt', help='Decrypt integer ciphertext with private key.')
  p_rsa_dec.add_argument('ciphertext', type=str, help='Integer ciphertext')
  p_rsa_dec.add_argument('--key', type=str, required=True, help='Path to private key (Serialize)')
  p_rsa_dec.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Sign integer message with private key
  p_rsa_sig: argparse.ArgumentParser = rsa_sub.add_parser(
      'sign', help='Sign integer message with private key.')
  p_rsa_sig.add_argument('message', type=str, help='Integer message')
  p_rsa_sig.add_argument('--key', type=str, required=True, help='Path to private key (Serialize)')
  p_rsa_sig.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Verify integer signature with public key
  p_rsa_ver: argparse.ArgumentParser = rsa_sub.add_parser(
      'verify', help='Verify integer signature with public key.')
  p_rsa_ver.add_argument('message', type=str, help='Integer message')
  p_rsa_ver.add_argument('signature', type=str, help='Integer signature')
  p_rsa_ver.add_argument(
      '--key', type=str, required=True, help='Path to private/public key (Serialize)')
  p_rsa_ver.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # ========================= ElGamal ==============================================================

  # ElGamal group
  p_eg: argparse.ArgumentParser = sub.add_parser('elgamal', help='Raw El-Gamal (no padding).')
  eg_sub = p_eg.add_subparsers(dest='eg_command')

  # Generate shared (p,g) params
  p_eg_shared: argparse.ArgumentParser = eg_sub.add_parser(
      'shared', help='Generate shared parameters (p, g).')
  p_eg_shared.add_argument('bits', type=int, help='Bit length for prime modulus p')
  p_eg_shared.add_argument('--out', type=str, required=True, help='Save shared key to path')
  p_eg_shared.add_argument(
      '--protect', type=str, default='', help='Password to encrypt saved key file')

  # Generate individual private key from shared (p,g)
  p_eg_new: argparse.ArgumentParser = eg_sub.add_parser(
      'new', help='Generate individual private key from shared.')
  p_eg_new.add_argument('--shared', type=str, required=True, help='Path to shared (p,g)')
  p_eg_new.add_argument('--out', type=str, required=True, help='Save private key to path')
  p_eg_new.add_argument(
      '--protect', type=str, default='', help='Password to encrypt saved key file')

  # Encrypt integer with public key
  p_eg_enc: argparse.ArgumentParser = eg_sub.add_parser(
      'encrypt', help='Encrypt integer with public key.')
  p_eg_enc.add_argument('message', type=str, help='Integer message 1 ≤ m < p')
  p_eg_enc.add_argument('--key', type=str, required=True, help='Path to private/public key')
  p_eg_enc.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Decrypt El-Gamal ciphertext tuple (c1,c2)
  p_eg_dec: argparse.ArgumentParser = eg_sub.add_parser(
      'decrypt', help='Decrypt El-Gamal ciphertext tuple (c1,c2).')
  p_eg_dec.add_argument('c1', type=str)
  p_eg_dec.add_argument('c2', type=str)
  p_eg_dec.add_argument('--key', type=str, required=True, help='Path to private key')
  p_eg_dec.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Sign integer message with private key
  p_eg_sig: argparse.ArgumentParser = eg_sub.add_parser(
      'sign', help='Sign integer message with private key.')
  p_eg_sig.add_argument('message', type=str)
  p_eg_sig.add_argument('--key', type=str, required=True, help='Path to private key')
  p_eg_sig.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Verify El-Gamal signature (s1,s2)
  p_eg_ver: argparse.ArgumentParser = eg_sub.add_parser(
      'verify', help='Verify El-Gamal signature (s1,s2).')
  p_eg_ver.add_argument('message', type=str)
  p_eg_ver.add_argument('s1', type=str)
  p_eg_ver.add_argument('s2', type=str)
  p_eg_ver.add_argument('--key', type=str, required=True, help='Path to private/public key')
  p_eg_ver.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # ========================= DSA ==================================================================

  # DSA group
  p_dsa: argparse.ArgumentParser = sub.add_parser(
      'dsa', help='Raw DSA (no hash, integer messages < q).')
  dsa_sub = p_dsa.add_subparsers(dest='dsa_command')

  # Generate shared (p,q,g) params
  p_dsa_shared: argparse.ArgumentParser = dsa_sub.add_parser(
      'shared', help='Generate (p,q,g) with q | p-1.')
  p_dsa_shared.add_argument('p_bits', type=int, help='Bit length of p (≥ q_bits + 11)')
  p_dsa_shared.add_argument('q_bits', type=int, help='Bit length of q (≥ 11)')
  p_dsa_shared.add_argument('--out', type=str, required=True, help='Save shared params to path')
  p_dsa_shared.add_argument(
      '--protect', type=str, default='', help='Password to encrypt saved key file')

  # Generate individual private key from shared (p,q,g)
  p_dsa_new: argparse.ArgumentParser = dsa_sub.add_parser(
      'new', help='Generate DSA private key from shared.')
  p_dsa_new.add_argument('--shared', type=str, required=True, help='Path to shared (p,q,g)')
  p_dsa_new.add_argument('--out', type=str, required=True, help='Save private key to path')
  p_dsa_new.add_argument(
      '--protect', type=str, default='', help='Password to encrypt saved key file')

  # Sign integer m with private key
  p_dsa_sign: argparse.ArgumentParser = dsa_sub.add_parser(
      'sign', help='Sign integer m (1 ≤ m < q).')
  p_dsa_sign.add_argument('message', type=str)
  p_dsa_sign.add_argument('--key', type=str, required=True, help='Path to private key')
  p_dsa_sign.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Verify DSA signature (s1,s2)
  p_dsa_verify: argparse.ArgumentParser = dsa_sub.add_parser(
      'verify', help='Verify DSA signature (s1,s2).')
  p_dsa_verify.add_argument('message', type=str)
  p_dsa_verify.add_argument('s1', type=str)
  p_dsa_verify.add_argument('s2', type=str)
  p_dsa_verify.add_argument('--key', type=str, required=True, help='Path to private/public key')
  p_dsa_verify.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # ========================= Shamir Secret Sharing ================================================

  # SSS group
  p_sss: argparse.ArgumentParser = sub.add_parser(
      'sss', help='Shamir Shared Secret (unauthenticated).')
  sss_sub = p_sss.add_subparsers(dest='sss_command')

  # Generate new SSS params (t, prime, coefficients)
  p_sss_new: argparse.ArgumentParser = sss_sub.add_parser(
      'new', help='Generate SSS params (minimum, prime, coefficients).')
  p_sss_new.add_argument('minimum', type=int, help='Threshold t (≥ 2)')
  p_sss_new.add_argument('bits', type=int, help='Prime modulus bit length (≥ 128 for non-toy)')
  p_sss_new.add_argument('--out', type=str, required=True,
                         help='Base path; will save ".priv" and ".pub"')
  p_sss_new.add_argument('--protect', type=str, default='', help='Password to encrypt saved files')

  # Issue N shares for a secret
  p_sss_shares: argparse.ArgumentParser = sss_sub.add_parser(
      'shares', help='Issue N shares for a secret (private params).')
  p_sss_shares.add_argument('secret', type=str, help='Secret as integer (supports 0x..)')
  p_sss_shares.add_argument('count', type=int, help='How many shares to produce')
  p_sss_shares.add_argument(
      '--key', type=str, required=True, help='Path to private SSS key (.priv)')
  p_sss_shares.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Recover secret from shares
  p_sss_recover: argparse.ArgumentParser = sss_sub.add_parser(
      'recover', help='Recover secret from shares (public params).')
  p_sss_recover.add_argument('shares', nargs='+', help='Shares as k:v (e.g., 2:123 5:456 ...)')
  p_sss_recover.add_argument(
      '--key', type=str, required=True, help='Path to public SSS key (.pub)')
  p_sss_recover.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # Verify a share against a secret
  p_sss_verify: argparse.ArgumentParser = sss_sub.add_parser(
      'verify', help='Verify a share against a secret (private params).')
  p_sss_verify.add_argument('secret', type=str, help='Secret as integer (supports 0x..)')
  p_sss_verify.add_argument('share', type=str, help='One share as k:v (e.g., 7:9999)')
  p_sss_verify.add_argument(
      '--key', type=str, required=True, help='Path to private SSS key (.priv)')
  p_sss_verify.add_argument(
      '--protect', type=str, default='', help='Password to decrypt key file if needed')

  # ========================= Markdown Generation ==================================================

  # Documentation generation
  doc: argparse.ArgumentParser = sub.add_parser('doc', help='Documentation utilities.')
  doc_sub = doc.add_subparsers(dest='doc_command')
  doc_sub.add_parser('md', help='Emit Markdown for the CLI (see README.md section "Creating a New Version").')
  # doc_md: argparse.ArgumentParser (for future use)

  return parser


def main(argv: list[str] | None = None) -> int:  # pylint: disable=invalid-name,too-many-locals,too-many-branches,too-many-statements
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
  in_format: _StrBytesType = _StrBytesType.FromFlags(args.hex, args.b64, args.bin)
  out_format: _StrBytesType = _StrBytesType.FromFlags(args.out_hex, args.out_b64, args.out_bin)

  a: int
  b: int
  c: int
  e: int
  m: int
  n: int
  x: int
  y: int
  bt: bytes
  pt: bytes
  ct: bytes

  command: str = args.command.lower().strip() if args.command else ''
  match command:
    # -------- primes ----------
    case 'isprime':
      n = _ParseInt(args.n)
      print(modmath.IsPrime(n))
    case 'primegen':
      start: int = _ParseInt(args.start)
      count: int = args.count
      i = 0
      for p in modmath.PrimeGenerator(start):
        print(p)
        i += 1
        if count and i >= count:
          break
    case 'mersenne':
      for k, m_p, perfect in modmath.MersennePrimesGenerator(args.min_k):
        print(f'k={k}  M={m_p}  perfect={perfect}')
        if k > args.cutoff_k:
          break

    # -------- integer / modular ----------
    case 'gcd':
      a, b = _ParseInt(args.a), _ParseInt(args.b)
      print(base.GCD(a, b))
    case 'xgcd':
      a, b = _ParseInt(args.a), _ParseInt(args.b)
      print(base.ExtendedGCD(a, b))
    case 'mod':
      mod_command: str = args.mod_command.lower().strip() if args.mod_command else ''
      match mod_command:
        case 'inv':
          a, m = _ParseInt(args.a), _ParseInt(args.m)
          try:
            print(modmath.ModInv(a, m))
          except modmath.ModularDivideError:
            print('<<INVALID>> no modular inverse exists (ModularDivideError)')
        case 'div':
          x, y, m = _ParseInt(args.x), _ParseInt(args.y), _ParseInt(args.m)
          try:
            print(modmath.ModDiv(x, y, m))
          except modmath.ModularDivideError:
            print('<<INVALID>> no modular inverse exists (ModularDivideError)')
        case 'exp':
          a, e, m = _ParseInt(args.a), _ParseInt(args.e), _ParseInt(args.m)
          print(modmath.ModExp(a, e, m))
        case 'poly':
          x, m = _ParseInt(args.x), _ParseInt(args.m)
          coeffs: list[int] = _ParseIntList(args.coeff)
          print(modmath.ModPolynomial(x, coeffs, m))
        case 'lagrange':
          x, m = _ParseInt(args.x), _ParseInt(args.m)
          pts: dict[int, int] = {}
          k_s: str
          v_s: str
          for kv in args.pt:
            k_s, v_s = kv.split(':', 1)
            pts[_ParseInt(k_s)] = _ParseInt(v_s)
          print(modmath.ModLagrangeInterpolate(x, pts, m))
        case 'crt':
          crt_tuple: tuple[int, int, int, int] = (
              _ParseInt(args.a1), _ParseInt(args.m1), _ParseInt(args.a2), _ParseInt(args.m2))
          try:
            print(modmath.CRTPair(*crt_tuple))
          except modmath.ModularDivideError:
            print('<<INVALID>> moduli m1/m2 not co-prime (ModularDivideError)')
        case _:
          raise NotImplementedError()

    # -------- randomness / hashing ----------
    case 'random':
      rand_cmd: str = args.rand_command.lower().strip() if args.rand_command else ''
      match rand_cmd:
        case 'bits':
          print(base.RandBits(args.bits))
        case 'int':
          print(base.RandInt(_ParseInt(args.min), _ParseInt(args.max)))
        case 'bytes':
          print(base.BytesToHex(base.RandBytes(args.n)))
        case 'prime':
          print(modmath.NBitRandomPrime(args.bits))
        case _:
          raise NotImplementedError()
    case 'hash':
      hash_cmd: str = args.hash_command.lower().strip() if args.hash_command else ''
      match hash_cmd:
        case 'sha256':
          bt = _BytesFromText(args.data, in_format)
          digest: bytes = base.Hash256(bt)
          print(_BytesToText(digest, out_format))
        case 'sha512':
          bt = _BytesFromText(args.data, in_format)
          digest = base.Hash512(bt)
          print(_BytesToText(digest, out_format))
        case 'file':
          digest = base.FileHash(args.path, digest=args.digest)
          print(_BytesToText(digest, out_format))
        case _:
          raise NotImplementedError()

    # -------- AES ----------
    case 'aes':
      aes_cmd: str = args.aes_command.lower().strip() if args.aes_command else ''
      match aes_cmd:
        case 'key':
          aes_key: aes.AESKey = aes.AESKey.FromStaticPassword(args.password)
          if args.out:
            _SaveObj(aes_key, args.out, args.protect or None)
          else:
            print(_BytesToText(aes_key.key256, out_format))
        case 'encrypt':
          if args.key_b64:
            aes_key = aes.AESKey(key256=base.EncodedToBytes(args.key_b64))
          elif args.key_path:
            aes_key = _LoadObj(args.key_path, args.protect or None)
          else:
            raise base.InputError('provide --key-b64 or --key-path')
          aad: bytes | None = args.aad.encode('utf-8') if args.aad else None
          pt = _BytesFromText(args.plaintext, in_format)
          ct = aes_key.Encrypt(pt, associated_data=aad)
          print(_BytesToText(ct, out_format))
        case 'decrypt':
          if args.key_b64:
            aes_key = aes.AESKey(key256=base.EncodedToBytes(args.key_b64))
          elif args.key_path:
            aes_key = _LoadObj(args.key_path, args.protect or None)
          else:
            raise base.InputError('provide --key-b64 or --key-path')
          aad = args.aad.encode('utf-8') if args.aad else None
          ct = _BytesFromText(args.ciphertext, in_format)
          pt = aes_key.Decrypt(ct, associated_data=aad)
          print(_BytesToText(pt, out_format))
        case 'ecb':
          ecb_cmd: str = args.aes_ecb_command.lower().strip() if args.aes_ecb_command else ''
          if args.key_b64:
            aes_key = aes.AESKey(key256=base.EncodedToBytes(args.key_b64))
          elif args.key_path:
            aes_key = _LoadObj(args.key_path, args.protect or None)
          else:
            raise base.InputError('provide --key-b64 or --key-path')
          match ecb_cmd:
            case 'encrypthex':
              ecb: aes.AESKey.ECBEncoderClass = aes_key.ECBEncoder()
              print(ecb.EncryptHex(args.block_hex))
            case 'decrypthex':
              ecb = aes_key.ECBEncoder()
              print(ecb.DecryptHex(args.block_hex))
            case _:
              raise NotImplementedError()
        case _:
          raise NotImplementedError()

    # -------- RSA ----------
    case 'rsa':
      rsa_cmd: str = args.rsa_command.lower().strip() if args.rsa_command else ''
      match rsa_cmd:
        case 'new':
          rsa_priv: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(args.bits)
          if args.out:
            _SaveObj(rsa_priv, args.out, args.protect or None)
          rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(rsa_priv)
          print(f'n={rsa_pub.public_modulus}  bits={rsa_pub.public_modulus.bit_length()}')
          print(f'e={rsa_pub.encrypt_exp}')
        case 'encrypt':
          rsa_pub = rsa.RSAPublicKey.Copy(_LoadObj(args.key, args.protect or None))
          m = _ParseInt(args.message)
          print(rsa_pub.Encrypt(m))
        case 'decrypt':
          rsa_priv = _LoadObj(args.key, args.protect or None)
          c = _ParseInt(args.ciphertext)
          print(rsa_priv.Decrypt(c))
        case 'sign':
          rsa_priv = _LoadObj(args.key, args.protect or None)
          m = _ParseInt(args.message)
          print(rsa_priv.Sign(m))
        case 'verify':
          rsa_pub = rsa.RSAPublicKey.Copy(_LoadObj(args.key, args.protect or None))
          m = _ParseInt(args.message)
          sig: int = _ParseInt(args.signature)
          print(rsa_pub.VerifySignature(m, sig))
        case _:
          raise NotImplementedError()

    # -------- ElGamal ----------
    case 'elgamal':
      eg_cmd: str = args.eg_command.lower().strip() if args.eg_command else ''
      match eg_cmd:
        case 'shared':
          shared_eg: elgamal.ElGamalSharedPublicKey = elgamal.ElGamalSharedPublicKey.NewShared(
              args.bits)
          _SaveObj(shared_eg, args.out, args.protect or None)
          print('shared parameters saved')
        case 'new':
          shared_eg = _LoadObj(args.shared, args.protect or None)
          eg_priv: elgamal.ElGamalPrivateKey = elgamal.ElGamalPrivateKey.New(shared_eg)
          _SaveObj(eg_priv, args.out, args.protect or None)
          print('elgamal key saved')
        case 'encrypt':
          pub_eg: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(
              _LoadObj(args.key, args.protect or None))
          m = _ParseInt(args.message)
          cc: tuple[int, int] = pub_eg.Encrypt(m)
          print(f'{cc[0]} {cc[1]}')
        case 'decrypt':
          eg_priv = _LoadObj(args.key, args.protect or None)
          cc = _ParseInt(args.c1), _ParseInt(args.c2)
          print(eg_priv.Decrypt(cc))
        case 'sign':
          eg_priv = _LoadObj(args.key, args.protect or None)
          m = _ParseInt(args.message)
          ss: tuple[int, int] = eg_priv.Sign(m)
          print(f'{ss[0]} {ss[1]}')
        case 'verify':
          pub_eg = elgamal.ElGamalPublicKey.Copy(_LoadObj(args.key, args.protect or None))
          m = _ParseInt(args.message)
          ss = (_ParseInt(args.s1), _ParseInt(args.s2))
          print(pub_eg.VerifySignature(m, ss))
        case _:
          raise NotImplementedError()

    # -------- DSA ----------
    case 'dsa':
      dsa_cmd: str = args.dsa_command.lower().strip() if args.dsa_command else ''
      match dsa_cmd:
        case 'shared':
          dsa_shared: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(
              args.p_bits, args.q_bits)
          _SaveObj(dsa_shared, args.out, args.protect or None)
          print('dsa shared parameters saved')
        case 'new':
          dsa_priv: dsa.DSAPrivateKey = dsa.DSAPrivateKey.New(
              _LoadObj(args.shared, args.protect or None))
          _SaveObj(dsa_priv, args.out, args.protect or None)
          print('dsa key saved')
        case 'sign':
          dsa_priv = _LoadObj(args.key, args.protect or None)
          m = _ParseInt(args.message) % dsa_priv.prime_seed
          ss = dsa_priv.Sign(m)
          print(f'{ss[0]} {ss[1]}')
        case 'verify':
          dsa_pub: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(
              _LoadObj(args.key, args.protect or None))
          m = _ParseInt(args.message) % dsa_pub.prime_seed
          ss = (_ParseInt(args.s1), _ParseInt(args.s2))
          print(dsa_pub.VerifySignature(m, ss))
        case _:
          raise NotImplementedError()

    # -------- SSS ----------
    case 'sss':
      sss_cmd: str = args.sss_command.lower().strip() if args.sss_command else ''
      match sss_cmd:
        case 'new':
          sss_priv: sss.ShamirSharedSecretPrivate = sss.ShamirSharedSecretPrivate.New(
              args.minimum, args.bits)
          pub: sss.ShamirSharedSecretPublic = sss.ShamirSharedSecretPublic.Copy(sss_priv)
          _SaveObj(sss_priv, args.out + '.priv', args.protect or None)
          _SaveObj(pub, args.out + '.pub', args.protect or None)
          print('sss private/public saved')
        case 'shares':
          sss_priv = _LoadObj(args.key, args.protect or None)
          secret: int = _ParseInt(args.secret)
          for sh in sss_priv.Shares(secret, max_shares=args.count):
            print(f'{sh.share_key}:{sh.share_value}')
        case 'recover':
          pub = _LoadObj(args.key, args.protect or None)
          subset: list[sss.ShamirSharePrivate] = []
          for kv in args.shares:
            k_s, v_s = kv.split(':', 1)
            subset.append(sss.ShamirSharePrivate(
                minimum=pub.minimum, modulus=pub.modulus,
                share_key=_ParseInt(k_s), share_value=_ParseInt(v_s)))
          print(pub.RecoverSecret(subset))
        case 'verify':
          sss_priv = _LoadObj(args.key, args.protect or None)
          secret = _ParseInt(args.secret)
          k_s, v_s = args.share.split(':', 1)
          share = sss.ShamirSharePrivate(
              minimum=sss_priv.minimum, modulus=sss_priv.modulus,
              share_key=_ParseInt(k_s), share_value=_ParseInt(v_s))
          print(sss_priv.VerifyShare(secret, share))
        case _:
          raise NotImplementedError()

    # -------- Documentation ----------
    case 'doc':
      doc_command: str = (
          args.doc_command.lower().strip() if getattr(args, 'doc_command', '') else '')
      match doc_command:
        case 'md':
          print(_GenerateCLIMarkdown())
        case _:
          raise NotImplementedError()

    case _:
      parser.print_help()
  return 0


if __name__ == '__main__':
  sys.exit(main())
