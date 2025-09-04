#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto command line interface.

See README.md for documentation on how to use.

Notes on the layout (quick mental model):

isprime, primegen, mersenne
gcd, xgcd, and grouped mod inv|div|exp|poly|lagrange|crt
random bits|int|bytes|prime, hash sha256|sha512|file
aes key frompass, aes encrypt|decrypt (GCM), aes ecb encrypt|decrypt
rsa new|encrypt|decrypt|sign|verify|rawencrypt|rawdecrypt|rawsign|rawverify
elgamal shared|new|encrypt|decrypt|sign|verify|rawencrypt|rawdecrypt|rawsign|rawverify
dsa shared|new|sign|verify|rawsign|rawverify
bid new|verify
sss new|shares|recover|verify
"""

from __future__ import annotations

import argparse
import enum
import glob
import logging
# import pdb
import sys
from typing import Any, Iterable, Sequence

from . import base, modmath, rsa, sss, elgamal, dsa, aes

__author__ = 'balparda@github.com'
__version__: str = base.__version__  # version comes from base!
__version_tuple__: tuple[int, ...] = base.__version_tuple__


def _ParseInt(s: str, /) -> int:
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


def _ParseIntList(items: Iterable[str], /) -> list[int]:
  """Parse list of strings into list of ints."""
  return [_ParseInt(x) for x in items]


class _StrBytesType(enum.Enum):
  """Type of bytes encoded as string."""
  RAW = 0
  HEXADECIMAL = 1
  BASE64 = 2

  @staticmethod
  def FromFlags(is_hex: bool, is_base64: bool, is_bin: bool, /) -> _StrBytesType:
    """Use flags to determine the type."""
    if sum((is_hex, is_base64, is_bin)) > 1:
      raise base.InputError('Only one of --hex, --b64, --bin can be set, if any.')
    if is_bin:
      return _StrBytesType.RAW
    if is_base64:
      return _StrBytesType.BASE64
    return _StrBytesType.HEXADECIMAL  # default


def _BytesFromText(text: str, tp: _StrBytesType, /) -> bytes:
  """Parse bytes as hex, base64, or raw."""
  match tp:
    case _StrBytesType.RAW:
      return text.encode('utf-8')
    case _StrBytesType.HEXADECIMAL:
      return base.HexToBytes(text)
    case _StrBytesType.BASE64:
      return base.EncodedToBytes(text)


def _BytesToText(b: bytes, tp: _StrBytesType, /) -> str:
  """Output bytes as hex, base64, or raw."""
  match tp:
    case _StrBytesType.RAW:
      return b.decode('utf-8', errors='replace')
    case _StrBytesType.HEXADECIMAL:
      return base.BytesToHex(b)
    case _StrBytesType.BASE64:
      return base.BytesToEncoded(b)


def _MaybePasswordKey(password: str | None, /) -> aes.AESKey | None:
  """Generate a key if there is a password."""
  return aes.AESKey.FromStaticPassword(password) if password else None


def _SaveObj(obj: Any, path: str, password: str | None, /) -> None:
  """Save object."""
  key: aes.AESKey | None = _MaybePasswordKey(password)
  blob: bytes = base.Serialize(obj, file_path=path, key=key)
  logging.info('saved object: %s (%s)', path, base.HumanizedBytes(len(blob)))


def _LoadObj(path: str, password: str | None, expect: type, /) -> Any:
  """Load object."""
  key: aes.AESKey | None = _MaybePasswordKey(password)
  obj: Any = base.DeSerialize(file_path=path, key=key)
  if not isinstance(obj, expect):
    raise base.InputError(
        f'Object loaded from {path} is of invalid type {type(obj)}, expected {expect}')
  return obj


def _FlagNames(a: argparse.Action, /) -> list[str]:
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


def _ActionIsSubparser(a: argparse.Action, /) -> bool:
  return isinstance(a, argparse._SubParsersAction)  # type: ignore[attr-defined]  # pylint: disable=protected-access


def _FormatDefault(a: argparse.Action, /) -> str:
  if a.default is argparse.SUPPRESS:
    return ''
  if isinstance(a.default, bool):
    return ' (default: on)' if a.default else ''
  if a.default in (None, '', 0, False):
    return ''
  return f' (default: {a.default})'


def _FormatChoices(a: argparse.Action, /) -> str:
  return f' choices: {list(a.choices)}' if getattr(a, 'choices', None) else ''  # type:ignore


def _FormatType(a: argparse.Action, /) -> str:
  t: Any | None = getattr(a, 'type', None)
  if t is None:
    return ''
  # Show clean type names (int, str, float); for callables, just say 'custom'
  return f' type: {t.__name__ if hasattr(t, "__name__") else "custom"}'


def _FormatNArgs(a: argparse.Action, /) -> str:
  return f' nargs: {a.nargs}' if getattr(a, 'nargs', None) not in (None, 0) else ''


def _RowsForActions(actions: Sequence[argparse.Action], /) -> list[tuple[str, str]]:
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
    headers: tuple[str, str] = ('Option/Arg', 'Description'), /) -> str:
  if not rows:
    return ''
  out: list[str] = ['| ' + headers[0] + ' | ' + headers[1] + ' |', '|---|---|']
  for left, right in rows:
    out.append(f'| `{left}` | {right} |')
  return '\n'.join(out)


def _WalkSubcommands(
    parser: argparse.ArgumentParser, path: list[str] | None = None, /) -> list[
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


def _HelpText(sub_parser: argparse.ArgumentParser, parent_sub_action: Any, /) -> str:
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
      'generation**, **hashing**, **AES**, **RSA**, **El-Gamal**, **DSA**, **bidding**, **SSS**, '
      'and other utilities without writing code.\n')
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
      help_text: str = (sp.description or ' '.join(i.strip() for i in sp.format_usage().splitlines())).strip()  # type:ignore
      short: str = (sp.help if hasattr(sp, 'help') else '') or ''  # type:ignore
      help_text = short or help_text                               # type:ignore
      help_text = help_text.replace('usage: ', '').strip()  # type:ignore
      lines.append(f'- **`{name}`** — `{help_text}`')
  lines.append('')
  if parser.epilog:
    lines.append('```bash')
    lines.append(parser.epilog)
    lines.append('```\n')
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
                   'AES, RSA, El-Gamal, DSA, bidding, SSS, and utilities.'),
      epilog=(
          'Examples:\n\n'
          '  # --- Randomness ---\n'
          '  poetry run transcrypto random bits 16\n'
          '  poetry run transcrypto random int 1000 2000\n'
          '  poetry run transcrypto random bytes 32\n'
          '  poetry run transcrypto random prime 64\n\n'
          '  # --- Primes ---\n'
          '  poetry run transcrypto isprime 428568761\n'
          '  poetry run transcrypto primegen 100 -c 3\n'
          '  poetry run transcrypto mersenne -k 2 -C 17\n\n'
          '  # --- Integer / Modular Math ---\n'
          '  poetry run transcrypto gcd 462 1071\n'
          '  poetry run transcrypto xgcd 127 13\n'
          '  poetry run transcrypto mod inv 17 97\n'
          '  poetry run transcrypto mod div 6 127 13\n'
          '  poetry run transcrypto mod exp 438 234 127\n'
          '  poetry run transcrypto mod poly 12 17 10 20 30\n'
          '  poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1\n'
          '  poetry run transcrypto mod crt 6 7 127 13\n\n'
          '  # --- Hashing ---\n'
          '  poetry run transcrypto hash sha256 xyz\n'
          '  poetry run transcrypto --b64 hash sha512 eHl6\n'
          '  poetry run transcrypto hash file /etc/passwd --digest sha512\n\n'
          '  # --- AES ---\n'
          '  poetry run transcrypto --out-b64 aes key "correct horse battery staple"\n'
          '  poetry run transcrypto --b64 --out-b64 aes encrypt -k "<b64key>" "secret"\n'
          '  poetry run transcrypto --b64 --out-b64 aes decrypt -k "<b64key>" "<ciphertext>"\n'
          '  poetry run transcrypto aes ecb -k "<b64key>" encrypt "<128bithexblock>"\n'    # cspell:disable-line
          '  poetry run transcrypto aes ecb -k "<b64key>" decrypt "<128bithexblock>"\n\n'  # cspell:disable-line
          '  # --- RSA ---\n'
          '  poetry run transcrypto -p rsa-key rsa new --bits 2048\n'
          '  poetry run transcrypto -p rsa-key.pub rsa encrypt <plaintext>\n'
          '  poetry run transcrypto -p rsa-key.priv rsa decrypt <ciphertext>\n'
          '  poetry run transcrypto -p rsa-key.priv rsa sign <message>\n'
          '  poetry run transcrypto -p rsa-key.pub rsa verify <message> <signature>\n\n'
          '  # --- ElGamal ---\n'
          '  poetry run transcrypto -p eg-key elgamal shared --bits 2048\n'
          '  poetry run transcrypto -p eg-key elgamal new\n'
          '  poetry run transcrypto -p eg-key.pub elgamal encrypt <plaintext>\n'
          '  poetry run transcrypto -p eg-key.priv elgamal decrypt <c1:c2>\n'
          '  poetry run transcrypto -p eg-key.priv elgamal sign <message>\n'
          '  poetry run transcrypto-p eg-key.pub elgamal verify <message> <s1:s2>\n\n'
          '  # --- DSA ---\n'
          '  poetry run transcrypto -p dsa-key dsa shared --p-bits 2048 --q-bits 256\n'
          '  poetry run transcrypto -p dsa-key dsa new\n'
          '  poetry run transcrypto -p dsa-key.priv dsa sign <message>\n'
          '  poetry run transcrypto -p dsa-key.pub dsa verify <message> <s1:s2>\n\n'
          '  # --- Public Bid ---\n'
          '  poetry run transcrypto --bin bid new "tomorrow it will rain"\n'
          '  poetry run transcrypto --out-bin bid verify\n\n'
          '  # --- Shamir Secret Sharing (SSS) ---\n'
          '  poetry run transcrypto -p sss-key sss new 3 --bits 1024\n'
          '  poetry run transcrypto -p sss-key sss shares <secret> 5\n'
          '  poetry run transcrypto -p sss-key sss recover\n'
          '  poetry run transcrypto -p sss-key sss verify <secret>'
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

  # key loading/saving from/to file, with optional password; will only work with some commands
  parser.add_argument(
      '-p', '--key-path', type=str, default='',
      help='File path to serialized key object, if key is needed for operation')
  parser.add_argument(
      '--protect', type=str, default='',
      help='Password to encrypt/decrypt key file if using the `-p`/`--key-path` option')

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
      epilog='xgcd 462 1071\n(21, 7, -3) $$ xgcd 0 5\n(5, 0, 1) $$ xgcd 127 13\n(1, 4, -39)')
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
      epilog=('--bin hash sha512 xyz\n'
              '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
              '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728 $$'
              '--b64 hash sha512 eHl6  # "xyz" in base-64\n'
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
      'aes',
      help=('AES-256 operations (GCM/ECB) and key derivation. '
            'No measures are taken here to prevent timing attacks.'))
  aes_sub = p_aes.add_subparsers(dest='aes_command')

  # Derive key from password
  p_aes_key_pass: argparse.ArgumentParser = aes_sub.add_parser(
      'key',
      help=('Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive '
            'salt and iterations. Very good/safe for simple password-to-key but not for '
            'passwords databases (because of constant salt).'),
      epilog=('--out-b64 aes key "correct horse battery staple"\n'
              'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= $$ '  # cspell:disable-line
              '-p keyfile.out --protect hunter aes key "correct horse battery staple"\n'
              'AES key saved to \'keyfile.out\''))
  p_aes_key_pass.add_argument(
      'password', type=str, help='Password (leading/trailing spaces ignored)')

  # AES-256-GCM encrypt
  p_aes_enc: argparse.ArgumentParser = aes_sub.add_parser(
      'encrypt',
      help=('AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with '
            '`-p`/`--key-path` keyfile. All inputs are raw, or you '
            'can use `--bin`/`--hex`/`--b64` flags. Attention: if you provide `-a`/`--aad` '
            '(associated data, AAD), you will need to provide the same AAD when decrypting '
            'and it is NOT included in the `ciphertext`/CT returned by this method!'),
      epilog=('--b64 --out-b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= '          # cspell:disable-line
              'AAAAAAB4eXo=\nF2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA== $$ '            # cspell:disable-line
              '--b64 --out-b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 '  # cspell:disable-line
              'AAAAAAB4eXo=\nxOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA=='))              # cspell:disable-line
  p_aes_enc.add_argument('plaintext', type=str, help='Input data to encrypt (PT)')
  p_aes_enc.add_argument(
      '-k', '--key', type=str, default='', help='Key if `-p`/`--key-path` wasn\'t used (32 bytes)')
  p_aes_enc.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be separately sent to receiver/stored)')

  # AES-256-GCM decrypt
  p_aes_dec: argparse.ArgumentParser = aes_sub.add_parser(
      'decrypt',
      help=('AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with '
            '`-p`/`--key-path` keyfile. All inputs are raw, or you '
            'can use `--bin`/`--hex`/`--b64` flags. Attention: if you provided `-a`/`--aad` '
            '(associated data, AAD) during encryption, you will need to provide the same AAD now!'),
      epilog=('--b64 --out-b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= '      # cspell:disable-line
              'F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==\nAAAAAAB4eXo= $$ '        # cspell:disable-line
              '--b64 --out-b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= '      # cspell:disable-line
              '-a eHl6 xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==\nAAAAAAB4eXo='))  # cspell:disable-line
  p_aes_dec.add_argument('ciphertext', type=str, help='Input data to decrypt (CT)')
  p_aes_dec.add_argument(
      '-k', '--key', type=str, default='', help='Key if `-p`/`--key-path` wasn\'t used (32 bytes)')
  p_aes_dec.add_argument(
      '-a', '--aad', type=str, default='',
      help='Associated data (optional; has to be exactly the same as used during encryption)')

  # AES-ECB
  p_aes_ecb: argparse.ArgumentParser = aes_sub.add_parser(
      'ecb',
      help=('AES-256-ECB: encrypt/decrypt 128 bit (16 bytes) hexadecimal blocks. UNSAFE, except '
            'for specifically encrypting hash blocks which are very much expected to look random. '
            'ECB mode will have the same output for the same input (no IV/nonce is used).'))
  p_aes_ecb.add_argument(
      '-k', '--key', type=str, default='',
      help=('Key if `-p`/`--key-path` wasn\'t used (32 bytes; raw, or you '
            'can use `--bin`/`--hex`/`--b64` flags)'))
  aes_ecb_sub = p_aes_ecb.add_subparsers(dest='aes_ecb_command')

  # AES-ECB encrypt 16-byte hex block
  p_aes_ecb_e: argparse.ArgumentParser = aes_ecb_sub.add_parser(
      'encrypt',
      help=('AES-256-ECB: encrypt 16-bytes hex `plaintext` with `-k`/`--key` or with '
            '`-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash blocks.'),
      epilog=('--b64 aes ecb -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= encrypt '  # cspell:disable-line
              '00112233445566778899aabbccddeeff\n54ec742ca3da7b752e527b74e3a798d7'))
  p_aes_ecb_e.add_argument('plaintext', type=str, help='Plaintext block as 32 hex chars (16-bytes)')

  # AES-ECB decrypt 16-byte hex block
  p_aes_scb_d: argparse.ArgumentParser = aes_ecb_sub.add_parser(
      'decrypt',
      help=('AES-256-ECB: decrypt 16-bytes hex `ciphertext` with `-k`/`--key` or with '
            '`-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash blocks.'),
      epilog=('--b64 aes ecb -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= decrypt '  # cspell:disable-line
              '54ec742ca3da7b752e527b74e3a798d7\n00112233445566778899aabbccddeeff'))    # cspell:disable-line
  p_aes_scb_d.add_argument(
      'ciphertext', type=str, help='Ciphertext block as 32 hex chars (16-bytes)')

  # ========================= RSA ==================================================================

  # RSA group
  p_rsa: argparse.ArgumentParser = sub.add_parser(
      'rsa',
      help=('Raw RSA (Rivest-Shamir-Adleman) asymmetric cryptography over *integers* '
            '(BEWARE: no OAEP/PSS padding or validation). '
            'These are pedagogical/raw primitives; do not use for new protocols. '
            'No measures are taken here to prevent timing attacks. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  rsa_sub = p_rsa.add_subparsers(dest='rsa_command')

  # Generate new RSA private key
  p_rsa_new: argparse.ArgumentParser = rsa_sub.add_parser(
      'new',
      help=('Generate RSA private/public key pair with `bits` modulus size '
            '(prime sizes will be `bits`/2). '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('-p rsa-key rsa new --bits 64  # NEVER use such a small key: example only!\n'
              'RSA private/public keys saved to \'rsa-key.priv/.pub\''))
  p_rsa_new.add_argument(
      '--bits', type=int, default=3332, help='Modulus size in bits; the default is a safe size')

  # Encrypt integer with public key
  p_rsa_enc_raw: argparse.ArgumentParser = rsa_sub.add_parser(
      'rawencrypt',
      help='Encrypt integer `message` with public key.',
      epilog='-p rsa-key.pub rsa rawencrypt 999\n6354905961171348600')
  p_rsa_enc_raw.add_argument(
      'message', type=str, help='Integer message to encrypt, 1≤`message`<*modulus*')

  # Decrypt integer ciphertext with private key
  p_rsa_dec_raw: argparse.ArgumentParser = rsa_sub.add_parser(
      'rawdecrypt',
      help='Decrypt integer `ciphertext` with private key.',
      epilog='-p rsa-key.priv rsa rawdecrypt 6354905961171348600\n999')
  p_rsa_dec_raw.add_argument(
      'ciphertext', type=str, help='Integer ciphertext to decrypt, 1≤`ciphertext`<*modulus*')

  # Sign integer message with private key
  p_rsa_sig_raw: argparse.ArgumentParser = rsa_sub.add_parser(
      'rawsign',
      help='Sign integer `message` with private key.',
      epilog='-p rsa-key.priv rsa rawsign 999\n7632909108672871784')
  p_rsa_sig_raw.add_argument(
      'message', type=str, help='Integer message to sign, 1≤`message`<*modulus*')

  # Verify integer signature with public key
  p_rsa_ver_raw: argparse.ArgumentParser = rsa_sub.add_parser(
      'rawverify',
      help='Verify integer `signature` for integer `message` with public key.',
      epilog=('-p rsa-key.pub rsa rawverify 999 7632909108672871784\nRSA signature: OK $$ '
              '-p rsa-key.pub rsa rawverify 999 7632909108672871785\nRSA signature: INVALID'))
  p_rsa_ver_raw.add_argument(
      'message', type=str, help='Integer message that was signed earlier, 1≤`message`<*modulus*')
  p_rsa_ver_raw.add_argument(
      'signature', type=str,
      help='Integer putative signature for `message`, 1≤`signature`<*modulus*')

  # ========================= ElGamal ==============================================================

  # ElGamal group
  p_eg: argparse.ArgumentParser = sub.add_parser(
      'elgamal',
      help=('Raw El-Gamal asymmetric cryptography over *integers* '
            '(BEWARE: no ECIES-style KEM/DEM padding or validation). These are '
            'pedagogical/raw primitives; do not use for new protocols. '
            'No measures are taken here to prevent timing attacks. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  eg_sub = p_eg.add_subparsers(dest='eg_command')

  # Generate shared (p,g) params
  p_eg_shared: argparse.ArgumentParser = eg_sub.add_parser(
      'shared',
      help=('Generate a shared El-Gamal key with `bits` prime modulus size, which is the '
            'first step in key generation. '
            'The shared key can safely be used by any number of users to generate their '
            'private/public key pairs (with the `new` command). The shared keys are "public". '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('-p eg-key elgamal shared --bits 64  # NEVER use such a small key: example only!\n'
              'El-Gamal shared key saved to \'eg-key.shared\''))
  p_eg_shared.add_argument(
      '--bits', type=int, default=3332,
      help='Prime modulus (`p`) size in bits; the default is a safe size')

  # Generate individual private key from shared (p,g)
  eg_sub.add_parser(
      'new',
      help='Generate an individual El-Gamal private/public key pair from a shared key.',
      epilog='-p eg-key elgamal new\nEl-Gamal private/public keys saved to \'eg-key.priv/.pub\'')

  # Encrypt integer with public key
  p_eg_enc_raw: argparse.ArgumentParser = eg_sub.add_parser(
      'rawencrypt',
      help='Encrypt integer `message` with public key.',
      epilog='-p eg-key.pub elgamal rawencrypt 999\n2948854810728206041:15945988196340032688')
  p_eg_enc_raw.add_argument(
      'message', type=str, help='Integer message to encrypt, 1≤`message`<*modulus*')

  # Decrypt El-Gamal ciphertext tuple (c1,c2)
  p_eg_dec_raw: argparse.ArgumentParser = eg_sub.add_parser(
      'rawdecrypt',
      help='Decrypt integer `ciphertext` with private key.',
      epilog='-p eg-key.priv elgamal rawdecrypt 2948854810728206041:15945988196340032688\n999')
  p_eg_dec_raw.add_argument(
      'ciphertext', type=str,
      help=('Integer ciphertext to decrypt; expects `c1:c2` format with 2 integers, '
            ' 2≤`c1`,`c2`<*modulus*'))

  # Sign integer message with private key
  p_eg_sig_raw: argparse.ArgumentParser = eg_sub.add_parser(
      'rawsign',
      help='Sign integer message with private key. Output will 2 integers in a `s1:s2` format.',
      epilog='-p eg-key.priv elgamal rawsign 999\n4674885853217269088:14532144906178302633')
  p_eg_sig_raw.add_argument(
      'message', type=str, help='Integer message to sign, 1≤`message`<*modulus*')

  # Verify El-Gamal signature (s1,s2)
  p_eg_ver_raw: argparse.ArgumentParser = eg_sub.add_parser(
      'rawverify',
      help='Verify integer `signature` for integer `message` with public key.',
      epilog=('-p eg-key.pub elgamal rawverify 999 4674885853217269088:14532144906178302633\n'
              'El-Gamal signature: OK $$ '
              '-p eg-key.pub elgamal rawverify 999 4674885853217269088:14532144906178302632\n'
              'El-Gamal signature: INVALID'))
  p_eg_ver_raw.add_argument(
      'message', type=str, help='Integer message that was signed earlier, 1≤`message`<*modulus*')
  p_eg_ver_raw.add_argument(
      'signature', type=str,
      help=('Integer putative signature for `message`; expects `s1:s2` format with 2 integers, '
            ' 2≤`s1`,`s2`<*modulus*'))

  # ========================= DSA ==================================================================

  # DSA group
  p_dsa: argparse.ArgumentParser = sub.add_parser(
      'dsa',
      help=('Raw DSA (Digital Signature Algorithm) asymmetric signing over *integers* '
            '(BEWARE: no ECDSA/EdDSA padding or validation). These are pedagogical/raw '
            'primitives; do not use for new protocols. '
            'No measures are taken here to prevent timing attacks. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  dsa_sub = p_dsa.add_subparsers(dest='dsa_command')

  # Generate shared (p,q,g) params
  p_dsa_shared: argparse.ArgumentParser = dsa_sub.add_parser(
      'shared',
      help=('Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is '
            'the first step in key generation. `q-bits` should be larger than the secrets that '
            'will be protected and `p-bits` should be much larger than `q-bits` (e.g. 3584/256). '
            'The shared key can safely be used by any number of users to generate their '
            'private/public key pairs (with the `new` command). The shared keys are "public". '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('-p dsa-key dsa shared --p-bits 128 --q-bits 32  '
              '# NEVER use such a small key: example only!\n'
              'DSA shared key saved to \'dsa-key.shared\''))
  p_dsa_shared.add_argument(
      '--p-bits', type=int, default=3584,
      help='Prime modulus (`p`) size in bits; the default is a safe size')
  p_dsa_shared.add_argument(
      '--q-bits', type=int, default=256,
      help=('Prime modulus (`q`) size in bits; the default is a safe size ***IFF*** you '
            'are protecting symmetric keys or regular hashes'))

  # Generate individual private key from shared (p,q,g)
  dsa_sub.add_parser(
      'new',
      help='Generate an individual DSA private/public key pair from a shared key.',
      epilog='-p dsa-key dsa new\nDSA private/public keys saved to \'dsa-key.priv/.pub\'')

  # Sign integer m with private key
  p_dsa_sign_raw: argparse.ArgumentParser = dsa_sub.add_parser(
      'rawsign',
      help='Sign integer message with private key. Output will 2 integers in a `s1:s2` format.',
      epilog='-p dsa-key.priv dsa rawsign 999\n2395961484:3435572290')
  p_dsa_sign_raw.add_argument('message', type=str, help='Integer message to sign, 1≤`message`<`q`')

  # Verify DSA signature (s1,s2)
  p_dsa_verify_raw: argparse.ArgumentParser = dsa_sub.add_parser(
      'rawverify',
      help='Verify integer `signature` for integer `message` with public key.',
      epilog=('-p dsa-key.pub dsa rawverify 999 2395961484:3435572290\nDSA signature: OK $$ '
              '-p dsa-key.pub dsa rawverify 999 2395961484:3435572291\nDSA signature: INVALID'))
  p_dsa_verify_raw.add_argument(
      'message', type=str, help='Integer message that was signed earlier, 1≤`message`<`q`')
  p_dsa_verify_raw.add_argument(
      'signature', type=str,
      help=('Integer putative signature for `message`; expects `s1:s2` format with 2 integers, '
            ' 2≤`s1`,`s2`<`q`'))

  # ========================= Public Bid ===========================================================

  # bidding group
  p_bid: argparse.ArgumentParser = sub.add_parser(
      'bid',
      help=('Bidding on a `secret` so that you can cryptographically convince a neutral '
            'party that the `secret` that was committed to previously was not changed. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  bid_sub = p_bid.add_subparsers(dest='bid_command')

  # Generate a new bid
  p_bid_new: argparse.ArgumentParser = bid_sub.add_parser(
      'new',
      help=('Generate the bid files for `secret`. '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('--bin -p my-bid bid new "tomorrow it will rain"\n'
              'Bid private/public commitments saved to \'my-bid.priv/.pub\''))
  p_bid_new.add_argument('secret', type=str, help='Input data to bid to, the protected "secret"')

  # verify bid
  bid_sub.add_parser(
      'verify',
      help=('Verify the bid files for correctness and reveal the `secret`. '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('--out-bin -p my-bid bid verify\n'
              'Bid commitment: OK\nBid secret:\ntomorrow it will rain'))

  # ========================= Shamir Secret Sharing ================================================

  # SSS group
  p_sss: argparse.ArgumentParser = sub.add_parser(
      'sss',
      help=('Raw SSS (Shamir Shared Secret) secret sharing crypto scheme over *integers* '
            '(BEWARE: no modern message wrapping, padding or validation). These are '
            'pedagogical/raw primitives; do not use for new protocols. '
            'No measures are taken here to prevent timing attacks. '
            'All methods require file key(s) as `-p`/`--key-path` (see provided examples).'))
  sss_sub = p_sss.add_subparsers(dest='sss_command')

  # Generate new SSS params (t, prime, coefficients)
  p_sss_new: argparse.ArgumentParser = sss_sub.add_parser(
      'new',
      help=('Generate the private keys with `bits` prime modulus size and so that at least a '
            '`minimum` number of shares are needed to recover the secret. '
            'This key will be used to generate the shares later (with the `shares` command). '
            'Requires `-p`/`--key-path` to set the basename for output files.'),
      epilog=('-p sss-key sss new 3 --bits 64  # NEVER use such a small key: example only!\n'
              'SSS private/public keys saved to \'sss-key.priv/.pub\''))
  p_sss_new.add_argument(
      'minimum', type=int, help='Minimum number of shares required to recover secret, ≥ 2')
  p_sss_new.add_argument(
      '--bits', type=int, default=1024,
      help=('Prime modulus (`p`) size in bits; the default is a safe size ***IFF*** you '
            'are protecting symmetric keys; the number of bits should be comfortably larger '
            'than the size of the secret you want to protect with this scheme'))

  # Issue N shares for a secret
  p_sss_shares: argparse.ArgumentParser = sss_sub.add_parser(
      'shares',
      help='Issue `count` private shares for an integer `secret`.',
      epilog=('-p sss-key sss shares 999 5\n'
              'SSS 5 individual (private) shares saved to \'sss-key.share.1…5\'\n'
              '$ rm sss-key.share.2 sss-key.share.4  '
              '# this is to simulate only having shares 1,3,5'))
  p_sss_shares.add_argument(
      'secret', type=str, help='Integer secret to be protected, 1≤`secret`<*modulus*')
  p_sss_shares.add_argument(
      'count', type=int,
      help=('How many shares to produce; must be ≥ `minimum` used in `new` command or else the '
            '`secret` would become unrecoverable'))

  # Recover secret from shares
  sss_sub.add_parser(
      'recover',
      help='Recover secret from shares; will use any available shares that were found.',
      epilog=('-p sss-key sss recover\n'
              'Loaded SSS share: \'sss-key.share.3\'\n'
              'Loaded SSS share: \'sss-key.share.5\'\n'
              'Loaded SSS share: \'sss-key.share.1\'  '
              '# using only 3 shares: number 2/4 are missing\n'
              'Secret:\n999'))

  # Verify a share against a secret
  p_sss_verify: argparse.ArgumentParser = sss_sub.add_parser(
      'verify',
      help='Verify shares against a secret (private params).',
      epilog=('-p sss-key sss verify 999\n'
              'SSS share \'sss-key.share.3\' verification: OK\n'
              'SSS share \'sss-key.share.5\' verification: OK\n'
              'SSS share \'sss-key.share.1\' verification: OK $$ '
              '-p sss-key sss verify 998\n'
              'SSS share \'sss-key.share.3\' verification: INVALID\n'
              'SSS share \'sss-key.share.5\' verification: INVALID\n'
              'SSS share \'sss-key.share.1\' verification: INVALID'))
  p_sss_verify.add_argument(
      'secret', type=str, help='Integer secret used to generate the shares, 1≤`secret`<*modulus*')

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


def AESCommand(
    args: argparse.Namespace, in_format: _StrBytesType, out_format: _StrBytesType, /) -> None:
  """Execute `aes` command."""
  pt: bytes
  ct: bytes
  aes_cmd: str = args.aes_command.lower().strip() if args.aes_command else ''
  match aes_cmd:
    case 'key':
      aes_key: aes.AESKey = aes.AESKey.FromStaticPassword(args.password)
      if args.key_path:
        _SaveObj(aes_key, args.key_path, args.protect or None)
        print(f'AES key saved to {args.key_path!r}')
      else:
        print(_BytesToText(aes_key.key256, out_format))
    case 'encrypt':
      if args.key:
        aes_key = aes.AESKey(key256=_BytesFromText(args.key, in_format))
      elif args.key_path:
        aes_key = _LoadObj(args.key_path, args.protect or None, aes.AESKey)
      else:
        raise base.InputError('provide -k/--key or -p/--key-path')
      aad: bytes | None = _BytesFromText(args.aad, in_format) if args.aad else None
      pt = _BytesFromText(args.plaintext, in_format)
      ct = aes_key.Encrypt(pt, associated_data=aad)
      print(_BytesToText(ct, out_format))
    case 'decrypt':
      if args.key:
        aes_key = aes.AESKey(key256=_BytesFromText(args.key, in_format))
      elif args.key_path:
        aes_key = _LoadObj(args.key_path, args.protect or None, aes.AESKey)
      else:
        raise base.InputError('provide -k/--key or -p/--key-path')
      aad = _BytesFromText(args.aad, in_format) if args.aad else None
      ct = _BytesFromText(args.ciphertext, in_format)
      pt = aes_key.Decrypt(ct, associated_data=aad)
      print(_BytesToText(pt, out_format))
    case 'ecb':
      ecb_cmd: str = args.aes_ecb_command.lower().strip() if args.aes_ecb_command else ''
      if args.key:
        aes_key = aes.AESKey(key256=_BytesFromText(args.key, in_format))
      elif args.key_path:
        aes_key = _LoadObj(args.key_path, args.protect or None, aes.AESKey)
      else:
        raise base.InputError('provide -k/--key or -p/--key-path')
      match ecb_cmd:
        case 'encrypt':
          ecb: aes.AESKey.ECBEncoderClass = aes_key.ECBEncoder()
          print(ecb.EncryptHex(args.plaintext))
        case 'decrypt':
          ecb = aes_key.ECBEncoder()
          print(ecb.DecryptHex(args.ciphertext))
        case _:
          raise NotImplementedError()
    case _:
      raise NotImplementedError()


def RSACommand(args: argparse.Namespace, /) -> None:
  """Execute `rsa` command."""
  c: int
  m: int
  rsa_cmd: str = args.rsa_command.lower().strip() if args.rsa_command else ''
  match rsa_cmd:
    case 'new':
      rsa_priv: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(args.bits)
      rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(rsa_priv)
      _SaveObj(rsa_priv, args.key_path + '.priv', args.protect or None)
      _SaveObj(rsa_pub, args.key_path + '.pub', args.protect or None)
      print(f'RSA private/public keys saved to {args.key_path + ".priv/.pub"!r}')
    case 'rawencrypt':
      rsa_pub = rsa.RSAPublicKey.Copy(
          _LoadObj(args.key_path, args.protect or None, rsa.RSAPublicKey))
      m = _ParseInt(args.message)
      print(rsa_pub.RawEncrypt(m))
    case 'rawdecrypt':
      rsa_priv = _LoadObj(args.key_path, args.protect or None, rsa.RSAPrivateKey)
      c = _ParseInt(args.ciphertext)
      print(rsa_priv.RawDecrypt(c))
    case 'rawsign':
      rsa_priv = _LoadObj(args.key_path, args.protect or None, rsa.RSAPrivateKey)
      m = _ParseInt(args.message)
      print(rsa_priv.RawSign(m))
    case 'rawverify':
      rsa_pub = rsa.RSAPublicKey.Copy(
          _LoadObj(args.key_path, args.protect or None, rsa.RSAPublicKey))
      m = _ParseInt(args.message)
      sig: int = _ParseInt(args.signature)
      print('RSA signature: ' + ('OK' if rsa_pub.RawVerify(m, sig) else 'INVALID'))
    case _:
      raise NotImplementedError()


def ElGamalCommand(args: argparse.Namespace, /) -> None:
  """Execute `elgamal` command."""
  c1: str
  c2: str
  m: int
  ss: tuple[int, int]
  eg_cmd: str = args.eg_command.lower().strip() if args.eg_command else ''
  match eg_cmd:
    case 'shared':
      shared_eg: elgamal.ElGamalSharedPublicKey = elgamal.ElGamalSharedPublicKey.NewShared(
          args.bits)
      _SaveObj(shared_eg, args.key_path + '.shared', args.protect or None)
      print(f'El-Gamal shared key saved to {args.key_path + ".shared"!r}')
    case 'new':
      eg_priv: elgamal.ElGamalPrivateKey = elgamal.ElGamalPrivateKey.New(
          _LoadObj(args.key_path + '.shared', args.protect or None, elgamal.ElGamalSharedPublicKey))
      eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(eg_priv)
      _SaveObj(eg_priv, args.key_path + '.priv', args.protect or None)
      _SaveObj(eg_pub, args.key_path + '.pub', args.protect or None)
      print(f'El-Gamal private/public keys saved to {args.key_path + ".priv/.pub"!r}')
    case 'rawencrypt':
      eg_pub = elgamal.ElGamalPublicKey.Copy(
          _LoadObj(args.key_path, args.protect or None, elgamal.ElGamalPublicKey))
      m = _ParseInt(args.message)
      ss = eg_pub.RawEncrypt(m)
      print(f'{ss[0]}:{ss[1]}')
    case 'rawdecrypt':
      eg_priv = _LoadObj(args.key_path, args.protect or None, elgamal.ElGamalPrivateKey)
      c1, c2 = args.ciphertext.split(':')
      ss = (_ParseInt(c1), _ParseInt(c2))
      print(eg_priv.RawDecrypt(ss))
    case 'rawsign':
      eg_priv = _LoadObj(args.key_path, args.protect or None, elgamal.ElGamalPrivateKey)
      m = _ParseInt(args.message)
      ss = eg_priv.RawSign(m)
      print(f'{ss[0]}:{ss[1]}')
    case 'rawverify':
      eg_pub = elgamal.ElGamalPublicKey.Copy(
          _LoadObj(args.key_path, args.protect or None, elgamal.ElGamalPublicKey))
      m = _ParseInt(args.message)
      c1, c2 = args.signature.split(':')
      ss = (_ParseInt(c1), _ParseInt(c2))
      print('El-Gamal signature: ' + ('OK' if eg_pub.RawVerify(m, ss) else 'INVALID'))
    case _:
      raise NotImplementedError()


def DSACommand(args: argparse.Namespace, /) -> None:
  """Execute `dsa` command."""
  c1: str
  c2: str
  m: int
  ss: tuple[int, int]
  dsa_cmd: str = args.dsa_command.lower().strip() if args.dsa_command else ''
  match dsa_cmd:
    case 'shared':
      dsa_shared: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(
          args.p_bits, args.q_bits)
      _SaveObj(dsa_shared, args.key_path + '.shared', args.protect or None)
      print(f'DSA shared key saved to {args.key_path + ".shared"!r}')
    case 'new':
      dsa_priv: dsa.DSAPrivateKey = dsa.DSAPrivateKey.New(
          _LoadObj(args.key_path + '.shared', args.protect or None, dsa.DSASharedPublicKey))
      dsa_pub: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(dsa_priv)
      _SaveObj(dsa_priv, args.key_path + '.priv', args.protect or None)
      _SaveObj(dsa_pub, args.key_path + '.pub', args.protect or None)
      print(f'DSA private/public keys saved to {args.key_path + ".priv/.pub"!r}')
    case 'rawsign':
      dsa_priv = _LoadObj(args.key_path, args.protect or None, dsa.DSAPrivateKey)
      m = _ParseInt(args.message) % dsa_priv.prime_seed
      ss = dsa_priv.RawSign(m)
      print(f'{ss[0]}:{ss[1]}')
    case 'rawverify':
      dsa_pub = dsa.DSAPublicKey.Copy(
          _LoadObj(args.key_path, args.protect or None, dsa.DSAPublicKey))
      m = _ParseInt(args.message) % dsa_pub.prime_seed
      c1, c2 = args.signature.split(':')
      ss = (_ParseInt(c1), _ParseInt(c2))
      print('DSA signature: ' + ('OK' if dsa_pub.RawVerify(m, ss) else 'INVALID'))
    case _:
      raise NotImplementedError()


def BidCommand(
    args: argparse.Namespace, in_format: _StrBytesType, out_format: _StrBytesType, /) -> None:
  """Execute `bid` command."""
  bid_cmd: str = args.bid_command.lower().strip() if args.bid_command else ''
  match bid_cmd:
    case 'new':
      secret: bytes = _BytesFromText(args.secret, in_format)
      bid_priv: base.PrivateBid512 = base.PrivateBid512.New(secret)
      bid_pub: base.PublicBid512 = base.PublicBid512.Copy(bid_priv)
      _SaveObj(bid_priv, args.key_path + '.priv', args.protect or None)
      _SaveObj(bid_pub, args.key_path + '.pub', args.protect or None)
      print(f'Bid private/public commitments saved to {args.key_path + ".priv/.pub"!r}')
    case 'verify':
      bid_priv = _LoadObj(args.key_path + '.priv', args.protect or None, base.PrivateBid512)
      bid_pub = _LoadObj(args.key_path + '.pub', args.protect or None, base.PublicBid512)
      bid_pub_expect: base.PublicBid512 = base.PublicBid512.Copy(bid_priv)
      print('Bid commitment: ' + (
          'OK' if (bid_pub.VerifyBid(bid_priv.private_key, bid_priv.secret_bid) and
                   bid_pub == bid_pub_expect) else 'INVALID'))
      print('Bid secret:')
      print(_BytesToText(bid_priv.secret_bid, out_format))
    case _:
      raise NotImplementedError()


def SSSCommand(args: argparse.Namespace, /) -> None:
  """Execute `sss` command."""
  sss_cmd: str = args.sss_command.lower().strip() if args.sss_command else ''
  match sss_cmd:
    case 'new':
      sss_priv: sss.ShamirSharedSecretPrivate = sss.ShamirSharedSecretPrivate.New(
          args.minimum, args.bits)
      sss_pub: sss.ShamirSharedSecretPublic = sss.ShamirSharedSecretPublic.Copy(sss_priv)
      _SaveObj(sss_priv, args.key_path + '.priv', args.protect or None)
      _SaveObj(sss_pub, args.key_path + '.pub', args.protect or None)
      print(f'SSS private/public keys saved to {args.key_path + ".priv/.pub"!r}')
    case 'shares':
      sss_priv = _LoadObj(
          args.key_path + '.priv', args.protect or None, sss.ShamirSharedSecretPrivate)
      secret: int = _ParseInt(args.secret)
      sss_share: sss.ShamirSharePrivate
      for i, sss_share in enumerate(sss_priv.Shares(secret, max_shares=args.count)):
        _SaveObj(sss_share, f'{args.key_path}.share.{i + 1}', args.protect or None)
      print(f'SSS {args.count} individual (private) shares saved to '
            f'{args.key_path + ".share.1…" + str(args.count)!r}')
    case 'recover':
      sss_pub = _LoadObj(args.key_path + '.pub', args.protect or None, sss.ShamirSharedSecretPublic)
      subset: list[sss.ShamirSharePrivate] = []
      for fname in glob.glob(args.key_path + '.share.*'):
        sss_share = _LoadObj(fname, args.protect or None, sss.ShamirSharePrivate)
        subset.append(sss_share)
        print(f'Loaded SSS share: {fname!r}')
      print('Secret:')
      print(sss_pub.RecoverSecret(subset))
    case 'verify':
      sss_priv = _LoadObj(
          args.key_path + '.priv', args.protect or None, sss.ShamirSharedSecretPrivate)
      secret = _ParseInt(args.secret)
      for fname in glob.glob(args.key_path + '.share.*'):
        sss_share = _LoadObj(fname, args.protect or None, sss.ShamirSharePrivate)
        print(f'SSS share {fname!r} verification: '
              f'{"OK" if sss_priv.VerifyShare(secret, sss_share) else "INVALID"}')
    case _:
      raise NotImplementedError()


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
  in_format: _StrBytesType = _StrBytesType.FromFlags(args.hex, args.b64, args.bin)
  out_format: _StrBytesType = _StrBytesType.FromFlags(args.out_hex, args.out_b64, args.out_bin)

  a: int
  b: int
  e: int
  i: int
  m: int
  n: int
  x: int
  y: int
  bt: bytes

  try:
    # get the command, do basic checks and switch
    command: str = args.command.lower().strip() if args.command else ''
    if command in ('rsa', 'elgamal', 'dsa', 'bid', 'sss') and not args.key_path:
      raise base.InputError(f'you must provide -p/--key-path option for {command!r}')
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

      # -------- AES / RSA / El-Gamal / DSA / SSS ----------
      case 'aes':
        AESCommand(args, in_format, out_format)

      case 'rsa':
        RSACommand(args)

      case 'elgamal':
        ElGamalCommand(args)

      case 'dsa':
        DSACommand(args)

      case 'bid':
        BidCommand(args, in_format, out_format)

      case 'sss':
        SSSCommand(args)

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

  except NotImplementedError as err:
    print(f'Invalid command: {err}')
  except (base.Error, ValueError) as err:
    print(str(err))

  return 0


if __name__ == '__main__':
  sys.exit(main())
