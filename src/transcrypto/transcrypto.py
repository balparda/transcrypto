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
import os
# import pdb
import sys
from typing import Any, Iterable, Optional, Sequence

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
  """Parse list of strings into listo of ints."""
  return [_ParseInt(x) for x in items]


class _StrBytesType(enum.Enum):
  """Type of bytes encoded as string."""
  RAW = 0
  HEXADECIMAL = 1
  BASE64 = 2

  @staticmethod
  def FromFlags(is_hex: bool, is_base64: bool) -> _StrBytesType:
    return (_StrBytesType.HEXADECIMAL if is_hex else
            (_StrBytesType.BASE64 if is_base64 else _StrBytesType.RAW))


def _BytesFromText(text: str, tp: _StrBytesType) -> bytes:
  """Parse bytes as hex, base64, or raw."""
  match tp:
    case _StrBytesType.RAW:
      return text.encode('utf-8')
    case _StrBytesType.HEXADECIMAL:
      return base.HexToBytes(text)
    case _StrBytesType.BASE64:
      return base.EncodedToBytes(text)
    case _:
      raise base.InputError(f'Invalid type: {tp!r}')


def _BytesToText(b: bytes, tp: _StrBytesType) -> str:
  """Output bytes as hex, base64, or raw."""
  match tp:
    case _StrBytesType.RAW:
      return b.decode('utf-8', errors='replace')
    case _StrBytesType.HEXADECIMAL:
      return base.BytesToHex(b)
    case _StrBytesType.BASE64:
      return base.BytesToEncoded(b)
    case _:
      raise base.InputError(f'Invalid type: {tp!r}')


def _MaybePasswordKey(password: str | None) -> aes.AESKey | None:
  """Generate a key if there is a password."""
  return aes.AESKey.FromStaticPassword(password) if password else None


def _SaveObj(obj: Any, path: str, password: str | None) -> None:
  """Save object."""
  key = _MaybePasswordKey(password)
  blob = base.Serialize(obj, file_path=path, key=key)
  logging.info('saved object: %s (%s)', path, base.HumanizedBytes(len(blob)))

def _LoadObj(path: str, password: str | None) -> Any:
  """Load object."""
  key = _MaybePasswordKey(password)
  return base.DeSerialize(file_path=path, key=key)


def _PrintLines(lines: Iterable[str]) -> None:
  """Print lines."""
  for line in lines:
    print(line)


def _flag_names(a: argparse.Action) -> list[str]:
  # Positional args have empty 'option_strings'; otherwise use them (e.g., ['-v','--verbose'])
  return a.option_strings if a.option_strings else ([a.metavar or a.dest] if a.nargs != 0 else [a.dest])


def _action_is_subparser(a: argparse.Action) -> bool:
  return isinstance(a, argparse._SubParsersAction)  # type: ignore[attr-defined]


def _format_default(a: argparse.Action) -> str:
  if a.default is argparse.SUPPRESS:
    return ''
  if isinstance(a.default, bool):
    return ' (default: on)' if a.default else ''
  if a.default in (None, '', 0, False):
    return ''
  return f' (default: {a.default})'


def _format_choices(a: argparse.Action) -> str:
  return f' choices: {list(a.choices)}' if getattr(a, 'choices', None) else ''


def _format_type(a: argparse.Action) -> str:
  t = getattr(a, 'type', None)
  if t is None:
    return ''
  # Show clean type names (int, str, float); for callables, just say 'custom'
  return f' type: {t.__name__ if hasattr(t, "__name__") else "custom"}'


def _format_nargs(a: argparse.Action) -> str:
  return f' nargs: {a.nargs}' if getattr(a, 'nargs', None) not in (None, 0) else ''


def _rows_for_actions(actions: Sequence[argparse.Action]) -> list[tuple[str, str]]:
  rows: list[tuple[str, str]] = []
  for a in actions:
    if _action_is_subparser(a):
      continue
    # skip the built-in help action; it’s implied
    if getattr(a, 'help', '') == argparse.SUPPRESS or isinstance(a, argparse._HelpAction):  # type: ignore[attr-defined]
      continue
    flags = ', '.join(_flag_names(a))
    meta = ''.join((_format_type(a), _format_nargs(a), _format_choices(a), _format_default(a))).strip()
    desc = (a.help or '').strip()
    if meta:
      desc = f'{desc} [{meta}]' if desc else f'[{meta}]'
    rows.append((flags, desc))
  return rows


def _md_table(rows: Sequence[tuple[str, str]], headers: tuple[str, str] = ('Option/Arg', 'Description')) -> str:
  if not rows:
    return ''
  out = ['| ' + headers[0] + ' | ' + headers[1] + ' |', '|---|---|']
  for left, right in rows:
    out.append(f'| `{left}` | {right} |')
  return '\n'.join(out)


def _walk_subcommands(parser: argparse.ArgumentParser, path: list[str] | None = None) -> list[tuple[list[str], argparse.ArgumentParser, Optional[argparse._SubParsersAction]]]:  # type: ignore[name-defined]
  path = path or []
  items: list[tuple[list[str], argparse.ArgumentParser, Optional[argparse._SubParsersAction]]] = []
  sub_action: Optional[argparse._SubParsersAction] = None  # type: ignore[name-defined]
  for a in parser._actions:  # type: ignore[attr-defined]
    if _action_is_subparser(a):
      sub_action = a  # type: ignore[assignment]
      for name, sp in a.choices.items():  # type: ignore[union-attr]
        items.append((path + [name], sp, a))
        items.extend(_walk_subcommands(sp, path + [name]))
  return items


def generate_cli_markdown() -> str:
  """Return a Markdown doc section that reflects the current _BuildParser() tree."""
  parser = _BuildParser()
  prog = parser.prog or 'transcrypto.py'
  lines: list[str] = []

  # Header + global flags
  lines.append('## Command-Line Interface\n')
  lines.append(f'`{prog}` exposes cryptographic primitives, number theory tools, key management, and utilities.\n')
  lines.append('Invoke with:\n')
  lines.append('```bash')
  lines.append(f'poetry run {prog} <command> [sub-command] [options...]')
  lines.append('```\n')

  # Global options table
  global_rows = _rows_for_actions(parser._actions)  # type: ignore[attr-defined]
  if global_rows:
    lines.append('### Global Options\n')
    lines.append(_md_table(global_rows))
    lines.append('')

  # Top-level commands summary
  lines.append('### Commands\n')
  # Find top-level subparsers to list available commands
  top_subs = [a for a in parser._actions if _action_is_subparser(a)]  # type: ignore[attr-defined]
  for a in top_subs:
    for name, sp in a.choices.items():  # type: ignore[union-attr]
      help_text = (sp.description or sp.format_usage().splitlines()[0]).strip()
      short = (sp.help if hasattr(sp, 'help') else '') or ''
      lines.append(f'- `{name}` — {short or help_text}')
  lines.append('')

  # Detailed sections per (sub)command
  for path, subp, parent_action in _walk_subcommands(parser):
    header = ' '.join(path)
    lines.append(f'#### `{header}`')
    # Usage block
    usage = subp.format_usage().replace('usage: ', '').strip()
    lines.append('\n```bash')
    lines.append(f'poetry run {prog} {usage}')
    lines.append('```\n')

    # Description
    desc = (subp.description or subp.format_help().splitlines()[0]).strip()
    if desc:
      lines.append(desc + '\n')

    # Options/args table
    rows = _rows_for_actions(subp._actions)  # type: ignore[attr-defined]
    if rows:
      lines.append(_md_table(rows))
      lines.append('')

  return '\n'.join(lines)


def _BuildParser() -> argparse.ArgumentParser:
  """Construct the CLI argument parser (kept in sync with the docs)."""
  parser: argparse.ArgumentParser = argparse.ArgumentParser(
      prog='transcrypto.py',
      description='transcrypto: CLI for number theory, hashing, AES, RSA, ElGamal, DSA, SSS, and utilities.',
      epilog=(
        'Examples:\n'
        '  poetry run transcrypto.py isprime 428568761\n'
        '  poetry run transcrypto.py rsa new 2048 --out rsa.priv --protect hunter2\n'
        '  poetry run transcrypto.py aes key frompass "correct horse" --print-b64\n'
        '  poetry run transcrypto.py aes encrypt "secret" -k "<b64key>" -a "aad" --out-b64\n'
        '  poetry run transcrypto.py mod inv 17 97\n'
        '  poetry run transcrypto.py sss new 3 128 --out /tmp/sss\n'
      ),
      formatter_class=argparse.RawTextHelpFormatter)
  sub = parser.add_subparsers(dest='command')

  # ---------------- global flags ----------------
  parser.add_argument(
      '-v', '--verbose', action='count', default=0,
      help='Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG)')

  # ---------------- primes ----------------
  p_isprime = sub.add_parser(
      'isprime', help='Primality test with safe defaults (modmath.IsPrime)')
  p_isprime.add_argument('n', type=str,
      help='Integer to test (supports 0x.., 0b.., 0o.., underscores).')

  p_mr = sub.add_parser(
      'mr', help='Miller–Rabin primality with optional custom witnesses')
  p_mr.add_argument('n', type=str, help='Integer to test.')
  p_mr.add_argument(
      '-w', '--witness', action='append', default=[],
      help='Add a witness (repeatable). Example: -w 2 -w 7 -w 61')

  p_rprime = sub.add_parser(
      'randomprime', help='Generate a random prime with given bit length')
  p_rprime.add_argument('bits', type=int, help='Bit length (≥ 11).')

  p_pg = sub.add_parser(
      'primegen', help='Stream primes ≥ start (prints a limited count by default)')
  p_pg.add_argument('start', type=str, help='Starting integer (inclusive).')
  p_pg.add_argument(
      '-c', '--count', type=int, default=10,
      help='How many to print (default: 10; 0 = unlimited).')

  p_mers = sub.add_parser(
      'mersenne', help='Iterate Mersenne primes (k, M=2^k-1, perfect?)')
  p_mers.add_argument(
      '-k', '--min-k', type=int, default=0, help='Starting exponent k (default 0).')
  p_mers.add_argument(
      '-C', '--cutoff-k', type=int, default=10000, help='Stop once k > cutoff (default 10000).')

  # ---------------- integer / modular math ----------------
  p_gcd = sub.add_parser('gcd', help='Greatest Common Divisor')
  p_gcd.add_argument('a', type=str)
  p_gcd.add_argument('b', type=str)

  p_xgcd = sub.add_parser('xgcd', help='Extended GCD → (g, x, y) where ax + by = g')
  p_xgcd.add_argument('a', type=str)
  p_xgcd.add_argument('b', type=str)

  p_mod = sub.add_parser('mod', help='Modular arithmetic helpers')
  modsub = p_mod.add_subparsers(dest='mod_command')

  p_mi = modsub.add_parser('inv', help='Modular inverse: a^(-1) mod m')
  p_mi.add_argument('a', type=str)
  p_mi.add_argument('m', type=str)

  p_md = modsub.add_parser('div', help='Modular division: find z s.t. z·y ≡ x (mod m)')
  p_md.add_argument('x', type=str)
  p_md.add_argument('y', type=str)
  p_md.add_argument('m', type=str)

  p_me = modsub.add_parser('exp', help='Modular exponentiation: a^e mod m')
  p_me.add_argument('a', type=str)
  p_me.add_argument('e', type=str)
  p_me.add_argument('m', type=str)

  p_mp = modsub.add_parser('poly', help='Evaluate polynomial modulo m (c0 c1 c2 ... at t)')
  p_mp.add_argument('t', type=str, help='Evaluation point t.')
  p_mp.add_argument('m', type=str, help='Modulus m.')
  p_mp.add_argument('coeff', nargs='+', help='Coefficients (constant-term first).')

  p_ml = modsub.add_parser('lagrange', help='Lagrange interpolation over modulus')
  p_ml.add_argument('x', type=str, help='Point to evaluate at.')
  p_ml.add_argument('m', type=str, help='Modulus m.')
  p_ml.add_argument('pt', nargs='+', help='Points as k:v (e.g., 2:4 5:3 7:1).')

  p_crt = modsub.add_parser('crt', help='CRT pair: solve x ≡ a1 (mod m1), x ≡ a2 (mod m2)')
  p_crt.add_argument('a1', type=str)
  p_crt.add_argument('m1', type=str)
  p_crt.add_argument('a2', type=str)
  p_crt.add_argument('m2', type=str)

  # ---------------- randomness & hashing ----------------
  p_rand = sub.add_parser('rand', help='Cryptographically secure randomness')
  rsub = p_rand.add_subparsers(dest='rand_command')

  p_rbits = rsub.add_parser('bits', help='Random integer with exact bit length (MSB may be 1)')
  p_rbits.add_argument('bits', type=int, help='Number of bits ≥ 8 for base.RandBits.')

  p_rint = rsub.add_parser('int', help='Uniform random integer in [min, max], inclusive')
  p_rint.add_argument('min', type=str, help='Minimum (≥ 0).')
  p_rint.add_argument('max', type=str, help='Maximum (> min).')

  p_rbytes = rsub.add_parser('bytes', help='Random bytes from the OS CSPRNG')
  p_rbytes.add_argument('n', type=int, help='Number of bytes ≥ 1.')

  p_hash = sub.add_parser('hash', help='Hashing (SHA-256 / SHA-512 / file)')
  hsub = p_hash.add_subparsers(dest='hash_command')

  p_h256 = hsub.add_parser('sha256', help='SHA-256 of input data')
  p_h256.add_argument('data', type=str, help='Input text (raw; or use --hex/--b64).')
  p_h256.add_argument('--hex', action='store_true', help='Treat input as hex string.')
  p_h256.add_argument('--b64', action='store_true', help='Treat input as base64url.')
  p_h256.add_argument('--out-hex', action='store_true', help='Output digest as hex (default).')
  p_h256.add_argument('--out-b64', action='store_true', help='Output digest as base64url.')

  p_h512 = hsub.add_parser('sha512', help='SHA-512 of input data')
  p_h512.add_argument('data', type=str, help='Input text (raw; or use --hex/--b64).')
  p_h512.add_argument('--hex', action='store_true', help='Treat input as hex string.')
  p_h512.add_argument('--b64', action='store_true', help='Treat input as base64url.')
  p_h512.add_argument('--out-hex', action='store_true', help='Output digest as hex (default).')
  p_h512.add_argument('--out-b64', action='store_true', help='Output digest as base64url.')

  p_hf = hsub.add_parser('file', help='Hash file contents (streamed)')
  p_hf.add_argument('path', type=str, help='Path to file.')
  p_hf.add_argument('--digest', choices=['sha256', 'sha512'], default='sha256',
                    help='Digest (default: sha256).')
  p_hf.add_argument('--out-hex', action='store_true', help='Output digest as hex (default).')
  p_hf.add_argument('--out-b64', action='store_true', help='Output digest as base64url.')

  # ---------------- AES (GCM + ECB helper) ----------------
  p_aes = sub.add_parser('aes', help='AES-256 operations (GCM/ECB) and key derivation')
  asub = p_aes.add_subparsers(dest='aes_command')

  p_akey = asub.add_parser('key', help='Create/derive/store AES keys')
  akeysub = p_akey.add_subparsers(dest='aes_key_command')

  p_akey_pass = akeysub.add_parser('frompass', help='Derive key from a password (PBKDF2-HMAC-SHA256)')
  p_akey_pass.add_argument('password', type=str, help='Password (leading/trailing spaces ignored).')
  p_akey_pass.add_argument('--print-b64', action='store_true', help='Print derived key (base64url).')
  p_akey_pass.add_argument('--out', type=str, default='',
                           help='Save serialized AESKey to path.')
  p_akey_pass.add_argument('--protect', type=str, default='',
                           help='Password to encrypt the saved key file (Serialize).')

  p_aenc = asub.add_parser('encrypt', help='AES-256-GCM: encrypt (outputs IV||ct||tag)')
  p_aenc.add_argument('plaintext', type=str, help='Input data (raw; or use --in-hex/--in-b64).')
  p_aenc.add_argument('-k', '--key-b64', type=str, default='',
                      help='Key as base64url (32 bytes).')
  p_aenc.add_argument('-p', '--key-path', type=str, default='',
                      help='Path to serialized AESKey.')
  p_aenc.add_argument('-a', '--aad', type=str, default='', help='Associated data (optional).')
  p_aenc.add_argument('--in-hex', action='store_true', help='Treat plaintext as hex.')
  p_aenc.add_argument('--in-b64', action='store_true', help='Treat plaintext as base64url.')
  p_aenc.add_argument('--out-hex', action='store_true', help='Output ciphertext as hex (default).')
  p_aenc.add_argument('--out-b64', action='store_true', help='Output ciphertext as base64url.')
  p_aenc.add_argument('--protect', type=str, default='',
                      help='Password to decrypt key file if using --key-path.')

  p_adec = asub.add_parser('decrypt', help='AES-256-GCM: decrypt IV||ct||tag')
  p_adec.add_argument('ciphertext', type=str, help='Input blob (use --in-hex/--in-b64).')
  p_adec.add_argument('-k', '--key-b64', type=str, default='',
                      help='Key as base64url (32 bytes).')
  p_adec.add_argument('-p', '--key-path', type=str, default='',
                      help='Path to serialized AESKey.')
  p_adec.add_argument('-a', '--aad', type=str, default='', help='Associated data (must match).')
  p_adec.add_argument('--in-hex', action='store_true', help='Treat ciphertext as hex.')
  p_adec.add_argument('--in-b64', action='store_true', help='Treat ciphertext as base64url.')
  p_adec.add_argument('--out-hex', action='store_true', help='Output plaintext as hex.')
  p_adec.add_argument('--out-b64', action='store_true', help='Output plaintext as base64url.')
  p_adec.add_argument('--protect', type=str, default='',
                      help='Password to decrypt key file if using --key-path.')

  p_aecb = asub.add_parser('ecb', help='AES-ECB (unsafe; fixed 16-byte blocks only)')
  aecbsub = p_aecb.add_subparsers(dest='aes_ecb_command')

  p_aecb_e = aecbsub.add_parser('encrypthex', help='Encrypt 16-byte hex block with AES-ECB')
  p_aecb_e.add_argument('key_b64', type=str, help='Key as base64url (32 bytes).')
  p_aecb_e.add_argument('block_hex', type=str, help='Plaintext block as 32 hex chars.')

  p_aecb_d = aecbsub.add_parser('decrypthex', help='Decrypt 16-byte hex block with AES-ECB')
  p_aecb_d.add_argument('key_b64', type=str, help='Key as base64url (32 bytes).')
  p_aecb_d.add_argument('block_hex', type=str, help='Ciphertext block as 32 hex chars.')

  # ---------------- RSA ----------------
  p_rsa = sub.add_parser('rsa', help='Raw RSA over integers (no OAEP/PSS)')
  rsasub = p_rsa.add_subparsers(dest='rsa_command')

  p_rsa_new = rsasub.add_parser('new', help='Generate RSA private key')
  p_rsa_new.add_argument('bits', type=int, help='Modulus size in bits (e.g., 2048).')
  p_rsa_new.add_argument('--out', type=str, default='', help='Save private key to path (Serialize).')
  p_rsa_new.add_argument('--protect', type=str, default='', help='Password to encrypt saved key file.')

  p_rsa_enc = rsasub.add_parser('encrypt', help='Encrypt integer with public key')
  p_rsa_enc.add_argument('message', type=str, help='Integer message (e.g., "12345" or "0x...").')
  p_rsa_enc.add_argument('--key', type=str, required=True, help='Path to private/public key (Serialize).')
  p_rsa_enc.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_rsa_dec = rsasub.add_parser('decrypt', help='Decrypt integer ciphertext with private key')
  p_rsa_dec.add_argument('ciphertext', type=str, help='Integer ciphertext.')
  p_rsa_dec.add_argument('--key', type=str, required=True, help='Path to private key (Serialize).')
  p_rsa_dec.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_rsa_sig = rsasub.add_parser('sign', help='Sign integer message with private key')
  p_rsa_sig.add_argument('message', type=str, help='Integer message.')
  p_rsa_sig.add_argument('--key', type=str, required=True, help='Path to private key (Serialize).')
  p_rsa_sig.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_rsa_ver = rsasub.add_parser('verify', help='Verify integer signature with public key')
  p_rsa_ver.add_argument('message', type=str, help='Integer message.')
  p_rsa_ver.add_argument('signature', type=str, help='Integer signature.')
  p_rsa_ver.add_argument('--key', type=str, required=True, help='Path to private/public key (Serialize).')
  p_rsa_ver.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  # ---------------- ElGamal ----------------
  p_eg = sub.add_parser('elgamal', help='Raw El-Gamal (no padding)')
  egsub = p_eg.add_subparsers(dest='eg_command')

  p_eg_shared = egsub.add_parser('shared', help='Generate shared parameters (p, g)')
  p_eg_shared.add_argument('bits', type=int, help='Bit length for prime modulus p.')
  p_eg_shared.add_argument('--out', type=str, required=True, help='Save shared key to path.')
  p_eg_shared.add_argument('--protect', type=str, default='', help='Password to encrypt saved key file.')

  p_eg_new = egsub.add_parser('new', help='Generate individual private key from shared')
  p_eg_new.add_argument('--shared', type=str, required=True, help='Path to shared (p,g).')
  p_eg_new.add_argument('--out', type=str, required=True, help='Save private key to path.')
  p_eg_new.add_argument('--protect', type=str, default='', help='Password to encrypt saved key file.')

  p_eg_enc = egsub.add_parser('encrypt', help='Encrypt integer with public key')
  p_eg_enc.add_argument('message', type=str, help='Integer message 1 ≤ m < p.')
  p_eg_enc.add_argument('--key', type=str, required=True, help='Path to private/public key.')
  p_eg_enc.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_eg_dec = egsub.add_parser('decrypt', help='Decrypt El-Gamal ciphertext tuple (c1,c2)')
  p_eg_dec.add_argument('c1', type=str)
  p_eg_dec.add_argument('c2', type=str)
  p_eg_dec.add_argument('--key', type=str, required=True, help='Path to private key.')
  p_eg_dec.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_eg_sig = egsub.add_parser('sign', help='Sign integer message with private key')
  p_eg_sig.add_argument('message', type=str)
  p_eg_sig.add_argument('--key', type=str, required=True, help='Path to private key.')
  p_eg_sig.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_eg_ver = egsub.add_parser('verify', help='Verify El-Gamal signature (s1,s2)')
  p_eg_ver.add_argument('message', type=str)
  p_eg_ver.add_argument('s1', type=str)
  p_eg_ver.add_argument('s2', type=str)
  p_eg_ver.add_argument('--key', type=str, required=True, help='Path to private/public key.')
  p_eg_ver.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  # ---------------- DSA ----------------
  p_dsa = sub.add_parser('dsa', help='Raw DSA (no hash, integer messages < q)')
  dsasub = p_dsa.add_subparsers(dest='dsa_command')

  p_dsa_shared = dsasub.add_parser('shared', help='Generate (p,q,g) with q | p-1')
  p_dsa_shared.add_argument('p_bits', type=int, help='Bit length of p (≥ q_bits + 11).')
  p_dsa_shared.add_argument('q_bits', type=int, help='Bit length of q (≥ 11).')
  p_dsa_shared.add_argument('--out', type=str, required=True, help='Save shared params to path.')
  p_dsa_shared.add_argument('--protect', type=str, default='', help='Password to encrypt saved key file.')

  p_dsa_new = dsasub.add_parser('new', help='Generate DSA private key from shared')
  p_dsa_new.add_argument('--shared', type=str, required=True, help='Path to shared (p,q,g).')
  p_dsa_new.add_argument('--out', type=str, required=True, help='Save private key to path.')
  p_dsa_new.add_argument('--protect', type=str, default='', help='Password to encrypt saved key file.')

  p_dsa_sign = dsasub.add_parser('sign', help='Sign integer m (1 ≤ m < q)')
  p_dsa_sign.add_argument('message', type=str)
  p_dsa_sign.add_argument('--key', type=str, required=True, help='Path to private key.')
  p_dsa_sign.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_dsa_verify = dsasub.add_parser('verify', help='Verify DSA signature (s1,s2)')
  p_dsa_verify.add_argument('message', type=str)
  p_dsa_verify.add_argument('s1', type=str)
  p_dsa_verify.add_argument('s2', type=str)
  p_dsa_verify.add_argument('--key', type=str, required=True, help='Path to private/public key.')
  p_dsa_verify.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  # ---------------- Shamir Secret Sharing ----------------
  p_sss = sub.add_parser('sss', help='Shamir Shared Secret (unauthenticated)')
  ssssub = p_sss.add_subparsers(dest='sss_command')

  p_sss_new = ssssub.add_parser('new', help='Generate SSS params (minimum, prime, coefficients)')
  p_sss_new.add_argument('minimum', type=int, help='Threshold t (≥ 2).')
  p_sss_new.add_argument('bits', type=int, help='Prime modulus bit length (≥ 128 for non-toy).')
  p_sss_new.add_argument('--out', type=str, required=True,
                         help='Base path; will save ".priv" and ".pub".')
  p_sss_new.add_argument('--protect', type=str, default='', help='Password to encrypt saved files.')

  p_sss_shares = ssssub.add_parser('shares', help='Issue N shares for a secret (private params)')
  p_sss_shares.add_argument('secret', type=str, help='Secret as integer (supports 0x..).')
  p_sss_shares.add_argument('count', type=int, help='How many shares to produce.')
  p_sss_shares.add_argument('--key', type=str, required=True, help='Path to private SSS key (.priv).')
  p_sss_shares.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_sss_recover = ssssub.add_parser('recover', help='Recover secret from shares (public params)')
  p_sss_recover.add_argument('shares', nargs='+', help='Shares as k:v (e.g., 2:123 5:456 ...).')
  p_sss_recover.add_argument('--key', type=str, required=True, help='Path to public SSS key (.pub).')
  p_sss_recover.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  p_sss_verify = ssssub.add_parser('verify', help='Verify a share against a secret (private params)')
  p_sss_verify.add_argument('secret', type=str, help='Secret as integer (supports 0x..).')
  p_sss_verify.add_argument('share', type=str, help='One share as k:v (e.g., 7:9999).')
  p_sss_verify.add_argument('--key', type=str, required=True, help='Path to private SSS key (.priv).')
  p_sss_verify.add_argument('--protect', type=str, default='', help='Password to decrypt key file if needed.')

  # ---------------- Markdown Generation ----------------
  doc = sub.add_parser('doc', help='Documentation utilities')
  docsub = doc.add_subparsers(dest='doc_command')
  doc_md = docsub.add_parser('md', help='Emit Markdown for the CLI (auto-synced)')

  return parser


def main(argv: list[str] | None = None) -> int:  # pylint: disable=invalid-name,too-many-locals
  """Main entry point."""
  parser = _BuildParser()
  args: argparse.Namespace = parser.parse_args(argv)
  levels: list[int] = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
  logging.basicConfig(level=levels[min(args.verbose, len(levels) - 1)], format=getattr(base, 'LOG_FORMAT', '%(levelname)s:%(message)s'))  # type: ignore
  logging.captureWarnings(True)

  command = args.command.lower().strip() if args.command else ''
  match command:
    # -------- primes ----------
    case 'isprime':
      n = _ParseInt(args.n)
      print(modmath.IsPrime(n))
    case 'mr':
      n = _ParseInt(args.n)
      wit = set(_ParseIntList(args.witness)) if args.witness else None
      print(modmath.MillerRabinIsPrime(n, witnesses=wit))
    case 'randomprime':
      print(modmath.NBitRandomPrime(args.bits))
    case 'primegen':
      start = _ParseInt(args.start)
      count = args.count
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
      mod_command = args.mod_command.lower().strip() if args.mod_command else ''
      match mod_command:
        case 'inv':
          a, m = _ParseInt(args.a), _ParseInt(args.m)
          print(modmath.ModInv(a, m))
        case 'div':
          x, y, m = _ParseInt(args.x), _ParseInt(args.y), _ParseInt(args.m)
          print(modmath.ModDiv(x, y, m))
        case 'exp':
          a, e, m = _ParseInt(args.a), _ParseInt(args.e), _ParseInt(args.m)
          print(modmath.ModExp(a, e, m))
        case 'poly':
          t, m = _ParseInt(args.t), _ParseInt(args.m)
          coeffs = _ParseIntList(args.coeff)
          print(modmath.ModPolynomial(t, coeffs, m))
        case 'lagrange':
          x, m = _ParseInt(args.x), _ParseInt(args.m)
          pts: dict[int, int] = {}
          for kv in args.pt:
            k_s, v_s = kv.split(':', 1)
            pts[_ParseInt(k_s)] = _ParseInt(v_s)
          print(modmath.ModLagrangeInterpolate(x, pts, m))
        case 'crt':
          a1, m1, a2, m2 = _ParseInt(args.a1), _ParseInt(args.m1), _ParseInt(args.a2), _ParseInt(args.m2)
          print(modmath.CRTPair(a1, m1, a2, m2))
        case _:
          raise NotImplementedError()

    # -------- randomness / hashing ----------
    case 'rand':
      rcmd = args.rand_command.lower().strip() if args.rand_command else ''
      match rcmd:
        case 'bits':
          print(base.RandBits(args.bits))
        case 'int':
          print(base.RandInt(_ParseInt(args.min), _ParseInt(args.max)))
        case 'bytes':
          print(base.BytesToHex(base.RandBytes(args.n)))
        case _:
          raise NotImplementedError()
    case 'hash':
      hcmd = args.hash_command.lower().strip() if args.hash_command else ''
      match hcmd:
        case 'sha256':
          b = _BytesFromText(args.data, _StrBytesType.FromFlags(args.hex, args.b64))
          digest = base.Hash256(b)
          print(_BytesToText(digest, _StrBytesType.FromFlags(args.out_hex, args.out_b64)))
        case 'sha512':
          b = _BytesFromText(args.data, _StrBytesType.FromFlags(args.hex, args.b64))
          digest = base.Hash512(b)
          print(_BytesToText(digest, _StrBytesType.FromFlags(args.out_hex, args.out_b64)))
        case 'file':
          digest = base.FileHash(args.path, digest=args.digest)
          print(_BytesToText(digest, _StrBytesType.FromFlags(args.out_hex, args.out_b64)))
        case _:
          raise NotImplementedError()

    # -------- AES ----------
    case 'aes':
      acmd = args.aes_command.lower().strip() if args.aes_command else ''
      match acmd:
        case 'key':
          kcmd = args.aes_key_command.lower().strip() if args.aes_key_command else ''
          match kcmd:
            case 'frompass':
              key = aes.AESKey.FromStaticPassword(args.password)
              if args.print_b64:
                print(key.encoded)
              if args.out:
                _SaveObj(key, args.out, args.protect or None)
            case _:
              raise NotImplementedError()
        case 'encrypt':
          if args.key_b64:
            key = aes.AESKey(key256=base.EncodedToBytes(args.key_b64))
          elif args.key_path:
            key = _LoadObj(args.key_path, args.protect or None)
          else:
            raise base.InputError('provide --key-b64 or --key-path')
          aad = args.aad.encode('utf-8') if args.aad else None
          pt = _BytesFromText(args.plaintext, _StrBytesType.FromFlags(args.in_hex, args.in_b64))
          ct = key.Encrypt(pt, associated_data=aad)
          print(_BytesToText(ct, _StrBytesType.FromFlags(args.out_hex, args.out_b64)))
        case 'decrypt':
          if args.key_b64:
            key = aes.AESKey(key256=base.EncodedToBytes(args.key_b64))
          elif args.key_path:
            key = _LoadObj(args.key_path, args.protect or None)
          else:
            raise base.InputError('provide --key-b64 or --key-path')
          aad = args.aad.encode('utf-8') if args.aad else None
          ct = _BytesFromText(args.ciphertext, _StrBytesType.FromFlags(args.in_hex, args.in_b64))
          pt = key.Decrypt(ct, associated_data=aad)
          print(_BytesToText(pt, _StrBytesType.FromFlags(args.out_hex, args.out_b64)))
        case 'ecb':
          ecmd = args.aes_ecb_command.lower().strip() if args.aes_ecb_command else ''
          match ecmd:
            case 'encrypthex':
              key = aes.AESKey(key256=base.EncodedToBytes(args.key_b64))
              ecb = key.ECBEncoder()
              print(ecb.EncryptHex(args.block_hex))
            case 'decrypthex':
              key = aes.AESKey(key256=base.EncodedToBytes(args.key_b64))
              ecb = key.ECBEncoder()
              print(ecb.DecryptHex(args.block_hex))
            case _:
              raise NotImplementedError()
        case _:
          raise NotImplementedError()

    # -------- RSA ----------
    case 'rsa':
      rcmd = args.rsa_command.lower().strip() if args.rsa_command else ''
      match rcmd:
        case 'new':
          priv = rsa.RSAPrivateKey.New(args.bits)
          if args.out:
            _SaveObj(priv, args.out, args.protect or None)
          pub = rsa.RSAPublicKey.Copy(priv)
          print(f'n={priv.public_modulus}  bits={priv.public_modulus.bit_length()}')
          print(f'e={pub.public_exponent}')
        case 'encrypt':
          key_obj = _LoadObj(args.key, args.protect or None)
          pub = rsa.RSAPublicKey.Copy(key_obj)
          m = _ParseInt(args.message)
          print(pub.Encrypt(m))
        case 'decrypt':
          priv = _LoadObj(args.key, args.protect or None)
          c = _ParseInt(args.ciphertext)
          print(priv.Decrypt(c))
        case 'sign':
          priv = _LoadObj(args.key, args.protect or None)
          m = _ParseInt(args.message)
          print(priv.Sign(m))
        case 'verify':
          key_obj = _LoadObj(args.key, args.protect or None)
          pub = rsa.RSAPublicKey.Copy(key_obj)
          m = _ParseInt(args.message)
          sig = _ParseInt(args.signature)
          print(pub.VerifySignature(m, sig))
        case _:
          raise NotImplementedError()

    # -------- ElGamal ----------
    case 'elgamal':
      ecmd = args.eg_command.lower().strip() if args.eg_command else ''
      match ecmd:
        case 'shared':
          shared = elgamal.ElGamalSharedPublicKey.New(args.bits)
          _SaveObj(shared, args.out, args.protect or None)
          print('shared parameters saved')
        case 'new':
          shared = _LoadObj(args.shared, args.protect or None)
          priv = elgamal.ElGamalPrivateKey.New(shared)
          _SaveObj(priv, args.out, args.protect or None)
          print('elgamal key saved')
        case 'encrypt':
          key_obj = _LoadObj(args.key, args.protect or None)
          pub = elgamal.ElGamalPublicKey.Copy(key_obj)
          m = _ParseInt(args.message)
          c = pub.Encrypt(m)
          print(f'{c[0]} {c[1]}')
        case 'decrypt':
          priv = _LoadObj(args.key, args.protect or None)
          c1, c2 = _ParseInt(args.c1), _ParseInt(args.c2)
          print(priv.Decrypt((c1, c2)))
        case 'sign':
          priv = _LoadObj(args.key, args.protect or None)
          m = _ParseInt(args.message)
          s = priv.Sign(m)
          print(f'{s[0]} {s[1]}')
        case 'verify':
          key_obj = _LoadObj(args.key, args.protect or None)
          pub = elgamal.ElGamalPublicKey.Copy(key_obj)
          m = _ParseInt(args.message)
          s = (_ParseInt(args.s1), _ParseInt(args.s2))
          print(pub.VerifySignature(m, s))
        case _:
          raise NotImplementedError()

    # -------- DSA ----------
    case 'dsa':
      dcmd = args.dsa_command.lower().strip() if args.dsa_command else ''
      match dcmd:
        case 'shared':
          shared = dsa.DSASharedPublicKey.New(args.p_bits, args.q_bits)
          _SaveObj(shared, args.out, args.protect or None)
          print('dsa shared parameters saved')
        case 'new':
          shared = _LoadObj(args.shared, args.protect or None)
          priv = dsa.DSAPrivateKey.New(shared)
          _SaveObj(priv, args.out, args.protect or None)
          print('dsa key saved')
        case 'sign':
          priv = _LoadObj(args.key, args.protect or None)
          m = _ParseInt(args.message) % priv.prime_seed
          s = priv.Sign(m)
          print(f'{s[0]} {s[1]}')
        case 'verify':
          key_obj = _LoadObj(args.key, args.protect or None)
          pub = dsa.DSAPublicKey.Copy(key_obj)
          m = _ParseInt(args.message) % pub.prime_seed
          s = (_ParseInt(args.s1), _ParseInt(args.s2))
          print(pub.VerifySignature(m, s))
        case _:
          raise NotImplementedError()

    # -------- SSS ----------
    case 'sss':
      scmd = args.sss_command.lower().strip() if args.sss_command else ''
      match scmd:
        case 'new':
          priv = sss.ShamirSharedSecretPrivate.New(minimum_shares=args.minimum, bit_length=args.bits)
          pub = sss.ShamirSharedSecretPublic.Copy(priv)
          _SaveObj(priv, args.out + '.priv', args.protect or None)
          _SaveObj(pub, args.out + '.pub', args.protect or None)
          print('sss private/public saved')
        case 'shares':
          priv = _LoadObj(args.key, args.protect or None)
          secret = _ParseInt(args.secret)
          for sh in priv.Shares(secret, max_shares=args.count):
            print(f'{sh.share_key}:{sh.share_value}')
        case 'recover':
          pub = _LoadObj(args.key, args.protect or None)
          subset = []
          for kv in args.shares:
            k_s, v_s = kv.split(':', 1)
            subset.append(sss.ShamirSharePrivate(
              minimum=pub.minimum, modulus=pub.modulus,
              share_key=_ParseInt(k_s), share_value=_ParseInt(v_s)))
          print(pub.RecoverSecret(subset))
        case 'verify':
          priv = _LoadObj(args.key, args.protect or None)
          secret = _ParseInt(args.secret)
          k_s, v_s = args.share.split(':', 1)
          share = sss.ShamirSharePrivate(
            minimum=priv.minimum, modulus=priv.modulus,
            share_key=_ParseInt(k_s), share_value=_ParseInt(v_s))
          print(priv.VerifyShare(secret, share))
        case _:
          raise NotImplementedError()

    # -------- Documentation ----------
    case 'doc':
      doc_command = args.doc_command.lower().strip() if getattr(args, 'doc_command', '') else ''
      match doc_command:
        case 'md':
          print(generate_cli_markdown())
        case _:
          raise NotImplementedError()

    case _:
      parser.print_help()
  return 0


if __name__ == '__main__':
  sys.exit(main())
