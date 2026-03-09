# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto safe command line interface (CLI).

See <safetrans.md> for documentation on how to use. Test this CLI with:

poetry run pytest -vvv tests/safetrans_test.py
"""

from __future__ import annotations

import dataclasses
import enum
import logging
import pathlib

import click
import typer
from rich import console as rich_console

from transcrypto.cli import clibase
from transcrypto.core import aes, key
from transcrypto.utils import base, human
from transcrypto.utils import config as app_config
from transcrypto.utils import logging as tc_logging

from . import __version__


class IOFormat(enum.Enum):
  """Input/output data format for CLI commands."""

  hex = 'hex'
  b64 = 'b64'
  bin = 'bin'


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True)
class TransConfig(clibase.CLIConfig):
  """CLI global context, storing the configuration.

  Attributes:
    input_format (IOFormat): Input data format (hex, b64, bin)
    output_format (IOFormat): Output data format (hex, b64, bin)
    key_path (pathlib.Path | None): Path to key file for crypto operations
    protect (str | None): Password protection for key operations

  """

  input_format: IOFormat
  output_format: IOFormat
  key_path: pathlib.Path | None
  protect: str | None


def RequireKeyPath(config: TransConfig, command: str, /) -> str:
  """Ensure key path is provided and valid.

  Args:
      config (TransConfig): context
      command (str): command name

  Returns:
      str: key path

  Raises:
      base.InputError: input error

  """
  if config.key_path is None:
    raise base.InputError(f'you must provide -p/--key-path option for {command!r}')
  if config.key_path.exists() and config.key_path.is_dir():
    raise base.InputError(f'-p/--key-path must not be a directory: {str(config.key_path)!r}')
  return str(config.key_path)


def ParseInt(s: str, /, *, min_value: int | None = None) -> int:
  """Parse int, try to determine if binary, octal, decimal, or hexadecimal.

  Args:
      s (str): putative int
      min_value (int | None, optional): minimum allowed value. Defaults to None.

  Returns:
      int: parsed int

  Raises:
      base.InputError: input (conversion) error

  """
  raw: str = s.strip()
  if not raw:
    raise base.InputError(f'invalid int: {s!r}')
  try:
    clean: str = raw.lower().replace('_', '')
    value: int
    if clean.startswith('0x'):
      value = int(clean, 16)
    elif clean.startswith('0b'):
      value = int(clean, 2)
    elif clean.startswith('0o'):
      value = int(clean, 8)
    else:
      value = int(clean, 10)
    if min_value is not None and value < min_value:
      raise base.InputError(f'int must be ≥ {min_value}, got {value}')
    return value
  except ValueError as err:
    raise base.InputError(f'invalid int: {s!r}') from err


def ParseIntPairCLI(s: str, /) -> tuple[int, int]:
  """Parse a CLI int pair of the form `a:b`.

  Args:
      s (str): string to parse

  Returns:
      tuple[int, int]: parsed int pair

  Raises:
      base.InputError: if the input string is not a valid int pair

  """
  parts: list[str] = s.split(':')
  if len(parts) != 2:  # noqa: PLR2004
    raise base.InputError(f'invalid int(s): {s!r} (expected a:b)')
  return (ParseInt(parts[0]), ParseInt(parts[1]))


def BytesFromText(text: str, fmt: IOFormat, /) -> bytes:
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


def BytesToText(b: bytes, fmt: IOFormat, /) -> str:
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


def SaveObj(obj: key.CryptoKey, path: str, password: str | None, /) -> None:
  """Save object.

  Args:
      obj (cryptokey.CryptoKey): object
      path (str): path
      password (str | None): password

  """
  encryption_key: aes.AESKey | None = aes.AESKey.FromStaticPassword(password) if password else None
  blob: bytes = key.Serialize(obj, file_path=path, encryption_key=encryption_key)
  logging.info('saved object: %s (%s)', path, human.HumanizedBytes(len(blob)))


def LoadObj[T](path: str, password: str | None, expect: type[T], /) -> T:
  """Load object.

  Args:
      path (str): path
      password (str | None): password
      expect (type[T]): type to expect

  Returns:
      T: loaded object

  Raises:
      base.InputError: input error

  """
  decryption_key: aes.AESKey | None = aes.AESKey.FromStaticPassword(password) if password else None
  obj: T = key.DeSerialize(file_path=path, decryption_key=decryption_key)
  if not isinstance(obj, expect):
    raise base.InputError(
      f'Object loaded from {path} is of invalid type {type(obj)}, expected {expect}'
    )
  return obj


# ============================= "safetrans"/ROOT COMMAND =========================================


# CLI app setup, this is an important object and can be imported elsewhere and called
app = typer.Typer(
  add_completion=True,
  no_args_is_help=True,
  help=(  # keep in sync with Main().help
    'safetrans: CLI for number theory, hash, AES, RSA, El-Gamal, DSA, bidding, SSS, and more.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '# --- Randomness ---\n\n'
    'poetry run safetrans random bits 16\n\n'
    'poetry run safetrans random int 1000 2000\n\n'
    'poetry run safetrans random bytes 32\n\n'
    'poetry run safetrans random prime 64\n\n\n\n'
    '# --- Hashing ---\n\n'
    'poetry run safetrans hash sha256 xyz\n\n'
    'poetry run safetrans --input-format b64 hash sha512 -- eHl6\n\n'
    'poetry run safetrans hash file /etc/passwd --digest sha512\n\n\n\n'
    '# --- AES ---\n\n'
    'poetry run safetrans --output-format b64 aes key "correct horse battery staple"\n\n'
    'poetry run safetrans -i b64 -o b64 aes encrypt -k "<b64key>" -- "secret"\n\n'
    'poetry run safetrans -i b64 -o b64 aes decrypt -k "<b64key>" -- "<ciphertext>"\n\n\n\n'
    '# --- RSA ---\n\n'
    'poetry run safetrans -p rsa-key rsa new --bits 2048\n\n'
    'poetry run safetrans -i bin -o b64 -p rsa-key.pub rsa encrypt -a <aad> <plaintext>\n\n'
    'poetry run safetrans -i b64 -o bin -p rsa-key.priv rsa decrypt -a <aad> -- <ciphertext>\n\n'
    'poetry run safetrans -i bin -o b64 -p rsa-key.priv rsa sign <message>\n\n'
    'poetry run safetrans -i b64 -p rsa-key.pub rsa verify -- <message> <signature>\n\n\n\n'
    '# --- DSA ---\n\n'
    'poetry run safetrans -p dsa-key dsa shared --p-bits 2048 --q-bits 256\n\n'
    'poetry run safetrans -p dsa-key dsa new\n\n'
    'poetry run safetrans -i bin -o b64 -p dsa-key.priv dsa sign <message>\n\n'
    'poetry run safetrans -i b64 -p dsa-key.pub dsa verify -- <message> <signature>\n\n\n\n'
    '# --- Public Bid ---\n\n'
    'poetry run safetrans -i bin bid new "tomorrow it will rain"\n\n'
    'poetry run safetrans -o bin bid verify\n\n\n\n'
    '# --- Shamir Secret Sharing (SSS) ---\n\n'
    'poetry run safetrans -p sss-key sss new 3 --bits 1024\n\n'
    'poetry run safetrans -i bin -p sss-key sss shares <secret> <n>\n\n'
    'poetry run safetrans -o bin -p sss-key sss recover\n\n\n\n'
    '# --- Markdown ---\n\n'
    'poetry run safetrans markdown > safetrans.md\n\n'
  ),
)


def Run() -> None:
  """Run the CLI."""
  app()


@app.callback(
  invoke_without_command=True,  # have only one; this is the "constructor"
  help='safetrans: CLI for number theory, hash, AES, RSA, El-Gamal, DSA, bidding, SSS, and more.',
)  # keep message in sync with app.help
@clibase.CLIErrorGuard
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
    help=(
      'How to format inputs: "hex" (default hexadecimal), "b64" (base64), or "bin" (binary); '
      'sometimes base64 will start with "-" and that can conflict with other flags, so use " -- " '
      'before positional arguments if needed.'
    ),
  ),
  output_format: IOFormat = typer.Option(  # noqa: B008
    IOFormat.hex,
    '-o',
    '--output-format',
    help='How to format outputs: "hex" (default hexadecimal), "b64" (base64), or "bin" (binary).',
  ),
  # key loading/saving from/to file, with optional password; will only work with some commands
  key_path: pathlib.Path | None = typer.Option(  # noqa: B008
    None,
    '-p',
    '--key-path',
    resolve_path=True,
    help='File path to serialized key object, if key is needed for operation',
  ),
  protect: str | None = typer.Option(
    None,
    '-x',
    '--protect',
    help='Password to encrypt/decrypt key file if using the `-p`/`--key-path` option',
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
    include_process=False,
  )
  # create context with the arguments we received.
  ctx.obj = TransConfig(
    console=console,
    verbose=verbose,
    color=color,
    appconfig=app_config.InitConfig('transcrypto', 'safetrans.bin'),
    input_format=input_format,
    output_format=output_format,
    key_path=key_path,
    protect=protect,
  )


@app.command(
  'markdown',
  help='Emit Markdown docs for the CLI (see README.md section "Creating a New Version").',
  epilog=('Example:\n\n\n\n$ poetry run safetrans markdown > safetrans.md\n\n<<saves CLI doc>>'),
)
@clibase.CLIErrorGuard
def Markdown(*, ctx: click.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: TransConfig = ctx.obj
  config.console.print(clibase.GenerateTyperHelpMarkdown(app, prog_name='safetrans'))


# Import CLI modules to register their commands with the app
from transcrypto.cli import safeaeshash, safebidsecret, safeintmath, safepublicalgos  # pyright: ignore[reportUnusedImport] # noqa: I001, E402, F401
