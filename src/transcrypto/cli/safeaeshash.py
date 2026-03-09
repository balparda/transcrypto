# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto safe CLI: AES and Hash commands."""

from __future__ import annotations

import pathlib
import re

import click
import typer

from transcrypto import safetrans
from transcrypto.cli import clibase
from transcrypto.core import aes, hashes
from transcrypto.utils import base

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

# =================================== "HASH" COMMAND ===============================================


hash_app = typer.Typer(
  no_args_is_help=True,
  help='Cryptographic Hashing (SHA-256 / SHA-512 / file).',
)
safetrans.app.add_typer(hash_app, name='hash')


@hash_app.command(
  'sha256',
  help='SHA-256 of input `data`.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i bin hash sha256 xyz\n\n'
    '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282\n\n'
    '$ poetry run safetrans -i b64 hash sha256 -- eHl6  # "xyz" in base-64\n\n'
    '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282'
  ),
)
@clibase.CLIErrorGuard
def Hash256(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  data: str = typer.Argument(..., help='Input data (raw text; or `--input-format <hex|b64|bin>`)'),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  bt: bytes = safetrans.BytesFromText(data, config.input_format)
  config.console.print(safetrans.BytesToText(hashes.Hash256(bt), config.output_format))


@hash_app.command(
  'sha512',
  help='SHA-512 of input `data`.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i bin hash sha512 xyz\n\n'
    '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
    '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728\n\n'
    '$ poetry run safetrans -i b64 hash sha512 -- eHl6  # "xyz" in base-64\n\n'
    '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
    '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728'
  ),
)
@clibase.CLIErrorGuard
def Hash512(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  data: str = typer.Argument(..., help='Input data (raw text; or `--input-format <hex|b64|bin>`)'),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  bt: bytes = safetrans.BytesFromText(data, config.input_format)
  config.console.print(safetrans.BytesToText(hashes.Hash512(bt), config.output_format))


@hash_app.command(
  'file',
  help='SHA-256/512 hash of file contents, defaulting to SHA-256.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans hash file /etc/passwd --digest sha512\n\n'
    '8966f5953e79f55dfe34d3dc5b160ac4a4a3f9cbd1c36695a54e28d77c7874df'
    'f8595502f8a420608911b87d336d9e83c890f0e7ec11a76cb10b03e757f78aea'
  ),
)
@clibase.CLIErrorGuard
def HashFile(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
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
    '-d',
    '--digest',
    click_type=click.Choice(['sha256', 'sha512'], case_sensitive=False),
    help='Digest type, SHA-256 ("sha256") or SHA-512 ("sha512")',
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  config.console.print(
    safetrans.BytesToText(hashes.FileHash(str(path), digest=digest), config.output_format)
  )


# =================================== "AES" COMMAND ================================================


aes_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'AES-256 operations (GCM/ECB) and key derivation. '
    'No measures are taken here to prevent timing attacks.'
  ),
)
safetrans.app.add_typer(aes_app, name='aes')


@aes_app.command(
  'key',
  help=(
    'Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive '
    'salt and iterations. Very good/safe for simple password-to-key but not for '
    'passwords databases (because of constant salt).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -o b64 aes key "correct horse battery staple"\n\n'
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es=\n\n'  # cspell:disable-line
    '$ poetry run safetrans -p keyfile.out --protect hunter aes key '
    '"correct horse battery staple"\n\n'
    "AES key saved to 'keyfile.out'"
  ),
)
@clibase.CLIErrorGuard
def AESKeyFromPass(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  password: str = typer.Argument(..., help='Password (leading/trailing spaces ignored)'),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  aes_key: aes.AESKey = aes.AESKey.FromStaticPassword(password)
  if config.key_path is not None:
    safetrans.SaveObj(aes_key, str(config.key_path), config.protect)
    config.console.print(f'AES key saved to {str(config.key_path)!r}')
  else:
    config.console.print(safetrans.BytesToText(aes_key.key256, config.output_format))


@aes_app.command(
  'encrypt',
  help=(
    'AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with '
    '`-p`/`--key-path` keyfile. All inputs are raw, or you '
    'can use `--input-format <hex|b64|bin>`. Attention: if you provide `-a`/`--aad` '
    '(associated data, AAD), you will need to provide the same AAD when decrypting '
    'and it is NOT included in the `ciphertext`/CT returned by this method!'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i b64 -o b64 aes encrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- AAAAAAB4eXo=\n\n'  # cspell:disable-line
    'F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==\n\n'  # cspell:disable-line
    '$ poetry run safetrans -i b64 -o b64 aes encrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 -- AAAAAAB4eXo=\n\n'  # cspell:disable-line
    'xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA=='  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
def AESEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
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
  config: safetrans.TransConfig = ctx.obj
  aes_key: aes.AESKey
  if key:
    key_bytes: bytes = safetrans.BytesFromText(key, config.input_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = safetrans.LoadObj(str(config.key_path), config.protect, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')
  aad_bytes: bytes | None = safetrans.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = safetrans.BytesFromText(plaintext, config.input_format)
  ct: bytes = aes_key.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(safetrans.BytesToText(ct, config.output_format))


@aes_app.command(
  'decrypt',
  help=(
    'AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with '
    '`-p`/`--key-path` keyfile. All inputs are raw, or you '
    'can use `--input-format <hex|b64|bin>`. Attention: if you provided `-a`/`--aad` '
    '(associated data, AAD) during encryption, you will need to provide the same AAD now!'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i b64 -o b64 aes decrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- '  # cspell:disable-line
    'F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==\n\n'  # cspell:disable-line
    'AAAAAAB4eXo=\n\n'  # cspell:disable-line
    '$ poetry run safetrans -i b64 -o b64 aes decrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 -- '  # cspell:disable-line
    'xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==\n\n'  # cspell:disable-line
    'AAAAAAB4eXo='  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
def AESDecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
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
  config: safetrans.TransConfig = ctx.obj
  aes_key: aes.AESKey
  if key:
    key_bytes: bytes = safetrans.BytesFromText(key, config.input_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = safetrans.LoadObj(str(config.key_path), config.protect, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')
  # associated data, if any
  aad_bytes: bytes | None = safetrans.BytesFromText(aad, config.input_format) if aad else None
  ct: bytes = safetrans.BytesFromText(ciphertext, config.input_format)
  pt: bytes = aes_key.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(safetrans.BytesToText(pt, config.output_format))
