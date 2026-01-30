# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto CLI: AES and Hash commands."""

from __future__ import annotations

import pathlib
import re

import click
import typer

from transcrypto import transcrypto
from transcrypto.cli import clibase
from transcrypto.core import aes, hashes
from transcrypto.utils import base

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

# =================================== "HASH" COMMAND ===============================================


hash_app = typer.Typer(
  no_args_is_help=True,
  help='Cryptographic Hashing (SHA-256 / SHA-512 / file).',
)
transcrypto.app.add_typer(hash_app, name='hash')


@hash_app.command(
  'sha256',
  help='SHA-256 of input `data`.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin hash sha256 xyz\n\n'
    '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282\n\n'
    '$ poetry run transcrypto -i b64 hash sha256 -- eHl6  # "xyz" in base-64\n\n'
    '3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282'
  ),
)
@clibase.CLIErrorGuard
def Hash256(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  data: str = typer.Argument(..., help='Input data (raw text; or `--input-format <hex|b64|bin>`)'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  bt: bytes = transcrypto.BytesFromText(data, config.input_format)
  config.console.print(transcrypto.BytesToText(hashes.Hash256(bt), config.output_format))


@hash_app.command(
  'sha512',
  help='SHA-512 of input `data`.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin hash sha512 xyz\n\n'
    '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
    '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728\n\n'
    '$ poetry run transcrypto -i b64 hash sha512 -- eHl6  # "xyz" in base-64\n\n'
    '4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a5'
    '8e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728'
  ),
)
@clibase.CLIErrorGuard
def Hash512(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  data: str = typer.Argument(..., help='Input data (raw text; or `--input-format <hex|b64|bin>`)'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  bt: bytes = transcrypto.BytesFromText(data, config.input_format)
  config.console.print(transcrypto.BytesToText(hashes.Hash512(bt), config.output_format))


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
@clibase.CLIErrorGuard
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
    '-d',
    '--digest',
    click_type=click.Choice(['sha256', 'sha512'], case_sensitive=False),
    help='Digest type, SHA-256 ("sha256") or SHA-512 ("sha512")',
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  config.console.print(
    transcrypto.BytesToText(hashes.FileHash(str(path), digest=digest), config.output_format)
  )


# =================================== "AES" COMMAND ================================================


aes_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'AES-256 operations (GCM/ECB) and key derivation. '
    'No measures are taken here to prevent timing attacks.'
  ),
)
transcrypto.app.add_typer(aes_app, name='aes')


@aes_app.command(
  'key',
  help=(
    'Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive '
    'salt and iterations. Very good/safe for simple password-to-key but not for '
    'passwords databases (because of constant salt).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -o b64 aes key "correct horse battery staple"\n\n'
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es=\n\n'  # cspell:disable-line
    '$ poetry run transcrypto -p keyfile.out --protect hunter aes key '
    '"correct horse battery staple"\n\n'
    "AES key saved to 'keyfile.out'"
  ),
)
@clibase.CLIErrorGuard
def AESKeyFromPass(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  password: str = typer.Argument(..., help='Password (leading/trailing spaces ignored)'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  aes_key: aes.AESKey = aes.AESKey.FromStaticPassword(password)
  if config.key_path is not None:
    transcrypto.SaveObj(aes_key, str(config.key_path), config.protect)
    config.console.print(f'AES key saved to {str(config.key_path)!r}')
  else:
    config.console.print(transcrypto.BytesToText(aes_key.key256, config.output_format))


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
    '$ poetry run transcrypto -i b64 -o b64 aes encrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- AAAAAAB4eXo=\n\n'  # cspell:disable-line
    'F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==\n\n'  # cspell:disable-line
    '$ poetry run transcrypto -i b64 -o b64 aes encrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 -- AAAAAAB4eXo=\n\n'  # cspell:disable-line
    'xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA=='  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  aes_key: aes.AESKey
  if key:
    key_bytes: bytes = transcrypto.BytesFromText(key, config.input_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = transcrypto.LoadObj(str(config.key_path), config.protect, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(plaintext, config.input_format)
  ct: bytes = aes_key.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(ct, config.output_format))


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
    '$ poetry run transcrypto -i b64 -o b64 aes decrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -- '  # cspell:disable-line
    'F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==\n\n'  # cspell:disable-line
    'AAAAAAB4eXo=\n\n'  # cspell:disable-line
    '$ poetry run transcrypto -i b64 -o b64 aes decrypt -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 -- '  # cspell:disable-line
    'xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==\n\n'  # cspell:disable-line
    'AAAAAAB4eXo='  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  aes_key: aes.AESKey
  if key:
    key_bytes: bytes = transcrypto.BytesFromText(key, config.input_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = transcrypto.LoadObj(str(config.key_path), config.protect, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')
  # associated data, if any
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  ct: bytes = transcrypto.BytesFromText(ciphertext, config.input_format)
  pt: bytes = aes_key.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(pt, config.output_format))


# ================================ "AES ECB" SUB-COMMAND ===========================================


aes_ecb_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'AES-256-ECB: encrypt/decrypt 128 bit (16 bytes) hexadecimal blocks. UNSAFE, except '
    'for specifically encrypting hash blocks which are very much expected to look random. '
    'ECB mode will have the same output for the same input (no IV/nonce is used).'
  ),
)
aes_app.add_typer(aes_ecb_app, name='ecb')


@aes_ecb_app.command(
  'encrypt',
  help=(
    'AES-256-ECB: encrypt 16-bytes hex `plaintext` with `-k`/`--key` or with '
    '`-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash blocks.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i b64 aes ecb -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= encrypt '  # cspell:disable-line
    '00112233445566778899aabbccddeeff\n\n'  # cspell:disable-line
    '54ec742ca3da7b752e527b74e3a798d7'
  ),
)
@clibase.CLIErrorGuard
def AESECBEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  plaintext: str = typer.Argument(..., help='Plaintext block as 32 hex chars (16-bytes)'),
  key: str | None = typer.Option(
    None,
    '-k',
    '--key',
    help=(
      "Key if `-p`/`--key-path` wasn't used (32 bytes; raw, or you "
      'can use `--input-format <hex|b64|bin>`)'
    ),
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  plaintext = plaintext.strip()
  if len(plaintext) != 32:  # noqa: PLR2004
    raise base.InputError('hexadecimal string must be exactly 32 hex chars')
  if not _HEX_RE.match(plaintext):
    raise base.InputError(f'invalid hexadecimal string: {plaintext!r}')
  aes_key: aes.AESKey
  if key:
    key_bytes: bytes = transcrypto.BytesFromText(key, config.input_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = transcrypto.LoadObj(str(config.key_path), config.protect, aes.AESKey)
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
    '$ poetry run transcrypto -i b64 aes ecb -k '
    'DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= decrypt '  # cspell:disable-line
    '54ec742ca3da7b752e527b74e3a798d7\n\n'  # cspell:disable-line
    '00112233445566778899aabbccddeeff'  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
def AESECBDecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(..., help='Ciphertext block as 32 hex chars (16-bytes)'),
  key: str | None = typer.Option(
    None,
    '-k',
    '--key',
    help=(
      "Key if `-p`/`--key-path` wasn't used (32 bytes; raw, or you "
      'can use `--input-format <hex|b64|bin>`)'
    ),
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  ciphertext = ciphertext.strip()
  if len(ciphertext) != 32:  # noqa: PLR2004
    raise base.InputError('hexadecimal string must be exactly 32 hex chars')
  if not _HEX_RE.match(ciphertext):
    raise base.InputError(f'invalid hexadecimal string: {ciphertext!r}')
  aes_key: aes.AESKey
  if key:
    key_bytes: bytes = transcrypto.BytesFromText(key, config.input_format)
    if len(key_bytes) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid AES key size: {len(key_bytes)} bytes (expected 32)')
    aes_key = aes.AESKey(key256=key_bytes)
  elif config.key_path is not None:
    aes_key = transcrypto.LoadObj(str(config.key_path), config.protect, aes.AESKey)
  else:
    raise base.InputError('provide -k/--key or -p/--key-path')
  ecb: aes.AESKey.ECBEncoderClass = aes_key.ECBEncoder()
  config.console.print(ecb.DecryptHex(ciphertext))
