# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto safe CLI: Public algorithms commands."""

from __future__ import annotations

import click
import typer

from transcrypto import safetrans
from transcrypto.cli import clibase
from transcrypto.core import dsa, rsa

# ================================== "RSA" COMMAND =================================================


rsa_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'RSA (Rivest-Shamir-Adleman) asymmetric cryptography. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples). '
    'All non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. '
    'Attention: if you provide `-a`/`--aad` (associated data, AAD), '
    'you will need to provide the same AAD when decrypting/verifying and it is NOT included '
    'in the `ciphertext`/CT or `signature` returned by these methods! '
    'No measures are taken here to prevent timing attacks.'
  ),
)
safetrans.app.add_typer(rsa_app, name='rsa')


@rsa_app.command(
  'new',
  help=(
    'Generate RSA private/public key pair with `bits` modulus size (prime sizes will be `bits`/2).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -p rsa-key rsa new --bits 64  '
    '# NEVER use such a small key: example only!\n\n'
    "RSA private/public keys saved to 'rsa-key.priv/.pub'"
  ),
)
@clibase.CLIErrorGuard
def RSANew(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  bits: int = typer.Option(
    3332,
    '-b',
    '--bits',
    min=16,
    help='Modulus size in bits, ≥16; the default (3332) is a safe size',
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  base_path: str = safetrans.RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(bits)
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(rsa_priv)
  safetrans.SaveObj(rsa_priv, base_path + '.priv', config.protect)
  safetrans.SaveObj(rsa_pub, base_path + '.pub', config.protect)
  config.console.print(f'RSA private/public keys saved to {base_path + ".priv/.pub"!r}')


@rsa_app.command(
  'encrypt',
  help='Encrypt `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i bin -o b64 -p rsa-key.pub rsa encrypt "abcde" -a "xyz"\n\n'
    'AO6knI6xwq6TGR…Qy22jiFhXi1eQ=='
  ),
)
@clibase.CLIErrorGuard
def RSAEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  plaintext: str = typer.Argument(..., help='Message to encrypt'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  key_path: str = safetrans.RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = safetrans.LoadObj(key_path, config.protect, rsa.RSAPublicKey)
  aad_bytes: bytes | None = safetrans.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = safetrans.BytesFromText(plaintext, config.input_format)
  ct: bytes = rsa_pub.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(safetrans.BytesToText(ct, config.output_format))


@rsa_app.command(
  'decrypt',
  help='Decrypt `ciphertext` with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i b64 -o bin -p rsa-key.priv rsa decrypt -a eHl6 -- '
    'AO6knI6xwq6TGR…Qy22jiFhXi1eQ==\n\n'
    'abcde'
  ),
)
@clibase.CLIErrorGuard
def RSADecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  ciphertext: str = typer.Argument(..., help='Ciphertext to decrypt'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during encryption)',
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  key_path: str = safetrans.RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = safetrans.LoadObj(key_path, config.protect, rsa.RSAPrivateKey)
  aad_bytes: bytes | None = safetrans.BytesFromText(aad, config.input_format) if aad else None
  ct: bytes = safetrans.BytesFromText(ciphertext, config.input_format)
  pt: bytes = rsa_priv.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(safetrans.BytesToText(pt, config.output_format))


@rsa_app.command(
  'sign',
  help='Sign `message` with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i bin -o b64 -p rsa-key.priv rsa sign "xyz"\n\n'
    '91TS7gC6LORiL…6RD23Aejsfxlw=='  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
def RSASign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  message: str = typer.Argument(..., help='Message to sign'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  key_path: str = safetrans.RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = safetrans.LoadObj(key_path, config.protect, rsa.RSAPrivateKey)
  aad_bytes: bytes | None = safetrans.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = safetrans.BytesFromText(message, config.input_format)
  sig: bytes = rsa_priv.Sign(pt, associated_data=aad_bytes)
  config.console.print(safetrans.BytesToText(sig, config.output_format))


@rsa_app.command(
  'verify',
  help='Verify `signature` for `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i b64 -p rsa-key.pub rsa verify -- eHl6 '
    '91TS7gC6LORiL…6RD23Aejsfxlw==\n\n'  # cspell:disable-line
    'RSA signature: OK\n\n'
    '$ poetry run safetrans -i b64 -p rsa-key.pub rsa verify -- eLl6 '
    '91TS7gC6LORiL…6RD23Aejsfxlw==\n\n'  # cspell:disable-line
    'RSA signature: INVALID'
  ),
)
@clibase.CLIErrorGuard
def RSAVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  message: str = typer.Argument(..., help='Message that was signed earlier'),
  signature: str = typer.Argument(..., help='Putative signature for `message`'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during signing)',
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  key_path: str = safetrans.RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = safetrans.LoadObj(key_path, config.protect, rsa.RSAPublicKey)
  aad_bytes: bytes | None = safetrans.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = safetrans.BytesFromText(message, config.input_format)
  sig: bytes = safetrans.BytesFromText(signature, config.input_format)
  config.console.print(
    'RSA signature: '
    + ('[green]OK[/]' if rsa_pub.Verify(pt, sig, associated_data=aad_bytes) else '[red]INVALID[/]')
  )


# ================================== "DSA" COMMAND =================================================


dsa_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'DSA (Digital Signature Algorithm) asymmetric signing/verifying. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples). '
    'All non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. '
    'Attention: if you provide `-a`/`--aad` (associated data, AAD), '
    'you will need to provide the same AAD when decrypting/verifying and it is NOT included '
    'in the `signature` returned by these methods! '
    'No measures are taken here to prevent timing attacks.'
  ),
)
safetrans.app.add_typer(dsa_app, name='dsa')


@dsa_app.command(
  'shared',
  help=(
    'Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is '
    'the first step in key generation. `q-bits` should be larger than the secrets that '
    'will be protected and `p-bits` should be much larger than `q-bits` (e.g. 4096/544). '
    'The shared key can safely be used by any number of users to generate their '
    'private/public key pairs (with the `new` command). The shared keys are "public".'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -p dsa-key dsa shared --p-bits 128 --q-bits 32  '
    '# NEVER use such a small key: example only!\n\n'
    "DSA shared key saved to 'dsa-key.shared'"
  ),
)
@clibase.CLIErrorGuard
def DSAShared(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  p_bits: int = typer.Option(
    4096,
    '-b',
    '--p-bits',
    min=16,
    help='Prime modulus (`p`) size in bits, ≥16; the default (4096) is a safe size',
  ),
  q_bits: int = typer.Option(
    544,
    '-q',
    '--q-bits',
    min=8,
    help=(
      'Prime modulus (`q`) size in bits, ≥8; the default (544) is a safe size ***IFF*** you '
      'are protecting symmetric keys or regular hashes'
    ),
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  base_path: str = safetrans.RequireKeyPath(config, 'dsa')
  dsa_shared: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(p_bits, q_bits)
  safetrans.SaveObj(dsa_shared, base_path + '.shared', config.protect)
  config.console.print(f'DSA shared key saved to {base_path + ".shared"!r}')


@dsa_app.command(
  'new',
  help='Generate an individual DSA private/public key pair from a shared key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -p dsa-key dsa new\n\n'
    "DSA private/public keys saved to 'dsa-key.priv/.pub'"
  ),
)
@clibase.CLIErrorGuard
def DSANew(*, ctx: click.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: safetrans.TransConfig = ctx.obj
  base_path: str = safetrans.RequireKeyPath(config, 'dsa')
  dsa_shared: dsa.DSASharedPublicKey = safetrans.LoadObj(
    base_path + '.shared', config.protect, dsa.DSASharedPublicKey
  )
  dsa_priv: dsa.DSAPrivateKey = dsa.DSAPrivateKey.New(dsa_shared)
  dsa_pub: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(dsa_priv)
  safetrans.SaveObj(dsa_priv, base_path + '.priv', config.protect)
  safetrans.SaveObj(dsa_pub, base_path + '.pub', config.protect)
  config.console.print(f'DSA private/public keys saved to {base_path + ".priv/.pub"!r}')


@dsa_app.command(
  'sign',
  help='Sign message with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i bin -o b64 -p dsa-key.priv dsa sign "xyz"\n\n'
    'yq8InJVpViXh9…BD4par2XuA='
  ),
)
@clibase.CLIErrorGuard
def DSASign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  message: str = typer.Argument(..., help='Message to sign'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be separately sent to receiver/stored)',
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  key_path: str = safetrans.RequireKeyPath(config, 'dsa')
  dsa_priv: dsa.DSAPrivateKey = safetrans.LoadObj(key_path, config.protect, dsa.DSAPrivateKey)
  aad_bytes: bytes | None = safetrans.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = safetrans.BytesFromText(message, config.input_format)
  sig: bytes = dsa_priv.Sign(pt, associated_data=aad_bytes)
  config.console.print(safetrans.BytesToText(sig, config.output_format))


@dsa_app.command(
  'verify',
  help='Verify `signature` for `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run safetrans -i b64 -p dsa-key.pub dsa verify -- '
    'eHl6 yq8InJVpViXh9…BD4par2XuA=\n\n'
    'DSA signature: OK\n\n'
    '$ poetry run safetrans -i b64 -p dsa-key.pub dsa verify -- '
    'eLl6 yq8InJVpViXh9…BD4par2XuA=\n\n'
    'DSA signature: INVALID'
  ),
)
@clibase.CLIErrorGuard
def DSAVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: click.Context,
  message: str = typer.Argument(..., help='Message that was signed earlier'),
  signature: str = typer.Argument(..., help='Putative signature for `message`'),
  aad: str = typer.Option(
    '',
    '-a',
    '--aad',
    help='Associated data (optional; has to be exactly the same as used during signing)',
  ),
) -> None:
  config: safetrans.TransConfig = ctx.obj
  key_path: str = safetrans.RequireKeyPath(config, 'dsa')
  dsa_pub: dsa.DSAPublicKey = safetrans.LoadObj(key_path, config.protect, dsa.DSAPublicKey)
  aad_bytes: bytes | None = safetrans.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = safetrans.BytesFromText(message, config.input_format)
  sig: bytes = safetrans.BytesFromText(signature, config.input_format)
  config.console.print(
    'DSA signature: '
    + ('[green]OK[/]' if dsa_pub.Verify(pt, sig, associated_data=aad_bytes) else '[red]INVALID[/]')
  )
