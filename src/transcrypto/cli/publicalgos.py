# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto CLI: Public algorithms commands."""

from __future__ import annotations

import typer

from transcrypto import transcrypto
from transcrypto.cli import clibase
from transcrypto.core import dsa, elgamal, rsa

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
transcrypto.app.add_typer(rsa_app, name='rsa')


@rsa_app.command(
  'new',
  help=(
    'Generate RSA private/public key pair with `bits` modulus size (prime sizes will be `bits`/2).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p rsa-key rsa new --bits 64  '
    '# NEVER use such a small key: example only!\n\n'
    "RSA private/public keys saved to 'rsa-key.priv/.pub'"
  ),
)
@clibase.CLIErrorGuard
def RSANew(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  bits: int = typer.Option(
    3332,
    '-b',
    '--bits',
    min=16,
    help='Modulus size in bits, ≥16; the default (3332) is a safe size',
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(bits)
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(rsa_priv)
  transcrypto.SaveObj(rsa_priv, base_path + '.priv', config.protect)
  transcrypto.SaveObj(rsa_pub, base_path + '.pub', config.protect)
  config.console.print(f'RSA private/public keys saved to {base_path + ".priv/.pub"!r}')


@rsa_app.command(
  'rawencrypt',
  help=(
    'Raw encrypt *integer* `message` with public key (BEWARE: no OAEP/PSS padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p rsa-key.pub rsa rawencrypt 999\n\n'
    '6354905961171348600'
  ),
)
@clibase.CLIErrorGuard
def RSARawEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to encrypt, 1≤`message`<*modulus*'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  message_i: int = transcrypto.ParseInt(message, min_value=1)
  key_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(
    transcrypto.LoadObj(key_path, config.protect, rsa.RSAPublicKey)
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
    '$ poetry run transcrypto -p rsa-key.priv rsa rawdecrypt 6354905961171348600\n\n'
    '999'
  ),
)
@clibase.CLIErrorGuard
def RSARawDecrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  ciphertext: str = typer.Argument(
    ..., help='Integer ciphertext to decrypt, 1≤`ciphertext`<*modulus*'
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  ciphertext_i: int = transcrypto.ParseInt(ciphertext, min_value=1)
  key_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = transcrypto.LoadObj(key_path, config.protect, rsa.RSAPrivateKey)
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
@clibase.CLIErrorGuard
def RSARawSign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to sign, 1≤`message`<*modulus*'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  message_i: int = transcrypto.ParseInt(message, min_value=1)
  key_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = transcrypto.LoadObj(key_path, config.protect, rsa.RSAPrivateKey)
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
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  message_i: int = transcrypto.ParseInt(message, min_value=1)
  signature_i: int = transcrypto.ParseInt(signature, min_value=1)
  key_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(
    transcrypto.LoadObj(key_path, config.protect, rsa.RSAPublicKey)
  )
  config.console.print(
    'RSA signature: '
    + ('[green]OK[/]' if rsa_pub.RawVerify(message_i, signature_i) else '[red]INVALID[/]')
  )


@rsa_app.command(
  'encrypt',
  help='Encrypt `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin -o b64 -p rsa-key.pub rsa encrypt "abcde" -a "xyz"\n\n'
    'AO6knI6xwq6TGR…Qy22jiFhXi1eQ=='
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = transcrypto.LoadObj(key_path, config.protect, rsa.RSAPublicKey)
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(plaintext, config.input_format)
  ct: bytes = rsa_pub.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(ct, config.output_format))


@rsa_app.command(
  'decrypt',
  help='Decrypt `ciphertext` with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i b64 -o bin -p rsa-key.priv rsa decrypt -a eHl6 -- '
    'AO6knI6xwq6TGR…Qy22jiFhXi1eQ==\n\n'
    'abcde'
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = transcrypto.LoadObj(key_path, config.protect, rsa.RSAPrivateKey)
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  ct: bytes = transcrypto.BytesFromText(ciphertext, config.input_format)
  pt: bytes = rsa_priv.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(pt, config.output_format))


@rsa_app.command(
  'sign',
  help='Sign `message` with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin -o b64 -p rsa-key.priv rsa sign "xyz"\n\n'
    '91TS7gC6LORiL…6RD23Aejsfxlw=='  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_priv: rsa.RSAPrivateKey = transcrypto.LoadObj(key_path, config.protect, rsa.RSAPrivateKey)
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(message, config.input_format)
  sig: bytes = rsa_priv.Sign(pt, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(sig, config.output_format))


@rsa_app.command(
  'verify',
  help='Verify `signature` for `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i b64 -p rsa-key.pub rsa verify -- eHl6 '
    '91TS7gC6LORiL…6RD23Aejsfxlw==\n\n'  # cspell:disable-line
    'RSA signature: OK\n\n'
    '$ poetry run transcrypto -i b64 -p rsa-key.pub rsa verify -- eLl6 '
    '91TS7gC6LORiL…6RD23Aejsfxlw==\n\n'  # cspell:disable-line
    'RSA signature: INVALID'
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'rsa')
  rsa_pub: rsa.RSAPublicKey = transcrypto.LoadObj(key_path, config.protect, rsa.RSAPublicKey)
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(message, config.input_format)
  sig: bytes = transcrypto.BytesFromText(signature, config.input_format)
  config.console.print(
    'RSA signature: '
    + ('[green]OK[/]' if rsa_pub.Verify(pt, sig, associated_data=aad_bytes) else '[red]INVALID[/]')
  )


# ================================= "ELGAMAL" COMMAND ==============================================


eg_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'El-Gamal asymmetric cryptography. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples). '
    'All non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. '
    'Attention: if you provide `-a`/`--aad` (associated data, AAD), '
    'you will need to provide the same AAD when decrypting/verifying and it is NOT included '
    'in the `ciphertext`/CT or `signature` returned by these methods! '
    'No measures are taken here to prevent timing attacks.'
  ),
)
transcrypto.app.add_typer(eg_app, name='elgamal')


@eg_app.command(
  'shared',
  help=(
    'Generate a shared El-Gamal key with `bits` prime modulus size, which is the '
    'first step in key generation. '
    'The shared key can safely be used by any number of users to generate their '
    'private/public key pairs (with the `new` command). The shared keys are "public".'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p eg-key elgamal shared --bits 64  '
    '# NEVER use such a small key: example only!\n\n'
    "El-Gamal shared key saved to 'eg-key.shared'"
  ),
)
@clibase.CLIErrorGuard
def ElGamalShared(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  bits: int = typer.Option(
    3332,
    '-b',
    '--bits',
    min=16,
    help='Prime modulus (`p`) size in bits, ≥16; the default (3332) is a safe size',
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  shared_eg: elgamal.ElGamalSharedPublicKey = elgamal.ElGamalSharedPublicKey.NewShared(bits)
  transcrypto.SaveObj(shared_eg, base_path + '.shared', config.protect)
  config.console.print(f'El-Gamal shared key saved to {base_path + ".shared"!r}')


@eg_app.command(
  'new',
  help='Generate an individual El-Gamal private/public key pair from a shared key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p eg-key elgamal new\n\n'
    "El-Gamal private/public keys saved to 'eg-key.priv/.pub'"
  ),
)
@clibase.CLIErrorGuard
def ElGamalNew(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  shared_eg: elgamal.ElGamalSharedPublicKey = transcrypto.LoadObj(
    base_path + '.shared', config.protect, elgamal.ElGamalSharedPublicKey
  )
  eg_priv: elgamal.ElGamalPrivateKey = elgamal.ElGamalPrivateKey.New(shared_eg)
  eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(eg_priv)
  transcrypto.SaveObj(eg_priv, base_path + '.priv', config.protect)
  transcrypto.SaveObj(eg_pub, base_path + '.pub', config.protect)
  config.console.print(f'El-Gamal private/public keys saved to {base_path + ".priv/.pub"!r}')


@eg_app.command(
  'rawencrypt',
  help=(
    'Raw encrypt *integer* `message` with public key '
    '(BEWARE: no ECIES-style KEM/DEM padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p eg-key.pub elgamal rawencrypt 999\n\n'
    '2948854810728206041:15945988196340032688'
  ),
)
@clibase.CLIErrorGuard
def ElGamalRawEncrypt(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to encrypt, 1≤`message`<*modulus*'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  message_i: int = transcrypto.ParseInt(message, min_value=1)
  key_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(
    transcrypto.LoadObj(key_path, config.protect, elgamal.ElGamalPublicKey)
  )
  c1: int
  c2: int
  c1, c2 = eg_pub.RawEncrypt(message_i)
  config.console.print(f'{c1}:{c2}')


@eg_app.command(
  'rawdecrypt',
  help=(
    'Raw decrypt *integer* `ciphertext` with private key '
    '(BEWARE: no ECIES-style KEM/DEM padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p eg-key.priv elgamal rawdecrypt '
    '2948854810728206041:15945988196340032688\n\n'
    '999'
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  ciphertext_i: tuple[int, int] = transcrypto.ParseIntPairCLI(ciphertext)
  key_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = transcrypto.LoadObj(
    key_path, config.protect, elgamal.ElGamalPrivateKey
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
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p eg-key.priv elgamal rawsign 999\n\n'
    '4674885853217269088:14532144906178302633'
  ),
)
@clibase.CLIErrorGuard
def ElGamalRawSign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to sign, 1≤`message`<*modulus*'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  message_i: int = transcrypto.ParseInt(message, min_value=1)
  key_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = transcrypto.LoadObj(
    key_path, config.protect, elgamal.ElGamalPrivateKey
  )
  s1: int
  s2: int
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
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  message_i: int = transcrypto.ParseInt(message, min_value=1)
  signature_i: tuple[int, int] = transcrypto.ParseIntPairCLI(signature)
  key_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(
    transcrypto.LoadObj(key_path, config.protect, elgamal.ElGamalPublicKey)
  )
  config.console.print(
    'El-Gamal signature: '
    + ('[green]OK[/]' if eg_pub.RawVerify(message_i, signature_i) else '[red]INVALID[/]')
  )


@eg_app.command(
  'encrypt',
  help='Encrypt `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin -o b64 -p eg-key.pub elgamal encrypt "abcde" -a "xyz"\n\n'
    'CdFvoQ_IIPFPZLua…kqjhcUTspISxURg=='  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = transcrypto.LoadObj(
    key_path, config.protect, elgamal.ElGamalPublicKey
  )
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(plaintext, config.input_format)
  ct: bytes = eg_pub.Encrypt(pt, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(ct, config.output_format))


@eg_app.command(
  'decrypt',
  help='Decrypt `ciphertext` with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i b64 -o bin -p eg-key.priv elgamal decrypt -a eHl6 -- '
    'CdFvoQ_IIPFPZLua…kqjhcUTspISxURg==\n\n'  # cspell:disable-line
    'abcde'
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = transcrypto.LoadObj(
    key_path, config.protect, elgamal.ElGamalPrivateKey
  )
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  ct: bytes = transcrypto.BytesFromText(ciphertext, config.input_format)
  pt: bytes = eg_priv.Decrypt(ct, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(pt, config.output_format))


@eg_app.command(
  'sign',
  help='Sign message with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin -o b64 -p eg-key.priv elgamal sign "xyz"\n\n'
    'Xl4hlYK8SHVGw…0fCKJE1XVzA=='  # cspell:disable-line
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  eg_priv: elgamal.ElGamalPrivateKey = transcrypto.LoadObj(
    key_path, config.protect, elgamal.ElGamalPrivateKey
  )
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(message, config.input_format)
  sig: bytes = eg_priv.Sign(pt, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(sig, config.output_format))


@eg_app.command(
  'verify',
  help='Verify `signature` for `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i b64 -p eg-key.pub elgamal verify -- eHl6 '
    'Xl4hlYK8SHVGw…0fCKJE1XVzA==\n\n'  # cspell:disable-line
    'El-Gamal signature: OK\n\n'
    '$ poetry run transcrypto -i b64 -p eg-key.pub elgamal verify -- eLl6 '
    'Xl4hlYK8SHVGw…0fCKJE1XVzA==\n\n'  # cspell:disable-line
    'El-Gamal signature: INVALID'
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'elgamal')
  eg_pub: elgamal.ElGamalPublicKey = transcrypto.LoadObj(
    key_path, config.protect, elgamal.ElGamalPublicKey
  )
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(message, config.input_format)
  sig: bytes = transcrypto.BytesFromText(signature, config.input_format)
  config.console.print(
    'El-Gamal signature: '
    + ('[green]OK[/]' if eg_pub.Verify(pt, sig, associated_data=aad_bytes) else '[red]INVALID[/]')
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
transcrypto.app.add_typer(dsa_app, name='dsa')


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
    '$ poetry run transcrypto -p dsa-key dsa shared --p-bits 128 --q-bits 32  '
    '# NEVER use such a small key: example only!\n\n'
    "DSA shared key saved to 'dsa-key.shared'"
  ),
)
@clibase.CLIErrorGuard
def DSAShared(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
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
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'dsa')
  dsa_shared: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(p_bits, q_bits)
  transcrypto.SaveObj(dsa_shared, base_path + '.shared', config.protect)
  config.console.print(f'DSA shared key saved to {base_path + ".shared"!r}')


@dsa_app.command(
  'new',
  help='Generate an individual DSA private/public key pair from a shared key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p dsa-key dsa new\n\n'
    "DSA private/public keys saved to 'dsa-key.priv/.pub'"
  ),
)
@clibase.CLIErrorGuard
def DSANew(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'dsa')
  dsa_shared: dsa.DSASharedPublicKey = transcrypto.LoadObj(
    base_path + '.shared', config.protect, dsa.DSASharedPublicKey
  )
  dsa_priv: dsa.DSAPrivateKey = dsa.DSAPrivateKey.New(dsa_shared)
  dsa_pub: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(dsa_priv)
  transcrypto.SaveObj(dsa_priv, base_path + '.priv', config.protect)
  transcrypto.SaveObj(dsa_pub, base_path + '.pub', config.protect)
  config.console.print(f'DSA private/public keys saved to {base_path + ".priv/.pub"!r}')


@dsa_app.command(
  'rawsign',
  help=(
    'Raw sign *integer* message with private key (BEWARE: no ECDSA/EdDSA padding or validation). '
    'Output will 2 *integers* in a `s1:s2` format.'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p dsa-key.priv dsa rawsign 999\n\n'
    '2395961484:3435572290'
  ),
)
@clibase.CLIErrorGuard
def DSARawSign(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  message: str = typer.Argument(..., help='Integer message to sign, 1≤`message`<`q`'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'dsa')
  dsa_priv: dsa.DSAPrivateKey = transcrypto.LoadObj(key_path, config.protect, dsa.DSAPrivateKey)
  message_i: int = transcrypto.ParseInt(message, min_value=1)
  m: int = message_i % dsa_priv.prime_seed
  s1: int
  s2: int
  s1, s2 = dsa_priv.RawSign(m)
  config.console.print(f'{s1}:{s2}')


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
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'dsa')
  dsa_pub: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(
    transcrypto.LoadObj(key_path, config.protect, dsa.DSAPublicKey)
  )
  message_i: int = transcrypto.ParseInt(message, min_value=1)
  signature_i: tuple[int, int] = transcrypto.ParseIntPairCLI(signature)
  m: int = message_i % dsa_pub.prime_seed
  config.console.print(
    'DSA signature: ' + ('[green]OK[/]' if dsa_pub.RawVerify(m, signature_i) else '[red]INVALID[/]')
  )


@dsa_app.command(
  'sign',
  help='Sign message with private key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin -o b64 -p dsa-key.priv dsa sign "xyz"\n\n'
    'yq8InJVpViXh9…BD4par2XuA='
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'dsa')
  dsa_priv: dsa.DSAPrivateKey = transcrypto.LoadObj(key_path, config.protect, dsa.DSAPrivateKey)
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(message, config.input_format)
  sig: bytes = dsa_priv.Sign(pt, associated_data=aad_bytes)
  config.console.print(transcrypto.BytesToText(sig, config.output_format))


@dsa_app.command(
  'verify',
  help='Verify `signature` for `message` with public key.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i b64 -p dsa-key.pub dsa verify -- '
    'eHl6 yq8InJVpViXh9…BD4par2XuA=\n\n'
    'DSA signature: OK\n\n'
    '$ poetry run transcrypto -i b64 -p dsa-key.pub dsa verify -- '
    'eLl6 yq8InJVpViXh9…BD4par2XuA=\n\n'
    'DSA signature: INVALID'
  ),
)
@clibase.CLIErrorGuard
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
  config: transcrypto.TransConfig = ctx.obj
  key_path: str = transcrypto.RequireKeyPath(config, 'dsa')
  dsa_pub: dsa.DSAPublicKey = transcrypto.LoadObj(key_path, config.protect, dsa.DSAPublicKey)
  aad_bytes: bytes | None = transcrypto.BytesFromText(aad, config.input_format) if aad else None
  pt: bytes = transcrypto.BytesFromText(message, config.input_format)
  sig: bytes = transcrypto.BytesFromText(signature, config.input_format)
  config.console.print(
    'DSA signature: '
    + ('[green]OK[/]' if dsa_pub.Verify(pt, sig, associated_data=aad_bytes) else '[red]INVALID[/]')
  )
