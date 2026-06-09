# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto CLI: Bid secret and SSS commands."""

from __future__ import annotations

import glob

import typer

from transcrypto import transcrypto
from transcrypto.cli import clibase
from transcrypto.core import bid, sss
from transcrypto.utils import base

# ================================== "BID" COMMAND =================================================


bid_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'Bidding on a `secret` so that you can cryptographically convince a neutral '
    'party that the `secret` that was committed to previously was not changed. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples). '
    'All non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. '
    'No measures are taken here to prevent timing attacks.'
  ),
)
transcrypto.app.add_typer(bid_app, name='bid')


@bid_app.command(
  'new',
  help=('Generate the bid files for `secret`.'),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin -p my-bid bid new "tomorrow it will rain"\n\n'
    "Bid private/public commitments saved to 'my-bid.priv/.pub'"
  ),
)
@clibase.CLIErrorGuard
def BidNew(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Input data to bid to, the protected "secret"'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'bid')
  secret_bytes: bytes = transcrypto.BytesFromText(secret, config.input_format)
  bid_priv: bid.PrivateBid512 = bid.PrivateBid512.New(secret_bytes)
  bid_pub: bid.PublicBid512 = bid.PublicBid512.Copy(bid_priv)
  transcrypto.SaveObj(bid_priv, base_path + '.priv', config.protect)
  transcrypto.SaveObj(bid_pub, base_path + '.pub', config.protect)
  config.console.print(f'Bid private/public commitments saved to {base_path + ".priv/.pub"!r}')


@bid_app.command(
  'verify',
  help=('Verify the bid files for correctness and reveal the `secret`.'),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -o bin -p my-bid bid verify\n\n'
    'Bid commitment: OK\n\n'
    'Bid secret:\n\n'
    'tomorrow it will rain'
  ),
)
@clibase.CLIErrorGuard
def BidVerify(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'bid')
  bid_priv: bid.PrivateBid512 = transcrypto.LoadObj(
    base_path + '.priv', config.protect, bid.PrivateBid512
  )
  bid_pub: bid.PublicBid512 = transcrypto.LoadObj(
    base_path + '.pub', config.protect, bid.PublicBid512
  )
  bid_pub_expect: bid.PublicBid512 = bid.PublicBid512.Copy(bid_priv)
  config.console.print(
    'Bid commitment: '
    + (
      '[green]OK[/]'
      if (
        bid_pub.VerifyBid(bid_priv.private_key, bid_priv.secret_bid) and bid_pub == bid_pub_expect
      )
      else '[red]INVALID[/]'
    )
  )
  config.console.print('Bid secret:')
  config.console.print(transcrypto.BytesToText(bid_priv.secret_bid, config.output_format))


# ================================== "SSS" COMMAND =================================================


sss_app = typer.Typer(
  no_args_is_help=True,
  help=(
    'SSS (Shamir Shared Secret) secret sharing crypto scheme. '
    'All methods require file key(s) as `-p`/`--key-path` (see provided examples). '
    'All non-int inputs are raw, or you can use `--input-format <hex|b64|bin>`. '
    'No measures are taken here to prevent timing attacks.'
  ),
)
transcrypto.app.add_typer(sss_app, name='sss')


@sss_app.command(
  'new',
  help=(
    'Generate the private keys with `bits` prime modulus size and so that at least a '
    '`minimum` number of shares are needed to recover the secret. '
    'This key will be used to generate the shares later (with the `shares` command).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p sss-key sss new 3 --bits 64  '
    '# NEVER use such a small key: example only!\n\n'
    "SSS private/public keys saved to 'sss-key.priv/.pub'"
  ),
)
@clibase.CLIErrorGuard
def SSSNew(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  minimum: int = typer.Argument(
    ..., min=2, help='Minimum number of shares required to recover secret, ≥ 2'
  ),
  bits: int = typer.Option(
    1024,
    '-b',
    '--bits',
    min=16,
    help=(
      'Prime modulus (`p`) size in bits, ≥16; the default (1024) is a safe size ***IFF*** you '
      'are protecting symmetric keys; the number of bits should be comfortably larger '
      'than the size of the secret you want to protect with this scheme'
    ),
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = sss.ShamirSharedSecretPrivate.New(minimum, bits)
  sss_pub: sss.ShamirSharedSecretPublic = sss.ShamirSharedSecretPublic.Copy(sss_priv)
  transcrypto.SaveObj(sss_priv, base_path + '.priv', config.protect)
  transcrypto.SaveObj(sss_pub, base_path + '.pub', config.protect)
  config.console.print(f'SSS private/public keys saved to {base_path + ".priv/.pub"!r}')


@sss_app.command(
  'rawshares',
  help=(
    'Raw shares: Issue `count` private shares for an *integer* `secret` '
    '(BEWARE: no modern message wrapping, padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p sss-key sss rawshares 999 5\n\n'
    "SSS 5 individual (private) shares saved to 'sss-key.share.1…5'\n\n"
    '$ rm sss-key.share.2 sss-key.share.4  # this is to simulate only having shares 1,3,5'
  ),
)
@clibase.CLIErrorGuard
def SSSRawShares(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Integer secret to be protected, 1≤`secret`<*modulus*'),
  count: int = typer.Argument(
    ...,
    min=1,
    help=(
      'How many shares to produce; must be ≥ `minimum` used in `new` command or else the '
      '`secret` would become unrecoverable'
    ),
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = transcrypto.LoadObj(
    base_path + '.priv', config.protect, sss.ShamirSharedSecretPrivate
  )
  if count < sss_priv.minimum:
    raise base.InputError(
      f'count ({count}) must be >= minimum ({sss_priv.minimum}) to allow secret recovery'
    )
  secret_i: int = transcrypto.ParseInt(secret, min_value=1)
  for i, share in enumerate(sss_priv.RawShares(secret_i, max_shares=count)):
    transcrypto.SaveObj(share, f'{base_path}.share.{i + 1}', config.protect)
  config.console.print(
    f'SSS {count} individual (private) shares saved to {base_path + ".share.1…" + str(count)!r}'
  )


@sss_app.command(
  'rawrecover',
  help=(
    'Raw recover *integer* secret from shares; will use any available shares '
    'that were found (BEWARE: no modern message wrapping, padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p sss-key sss rawrecover\n\n'
    "Loaded SSS share: 'sss-key.share.3'\n\n"
    "Loaded SSS share: 'sss-key.share.5'\n\n"
    "Loaded SSS share: 'sss-key.share.1'  # using only 3 shares: number 2/4 are missing\n\n"
    'Secret:\n\n'
    '999'
  ),
)
@clibase.CLIErrorGuard
def SSSRawRecover(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'sss')
  sss_pub: sss.ShamirSharedSecretPublic = transcrypto.LoadObj(
    base_path + '.pub', config.protect, sss.ShamirSharedSecretPublic
  )
  subset: list[sss.ShamirSharePrivate] = []
  for fname in glob.glob(base_path + '.share.*'):  # noqa: PTH207
    subset.append(transcrypto.LoadObj(fname, config.protect, sss.ShamirSharePrivate))
    config.console.print(f'Loaded SSS share: {fname!r}')
  config.console.print('Secret:')
  config.console.print(sss_pub.RawRecoverSecret(subset))


@sss_app.command(
  'rawverify',
  help=(
    'Raw verify shares against a secret (private params; '
    'BEWARE: no modern message wrapping, padding or validation).'
  ),
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -p sss-key sss rawverify 999\n\n'
    "SSS share 'sss-key.share.3' verification: OK\n\n"
    "SSS share 'sss-key.share.5' verification: OK\n\n"
    "SSS share 'sss-key.share.1' verification: OK\n\n"
    '$ poetry run transcrypto -p sss-key sss rawverify 998\n\n'
    "SSS share 'sss-key.share.3' verification: INVALID\n\n"
    "SSS share 'sss-key.share.5' verification: INVALID\n\n"
    "SSS share 'sss-key.share.1' verification: INVALID"
  ),
)
@clibase.CLIErrorGuard
def SSSRawVerify(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Integer secret used to generate the shares, ≥ 1'),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = transcrypto.LoadObj(
    base_path + '.priv', config.protect, sss.ShamirSharedSecretPrivate
  )
  secret_i: int = transcrypto.ParseInt(secret, min_value=1)
  for fname in glob.glob(base_path + '.share.*'):  # noqa: PTH207
    share: sss.ShamirSharePrivate = transcrypto.LoadObj(
      fname, config.protect, sss.ShamirSharePrivate
    )
    config.console.print(
      f'SSS share {fname!r} verification: '
      f'{"OK" if sss_priv.RawVerifyShare(secret_i, share) else "INVALID"}'
    )


@sss_app.command(
  'shares',
  help='Shares: Issue `count` private shares for a `secret`.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -i bin -p sss-key sss shares "abcde" 5\n\n'
    "SSS 5 individual (private) shares saved to 'sss-key.share.1…5'\n\n"
    '$ rm sss-key.share.2 sss-key.share.4  # this is to simulate only having shares 1,3,5'
  ),
)
@clibase.CLIErrorGuard
def SSSShares(  # documentation is help/epilog/args # noqa: D103
  *,
  ctx: typer.Context,
  secret: str = typer.Argument(..., help='Secret to be protected'),
  count: int = typer.Argument(
    ...,
    help=(
      'How many shares to produce; must be ≥ `minimum` used in `new` command or else the '
      '`secret` would become unrecoverable'
    ),
  ),
) -> None:
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'sss')
  sss_priv: sss.ShamirSharedSecretPrivate = transcrypto.LoadObj(
    base_path + '.priv', config.protect, sss.ShamirSharedSecretPrivate
  )
  if count < sss_priv.minimum:
    raise base.InputError(
      f'count ({count}) must be >= minimum ({sss_priv.minimum}) to allow secret recovery'
    )
  pt: bytes = transcrypto.BytesFromText(secret, config.input_format)
  for i, data_share in enumerate(sss_priv.MakeDataShares(pt, count)):
    transcrypto.SaveObj(data_share, f'{base_path}.share.{i + 1}', config.protect)
  config.console.print(
    f'SSS {count} individual (private) shares saved to {base_path + ".share.1…" + str(count)!r}'
  )


@sss_app.command(
  'recover',
  help='Recover secret from shares; will use any available shares that were found.',
  epilog=(
    'Example:\n\n\n\n'
    '$ poetry run transcrypto -o bin -p sss-key sss recover\n\n'
    "Loaded SSS share: 'sss-key.share.3'\n\n"
    "Loaded SSS share: 'sss-key.share.5'\n\n"
    "Loaded SSS share: 'sss-key.share.1'  # using only 3 shares: number 2/4 are missing\n\n"
    'Secret:\n\n'
    'abcde'
  ),
)
@clibase.CLIErrorGuard
def SSSRecover(*, ctx: typer.Context) -> None:  # documentation is help/epilog/args # noqa: D103
  config: transcrypto.TransConfig = ctx.obj
  base_path: str = transcrypto.RequireKeyPath(config, 'sss')
  subset: list[sss.ShamirSharePrivate] = []
  data_share: sss.ShamirShareData | None = None
  for fname in glob.glob(base_path + '.share.*'):  # noqa: PTH207
    share: sss.ShamirSharePrivate = transcrypto.LoadObj(
      fname, config.protect, sss.ShamirSharePrivate
    )
    subset.append(share)
    if isinstance(share, sss.ShamirShareData):
      data_share = share
    config.console.print(f'Loaded SSS share: {fname!r}')
  if data_share is None:
    raise base.InputError('no data share found among the available shares')
  pt: bytes = data_share.RecoverData(subset)
  config.console.print('Secret:')
  config.console.print(transcrypto.BytesToText(pt, config.output_format))
