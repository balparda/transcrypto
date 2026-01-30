# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""core/bid.py unittest.

Run with:
  poetry run pytest -vvv tests/core/bid_test.py
"""

from __future__ import annotations

from unittest import mock

import pytest

from tests import util
from transcrypto.core import bid, key
from transcrypto.utils import base


@pytest.mark.parametrize(
  ('secret', 'public_hash', 'bid_str'),
  [
    pytest.param(
      b'a',
      '711f48ea38b803f8d2026846e7a8fb637879e818f60f768594bc91f061f23c00'
      '4187183c2d8c81c3b67feb534e5cad90b3d9eae9488a525dd037eccac9512f2f',
      'PrivateBid512(PublicBid512(public_key=eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4'
      'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==, public_hash=711f48ea38b803f8d2026846e7a8fb637879e818f6'
      '0f768594bc91f061f23c004187183c2d8c81c3b67feb534e5cad90b3d9eae9488a525dd037eccac9512f2f), '
      'private_key=81e396cb…, secret_bid=1f40fc92…)',
      id='a',
    ),
    pytest.param(
      b'secret',
      'ab13b41fe50fef61483f2ce495ca5af1e173245811ef8610023d61b0d12d3f52'
      'd9c1b92388fec771dc4601bc36c4ddffe713e64532c01eb8936e29e06d10f936',
      'PrivateBid512(PublicBid512(public_key=eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4'
      'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==, public_hash=ab13b41fe50fef61483f2ce495ca5af1e173245811'
      'ef8610023d61b0d12d3f52d9c1b92388fec771dc4601bc36c4ddffe713e64532c01eb8936e29e06d10f936), '
      'private_key=81e396cb…, secret_bid=bd2b1aaf…)',
      id='secret',
    ),
    pytest.param(
      b'longer secret value with spaces',
      '5f25720c817a89c446e51ce56e64643aa5343cb1898904ea0e45b8ad5f4caabc'
      'aba091fb7e122bfff8d8b54855fcaa27e0f962d98c8eebae3a7765393c0fdf6a',
      'PrivateBid512(PublicBid512(public_key=eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4'
      'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==, public_hash=5f25720c817a89c446e51ce56e64643aa5343cb189'
      '8904ea0e45b8ad5f4caabcaba091fb7e122bfff8d8b54855fcaa27e0f962d98c8eebae3a7765393c0fdf6a), '
      'private_key=81e396cb…, secret_bid=826df62c…)',
      id='longer secret value with spaces',
    ),
  ],
)
@mock.patch('transcrypto.utils.saferandom.RandBytes', autospec=True)
def test_Bid_with_mock(
  randbytes: mock.MagicMock, secret: bytes, public_hash: str, bid_str: str
) -> None:
  """Test."""
  randbytes.side_effect = [b'x' * 64, b'y' * 64]
  priv: bid.PrivateBid512 = bid.PrivateBid512.New(secret)
  pub: bid.PublicBid512 = bid.PublicBid512.Copy(priv)
  assert base.BytesToHex(pub.public_hash) == public_hash
  priv_s = str(priv)
  assert priv_s == bid_str
  assert priv_s == repr(priv) and str(pub) == repr(pub)
  assert pub.VerifyBid(b'y' * 64, secret)
  assert not pub.VerifyBid(b'y' * 64, secret + b'x')
  assert not pub.VerifyBid(b'z' * 64, secret)
  assert randbytes.call_args_list == [mock.call(64), mock.call(64)]


@pytest.mark.stochastic
@pytest.mark.parametrize(
  'secret',
  [
    b'a',
    b'secret',
    b'longer secret value with spaces',
  ],
)
def test_Bid(secret: bytes) -> None:
  """Test."""
  priv1: bid.PrivateBid512 = bid.PrivateBid512.New(secret)
  priv2: bid.PrivateBid512 = bid.PrivateBid512.New(secret)
  pub: bid.PublicBid512 = bid.PublicBid512.Copy(priv1)
  util.TestCryptoKeyEncoding(priv1, bid.PrivateBid512)
  util.TestCryptoKeyEncoding(pub, bid.PublicBid512)
  assert pub.VerifyBid(priv1.private_key, secret)
  assert not pub.VerifyBid(priv1.private_key, secret + b'x')
  assert not pub.VerifyBid(priv2.private_key, secret)
  assert priv1.public_key != priv2.public_key  # this could fail with probability 1 in 2**512...
  assert priv1.private_key != priv2.private_key
  assert priv1.public_hash != priv2.public_hash
  assert priv2.VerifyBid(priv2.private_key, secret)


def test_Bid_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid public_key or public_hash'):
    bid.PublicBid512(public_key=b'key', public_hash=b'hash')
  with pytest.raises(base.InputError, match='invalid private_key or secret_bid'):
    bid.PrivateBid512(
      public_key=b'k' * 64, public_hash=b'h' * 64, private_key=b'priv', secret_bid=b'secret'
    )
  with pytest.raises(key.CryptoError, match='inconsistent bid'):
    bid.PrivateBid512(
      public_key=b'k' * 64, public_hash=b'h' * 64, private_key=b'p' * 64, secret_bid=b'secret'
    )
  with pytest.raises(base.InputError, match='invalid secret length'):
    bid.PrivateBid512.New(b'')
