#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""sss.py unittest."""

# import pdb
import sys
from unittest import mock

import pytest

from src.transcrypto import base
from src.transcrypto import sss

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = sss.__version__  # tests inherit version from module


@pytest.mark.parametrize('minimum, modulus, polynomial, secret', [
    (3, 907, [593, 787], 12),
    (2, 821, [673], 13),
    (3, 919737471227, [824794422841, 870689553269], 1234567890),
])
def test_ShamirSharedSecret(minimum: int, modulus: int, polynomial: list[int], secret: int) -> None:
  """Test."""
  # create keys and some shares
  private = sss.ShamirSharedSecretPrivate(
      minimum=minimum, modulus=modulus, polynomial=polynomial)
  public: sss.ShamirSharedSecretPublic = sss.ShamirSharedSecretPublic.Copy(private)
  shares: list[sss.ShamirSharePrivate] = list(
      private.Shares(secret, max_shares=minimum + 2))
  # do operations
  assert public.RecoverSecret(shares) == secret
  assert public.RecoverSecret(shares[1:]) == secret
  assert public.RecoverSecret(shares[2:]) == secret
  assert public.RecoverSecret(shares[:-1]) == secret
  assert public.RecoverSecret(shares[:-2] + shares[:2]) == secret  # duplicate shares
  assert private.VerifyShare(secret, shares[0])
  assert private.VerifyShare(secret, shares[1])
  assert not private.VerifyShare(secret + 1, shares[0])
  with pytest.raises(base.CryptoError, match='unrecoverable secret'):
    public.RecoverSecret(shares[3:])
  if minimum > 2:
    assert public.RecoverSecret(shares[3:], force_recover=True) != secret
  with pytest.raises(base.InputError, match='duplicated with conflicting value'):
    bogus_share = sss.ShamirSharePrivate(  # same key, different value
        minimum=shares[0].minimum, modulus=shares[0].modulus,
        share_key=shares[0].share_key, share_value=shares[0].share_value - 1)
    public.RecoverSecret(shares[:-2] + [bogus_share])


@mock.patch('secrets.SystemRandom.randint', autospec=True)
@mock.patch('secrets.SystemRandom.shuffle', autospec=True)
@mock.patch('src.transcrypto.modmath.NBitRandomPrime', autospec=True)
def test_ShamirSharedSecret_creation(
    prime: mock.MagicMock, shuffle: mock.MagicMock, randint: mock.MagicMock) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='at least 2 shares are needed'):
    sss.ShamirSharedSecretPrivate.New(1, 10)
  with pytest.raises(base.InputError, match='invalid bit length'):
    sss.ShamirSharedSecretPrivate.New(3, 9)
  prime.side_effect = [23, 19, 23, 31]
  randint.side_effect = [19, 20, 19, 20, 21, 20, 22, 535, 587, 498, 341]
  private: sss.ShamirSharedSecretPrivate = sss.ShamirSharedSecretPrivate.New(3, 10)
  assert private == sss.ShamirSharedSecretPrivate(
      minimum=3, modulus=31, polynomial=[19, 23])
  with pytest.raises(base.InputError, match='invalid secret'):
    private.Share(-1)
  with pytest.raises(base.InputError, match='invalid share_key'):
    private.Share(10, share_key=-1)
  assert private.Share(10) == sss.ShamirSharePrivate(
      minimum=3, modulus=31, share_key=20, share_value=11)
  with pytest.raises(base.InputError, match='invalid max_shares'):
    list(private.Shares(20, max_shares=2))
  assert list(private.Shares(20, max_shares=3)) == [
      sss.ShamirSharePrivate(minimum=3, modulus=31, share_key=20, share_value=21),
      sss.ShamirSharePrivate(minimum=3, modulus=31, share_key=21, share_value=22),
      sss.ShamirSharePrivate(minimum=3, modulus=31, share_key=22, share_value=7),
  ]
  private = sss.ShamirSharedSecretPrivate(minimum=3, modulus=907, polynomial=[593, 787])
  assert list(private.Shares(12, max_shares=3)) == [
      # the 535 value will generate a share_value of 0 and will be discarded
      sss.ShamirSharePrivate(minimum=3, modulus=907, share_key=587, share_value=758),
      sss.ShamirSharePrivate(minimum=3, modulus=907, share_key=498, share_value=555),
      sss.ShamirSharePrivate(minimum=3, modulus=907, share_key=341, share_value=439),
  ]
  assert prime.call_args_list == [mock.call(10)] * 4
  shuffle.assert_called_once_with(mock.ANY, [19, 23])
  assert randint.call_args_list == (
      [mock.call(mock.ANY, 14, 30)] * 7 + [mock.call(mock.ANY, 452, 906)] * 4)


def test_ShamirSharedSecretPublic_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid modulus or minimum'):
    sss.ShamirSharedSecretPublic(minimum=1, modulus=7)
  with pytest.raises(base.InputError, match='invalid modulus or minimum'):
    sss.ShamirSharedSecretPublic(minimum=2, modulus=1)
  with pytest.raises(base.InputError, match='invalid modulus or minimum'):
    sss.ShamirSharedSecretPublic(minimum=2, modulus=6)
  sss.ShamirSharedSecretPublic(minimum=2, modulus=7)


def test_ShamirSharedSecretPrivate_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid polynomial'):
    sss.ShamirSharedSecretPrivate(minimum=2, modulus=7, polynomial=[])
  with pytest.raises(base.InputError, match='invalid polynomial'):
    sss.ShamirSharedSecretPrivate(minimum=2, modulus=7, polynomial=[3, 3])
  with pytest.raises(base.InputError, match='invalid polynomial'):
    sss.ShamirSharedSecretPrivate(minimum=2, modulus=7, polynomial=[7])
  with pytest.raises(base.InputError, match='invalid polynomial'):
    sss.ShamirSharedSecretPrivate(minimum=2, modulus=7, polynomial=[6])
  sss.ShamirSharedSecretPrivate(minimum=2, modulus=7, polynomial=[5])


def test_ShamirSharePrivate_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid share'):
    sss.ShamirSharePrivate(minimum=3, modulus=7, share_key=0, share_value=6)
  with pytest.raises(base.InputError, match='invalid share'):
    sss.ShamirSharePrivate(minimum=3, modulus=7, share_key=2, share_value=0)
  with pytest.raises(base.InputError, match='invalid share'):
    sss.ShamirSharePrivate(minimum=3, modulus=7, share_key=2, share_value=7)
  sss.ShamirSharePrivate(minimum=3, modulus=7, share_key=2, share_value=6)


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
