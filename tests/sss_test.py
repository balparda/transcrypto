# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""sss.py unittest."""

from __future__ import annotations

from unittest import mock

import pytest

from transcrypto import aes, base, sss

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = sss.__version__  # tests inherit version from module


@pytest.mark.parametrize(
  ('minimum', 'modulus', 'polynomial', 'secret'),
  [
    (3, 907, [593, 787], 12),
    (2, 821, [673], 13),
    (3, 919737471227, [824794422841, 870689553269], 1234567890),
  ],
)
def test_ShamirSharedSecret_raw(
  minimum: int, modulus: int, polynomial: list[int], secret: int
) -> None:
  """Test."""
  # create keys and some shares
  private = sss.ShamirSharedSecretPrivate(minimum=minimum, modulus=modulus, polynomial=polynomial)
  public: sss.ShamirSharedSecretPublic = sss.ShamirSharedSecretPublic.Copy(private)
  shares: list[sss.ShamirSharePrivate] = list(private.RawShares(secret, max_shares=minimum + 2))
  data = sss.ShamirShareData(
    minimum=minimum,
    modulus=modulus,
    share_key=shares[0].share_key,
    share_value=shares[0].share_value,
    encrypted_data=b'x' * 128,
  )
  aes._TestCryptoKeyEncoding(private, sss.ShamirSharedSecretPrivate)
  aes._TestCryptoKeyEncoding(public, sss.ShamirSharedSecretPublic)
  aes._TestCryptoKeyEncoding(shares[0], sss.ShamirSharePrivate)
  aes._TestCryptoKeyEncoding(data, sss.ShamirShareData)
  # do operations
  assert public.RawRecoverSecret(shares) == secret
  assert public.RawRecoverSecret(shares[1:]) == secret
  assert public.RawRecoverSecret(shares[2:]) == secret
  assert public.RawRecoverSecret(shares[:-1]) == secret
  assert public.RawRecoverSecret(shares[:-2] + shares[:2]) == secret  # duplicate shares
  assert private.RawVerifyShare(secret, shares[0])
  assert private.RawVerifyShare(secret, shares[1])
  assert not private.RawVerifyShare(secret + 1, shares[0])
  with pytest.raises(base.CryptoError, match='unrecoverable secret'):
    public.RawRecoverSecret(shares[3:])
  if minimum > 2:
    assert public.RawRecoverSecret(shares[3:], force_recover=True) != secret
  with pytest.raises(base.InputError, match='invalid total_shares'):
    private.MakeDataShares(b'msg', 1)
  with pytest.raises(base.InputError, match='modulus too small for key operations'):
    private.MakeDataShares(b'msg', 5)
  with pytest.raises(base.InputError, match='modulus too small for key operations'):
    data.RecoverData(shares)
  bogus_share = sss.ShamirSharePrivate(  # same key, different value
    minimum=shares[0].minimum,
    modulus=shares[0].modulus,
    share_key=shares[0].share_key,
    share_value=shares[0].share_value - 1,
  )
  with pytest.raises(base.InputError, match='duplicated with conflicting value'):
    public.RawRecoverSecret([*shares[:-2], bogus_share])


@mock.patch('transcrypto.base.RandBits', autospec=True)
@mock.patch('transcrypto.base.RandShuffle', autospec=True)
@mock.patch('transcrypto.modmath.NBitRandomPrimes', autospec=True)
def test_ShamirSharedSecret_creation(
  prime: mock.MagicMock, shuffle: mock.MagicMock, randbits: mock.MagicMock
) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='at least 2 shares are needed'):
    sss.ShamirSharedSecretPrivate.New(1, 10)
  with pytest.raises(base.InputError, match='invalid bit length'):
    sss.ShamirSharedSecretPrivate.New(3, 9)
  prime.side_effect = [{19, 23, 31}]
  randbits.side_effect = [19, 20, 19, 20, 21, 20, 22, 535, 587, 498, 341]
  private: sss.ShamirSharedSecretPrivate = sss.ShamirSharedSecretPrivate.New(3, 10)
  assert private == sss.ShamirSharedSecretPrivate(minimum=3, modulus=31, polynomial=[19, 23])
  with pytest.raises(base.InputError, match='invalid secret'):
    private.RawShare(-1)
  with pytest.raises(base.InputError, match='invalid share_key'):
    private.RawShare(10, share_key=-1)
  assert private.RawShare(10) == sss.ShamirSharePrivate(
    minimum=3, modulus=31, share_key=20, share_value=11
  )
  with pytest.raises(base.InputError, match='invalid max_shares'):
    list(private.RawShares(20, max_shares=2))
  assert list(private.RawShares(20, max_shares=3)) == [
    sss.ShamirSharePrivate(minimum=3, modulus=31, share_key=20, share_value=21),
    sss.ShamirSharePrivate(minimum=3, modulus=31, share_key=21, share_value=22),
    sss.ShamirSharePrivate(minimum=3, modulus=31, share_key=22, share_value=7),
  ]
  private = sss.ShamirSharedSecretPrivate(minimum=3, modulus=907, polynomial=[593, 787])
  shares: list[sss.ShamirSharePrivate] = list(private.RawShares(12, max_shares=3))
  assert shares == [
    # the 535 value will generate a share_value of 0 and will be discarded
    sss.ShamirSharePrivate(minimum=3, modulus=907, share_key=587, share_value=758),
    sss.ShamirSharePrivate(minimum=3, modulus=907, share_key=498, share_value=555),
    sss.ShamirSharePrivate(minimum=3, modulus=907, share_key=341, share_value=439),
  ]
  assert str(private) == (
    'ShamirSharedSecretPrivate(ShamirSharedSecretPublic(bits=10, minimum=3, modulus=A4s=), '
    'polynomial=[48d0972e…, 9c72b540…])'
  )
  assert private._DebugDump() == (
    'ShamirSharedSecretPrivate(minimum=3, modulus=907, polynomial=[593, 787])'
  )
  assert str(shares[0]) == (
    'ShamirSharePrivate(ShamirSharedSecretPublic(bits=10, minimum=3, modulus=A4s=), '
    'share_key=ed467e80…, share_value=6be320c8…)'
  )
  assert shares[0]._DebugDump() == (
    'ShamirSharePrivate(minimum=3, modulus=907, share_key=587, share_value=758)'
  )
  assert prime.call_args_list == [mock.call(10, n_primes=3)]
  shuffle.assert_called_once_with([19, 23])
  assert randbits.call_args_list == [mock.call(4)] * 7 + [mock.call(9)] * 4


@pytest.mark.slow
def test_ShamirSharedSecret() -> None:
  """Test."""
  private: sss.ShamirSharedSecretPrivate = sss.ShamirSharedSecretPrivate.New(
    5, 512
  )  # not too slow, not too fast
  public: sss.ShamirSharedSecretPublic = sss.ShamirSharedSecretPublic.Copy(private)
  assert private.modulus_size == public.modulus_size == 64
  assert public.modulus.bit_length() == 512
  shares: list[sss.ShamirShareData] = []
  s_shares: list[sss.ShamirSharePrivate] = []
  for plaintext, n_shares in [  # parametrize here so we don't have to repeat key gen
    (b'', 8),
    (b'abc', 8),
    (b'a0b1c2d3e4' * 10000000, 7),
  ]:
    shares = private.MakeDataShares(plaintext, n_shares)
    assert len(shares) == n_shares
    s_shares = [sss.ShamirSharePrivate.CopyShare(s) for s in shares]
    base.RandShuffle(shares)  # mix them up
    base.RandShuffle(s_shares)  # mix them up
    assert shares[0].RecoverData(s_shares[:5]) == plaintext
    assert shares[1].RecoverData(shares[1:6]) == plaintext  # type:ignore
    with pytest.raises(base.CryptoError, match='unrecoverable secret'):
      shares[0].RecoverData(s_shares[:3])
  with mock.patch(
    'transcrypto.sss.ShamirSharedSecretPublic.RawRecoverSecret', autospec=True
  ) as rrs:
    rrs.return_value = 1 << 300
    with pytest.raises(base.CryptoError, match='recovered key out of range for 256-bit key'):
      shares[0].RecoverData(s_shares[:5])


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


def test_ShamirShareData_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match=r'AES256\+GCM SSS should have ≥32 bytes IV/CT/tag'):
    sss.ShamirShareData(minimum=3, modulus=7, share_key=2, share_value=6, encrypted_data=b'xyz')
  sss.ShamirShareData(minimum=3, modulus=7, share_key=2, share_value=6, encrypted_data=b'x' * 128)
