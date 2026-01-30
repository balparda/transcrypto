# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""elgamal.py unittest."""

from __future__ import annotations

from unittest import mock

import pytest

from tests import util
from transcrypto import base, elgamal, modmath


@mock.patch('transcrypto.base.RandBits', autospec=True)
@mock.patch('transcrypto.modmath.NBitRandomPrimes', autospec=True)
def test_ElGamal_keys_creation(prime: mock.MagicMock, randbits: mock.MagicMock) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid bit length'):
    elgamal.ElGamalSharedPublicKey.NewShared(10)
  with pytest.raises(base.InputError, match='invalid bit length'):
    elgamal.ElGamalPrivateKey.New(elgamal.ElGamalSharedPublicKey(prime_modulus=37, group_base=8))
  prime.side_effect = [{1783}]
  randbits.side_effect = [146, 146, 409, 1546, 1546, 146, 148, 149]  # ModExp(146, 1546, 1783) == 2
  group: elgamal.ElGamalSharedPublicKey = elgamal.ElGamalSharedPublicKey.NewShared(11)
  assert group == elgamal.ElGamalSharedPublicKey(prime_modulus=1783, group_base=146)
  private: elgamal.ElGamalPrivateKey = elgamal.ElGamalPrivateKey.New(group)
  assert private == elgamal.ElGamalPrivateKey(
    prime_modulus=1783, group_base=146, individual_base=694, decrypt_exp=409
  )
  assert str(private) == (
    'ElGamalPrivateKey(ElGamalPublicKey(ElGamalSharedPublicKey(bits=11, '
    'prime_modulus=Bvc=, group_base=kg==), individual_base=ArY=), decrypt_exp=78168064…)'
  )
  assert private._DebugDump() == (
    'ElGamalPrivateKey(prime_modulus=1783, group_base=146, individual_base=694, decrypt_exp=409)'
  )
  with pytest.MonkeyPatch().context() as mp:
    mp.setattr(elgamal, '_MAX_KEY_GENERATION_FAILURES', 2)
    with pytest.raises(base.CryptoError, match='failed key generation'):
      elgamal.ElGamalPrivateKey.New(group)
  assert private._MakeEphemeralKey() == (149, 299)
  assert prime.call_args_list == [mock.call(11)]
  assert randbits.call_args_list == [mock.call(11)] * 8


@pytest.mark.parametrize(
  (
    'prime_modulus',
    'group_base',
    'individual_base',
    'decrypt_exp',
    'message',
    'ephemeral',
    'expected_cypher',
    'expected_signed',
  ),
  [
    (1783, 146, 694, 409, 10, 5, (108, 1691), (108, 434)),  # one individual, message==10
    (
      1783,
      146,
      694,
      409,
      11,
      5,
      (108, 612),
      (108, 1147),
    ),  # same ephemeral different message, first cypher is equal!
    (
      1783,
      146,
      694,
      409,
      10,
      919,
      (1260, 665),
      (1260, 370),
    ),  # different ephemeral same message, all changes
    (
      1783,
      146,
      895,
      66,
      10,
      5,
      (108, 1129),
      (108, 2),
    ),  # another individual of the same group, first cypher is equal!
    # same thing again, but with larger numbers:
    (
      10683855263626377773,
      4237160757485021964,
      6347817109416065590,
      7297922440270344179,
      10,
      40297678502457365,
      (8344081885661343574, 396610340005941186),
      (8344081885661343574, 10066062009891327152),
    ),  # one individual, message==10
    (
      10683855263626377773,
      4237160757485021964,
      6347817109416065590,
      7297922440270344179,
      11,
      40297678502457365,
      (8344081885661343574, 8983355584907637523),
      (8344081885661343574, 4776610262917878445),
    ),  # same ephemeral different message, first cypher is equal!
    (
      10683855263626377773,
      4237160757485021964,
      6347817109416065590,
      7297922440270344179,
      10,
      3984973770771867757,
      (4280206384080240986, 8684137473143402536),
      (4280206384080240986, 6323003457038402128),
    ),  # different ephemeral same message, all changes
    (
      10683855263626377773,
      4237160757485021964,
      4502163680704027637,
      8909246682740758948,
      10,
      40297678502457365,
      (8344081885661343574, 9614389933915395270),
      (8344081885661343574, 4646135738472651478),
    ),  # another individual of the same group, first cypher is equal!
  ],
)
@mock.patch('transcrypto.elgamal.ElGamalPublicKey._MakeEphemeralKey', autospec=True)
def test_ElGamal_raw(
  make_ephemeral: mock.MagicMock,
  prime_modulus: int,
  group_base: int,
  individual_base: int,
  decrypt_exp: int,
  message: int,
  ephemeral: int,
  expected_cypher: tuple[int, int],
  expected_signed: tuple[int, int],
) -> None:
  """Test."""
  # create keys
  shared = elgamal.ElGamalSharedPublicKey(prime_modulus=prime_modulus, group_base=group_base)
  private = elgamal.ElGamalPrivateKey(
    prime_modulus=prime_modulus,
    group_base=group_base,
    individual_base=individual_base,
    decrypt_exp=decrypt_exp,
  )
  public: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(private)
  util.TestCryptoKeyEncoding(shared, elgamal.ElGamalSharedPublicKey)
  util.TestCryptoKeyEncoding(private, elgamal.ElGamalPrivateKey)
  util.TestCryptoKeyEncoding(public, elgamal.ElGamalPublicKey)
  # do public key operations
  make_ephemeral.return_value = (ephemeral, modmath.ModInv(ephemeral, prime_modulus - 1))
  with pytest.raises(base.InputError, match='invalid message'):
    public.RawEncrypt(0)
  with pytest.raises(base.InputError, match='invalid message'):
    public.RawEncrypt(prime_modulus)
  cypher: tuple[int, int] = public.RawEncrypt(message)
  assert cypher == expected_cypher
  with pytest.raises(base.InputError, match='modulus too small for signing operations'):
    public.Verify(b'msg', b'sig')
  with pytest.raises(base.InputError, match='modulus too small for signing operations'):
    private.Sign(b'msg')
  with pytest.raises(base.CryptoError, match=r'hash output.*is out of range/invalid'):
    shared._DomainSeparatedHash(b'msg', b'aad', b's' * 64)
  # do private key operations
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawSign(0)
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawSign(prime_modulus)
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawDecrypt((-1, 3))
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawDecrypt((3, prime_modulus))
  assert private.RawDecrypt(cypher) == message
  signed: tuple[int, int] = private.RawSign(message)
  assert signed == expected_signed
  # check signatures with public key
  assert public.RawVerify(message, signed)
  assert not public.RawVerify(message, (signed[0], signed[1] + 1))
  assert not public.RawVerify(message + 1, signed)
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawVerify(0, (3, 3))
  with pytest.raises(base.InputError, match='invalid signature'):
    private.RawVerify(10, (1, 3))
  with pytest.raises(base.InputError, match='invalid signature'):
    private.RawVerify(10, (3, prime_modulus - 1))


@pytest.mark.slow
@pytest.mark.veryslow
def test_ElGamal() -> None:
  """Test."""
  shared: elgamal.ElGamalSharedPublicKey = elgamal.ElGamalSharedPublicKey.NewShared(
    609
  )  # not too slow, not too fast
  private: elgamal.ElGamalPrivateKey = elgamal.ElGamalPrivateKey.New(shared)
  public: elgamal.ElGamalPublicKey = elgamal.ElGamalPublicKey.Copy(private)
  assert private.modulus_size == shared.modulus_size == 77
  assert public.prime_modulus.bit_length() == 609
  aad: bytes | None
  for plaintext, aad, h_dsh in [  # parametrize here so we don't have to repeat key gen
    (b'', b'', '28ef0d5e5ccf4680'),
    (b'abc', b'', '89fced7b71b8a56f'),
    (b'abcd', b'', '2ab4c5f26e1a0c63'),
    (b'abc', b'z', '1d679318e921385d'),
    (b'a0b1c2d3e4' * 10000000, b'e4d3c2b1a0' * 10000000, '2dc8e0183a121cb9'),
  ]:
    aad = aad or None  # make sure we test both None and b''  # noqa: PLW2901
    ct: bytes = public.Encrypt(plaintext, associated_data=aad)
    dsh: int = public._DomainSeparatedHash(plaintext, aad, b's' * 64)
    sg: bytes = private.Sign(plaintext, associated_data=aad)
    sg2: bytes = private.Sign(b'foo')
    assert private.Decrypt(ct, associated_data=aad) == plaintext
    with pytest.raises(base.InputError, match='invalid ciphertext length'):
      private.Decrypt(b'v' * 108, associated_data=aad)
    assert public.Verify(plaintext, sg, associated_data=aad)
    assert public.Verify(b'foo', sg2)
    assert not public.Verify(plaintext, sg + b'x', associated_data=aad)  # wrong size
    assert not public.Verify(plaintext, sg2, associated_data=aad)  # incorrect signature
    assert not public.Verify(plaintext, b'\x00' * (64 + 77 + 77), associated_data=aad)  # zero sig
    assert not public.Verify(plaintext + b' ', sg, associated_data=aad)  # incorrect message
    assert not public.Verify(b'bar', sg2)  # incorrect message
    assert not public.Verify(plaintext, sg, associated_data=(aad or b'') + b'x')  # AAD
    assert base.BytesToHex(base.IntToBytes(dsh))[:16] == h_dsh


def test_ElGamalKey_invalid() -> None:
  """Test."""
  # ElGamalSharedPublicKey
  elgamal.ElGamalSharedPublicKey(prime_modulus=1693, group_base=83)
  with pytest.raises(base.InputError, match='invalid prime_modulus'):
    elgamal.ElGamalSharedPublicKey(prime_modulus=5, group_base=83)
  with pytest.raises(base.InputError, match='invalid prime_modulus'):
    elgamal.ElGamalSharedPublicKey(prime_modulus=1692, group_base=83)
  with pytest.raises(base.InputError, match='invalid group_base'):
    elgamal.ElGamalSharedPublicKey(prime_modulus=1693, group_base=2)
  with pytest.raises(base.InputError, match='invalid group_base'):
    elgamal.ElGamalSharedPublicKey(prime_modulus=1693, group_base=1692)
  # ElGamalPublicKey
  elgamal.ElGamalPublicKey(prime_modulus=1693, group_base=83, individual_base=156)
  with pytest.raises(base.InputError, match='invalid individual_base'):
    elgamal.ElGamalPublicKey(prime_modulus=1693, group_base=83, individual_base=2)
  with pytest.raises(base.InputError, match='invalid individual_base'):
    elgamal.ElGamalPublicKey(prime_modulus=1693, group_base=83, individual_base=1692)
  with pytest.raises(base.InputError, match='invalid individual_base'):
    elgamal.ElGamalPublicKey(prime_modulus=1693, group_base=83, individual_base=83)
  # ElGamalPrivateKey
  elgamal.ElGamalPrivateKey(
    prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=1007
  )
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    elgamal.ElGamalPrivateKey(prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=2)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    elgamal.ElGamalPrivateKey(
      prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=1692
    )
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    elgamal.ElGamalPrivateKey(
      prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=83
    )
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    elgamal.ElGamalPrivateKey(
      prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=156
    )
  with pytest.raises(base.CryptoError, match=r'inconsistent g.* == i'):
    elgamal.ElGamalPrivateKey(
      prime_modulus=1693, group_base=82, individual_base=156, decrypt_exp=1007
    )
