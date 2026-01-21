# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""dsa.py unittest."""

from __future__ import annotations

from unittest import mock

import pytest

from transcrypto import aes, base, dsa, modmath

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = dsa.__version__  # tests inherit version from module


@mock.patch('transcrypto.base.RandBits', autospec=True)
@mock.patch('transcrypto.base.RandInt', autospec=True)
@mock.patch('transcrypto.modmath.NBitRandomPrimes', autospec=True)
def test_DSA_keys_creation(
  prime: mock.MagicMock, randint: mock.MagicMock, randbits: mock.MagicMock
) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid q_bits length'):
    dsa.DSASharedPublicKey.NewShared(22, 10)
  with pytest.raises(base.InputError, match='invalid p_bits length'):
    dsa.DSASharedPublicKey.NewShared(21, 11)
  with pytest.raises(base.InputError, match='invalid q_bit length'):
    dsa.DSAPrivateKey.New(dsa.DSASharedPublicKey(prime_modulus=23, prime_seed=11, group_base=8))
  prime.side_effect = [{1097}, {1097}]
  randint.side_effect = [3819, 3619, 3819, 3819, 3819, 3819]
  randbits.side_effect = [2498, 2508153, 807, 10, 10, 2508153, 10]
  group: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(22, 11)
  assert group == dsa.DSASharedPublicKey(prime_modulus=3971141, prime_seed=1097, group_base=2508153)
  private: dsa.DSAPrivateKey = dsa.DSAPrivateKey.New(group)
  assert private == dsa.DSAPrivateKey(
    prime_modulus=3971141,
    prime_seed=1097,
    group_base=2508153,
    individual_base=1144026,
    decrypt_exp=807,
  )
  assert str(private) == (
    'DSAPrivateKey(DSAPublicKey(DSASharedPublicKey('
    'bits=[22, 11], prime_modulus=PJhF, prime_seed=BEk=, '
    'group_base=JkV5), individual_base=EXTa), decrypt_exp=9444c8b9…)'
  )
  assert private._DebugDump() == (
    'DSAPrivateKey(prime_modulus=3971141, prime_seed=1097, group_base=2508153, '
    'individual_base=1144026, decrypt_exp=807)'
  )
  with pytest.MonkeyPatch().context() as mp:
    mp.setattr(dsa, '_MAX_KEY_GENERATION_FAILURES', 2)
    with mock.patch('transcrypto.modmath.gmpy2.powmod', autospec=True) as powmod:
      powmod.return_value = 1144026
      with pytest.raises(base.CryptoError, match='failed key generation'):
        dsa.DSAPrivateKey.New(group)
      assert powmod.call_args_list == [
        mock.call(2508153, 10, 3971141),
        mock.call(31, 992785, 3971141),
        mock.call(2508153, 10, 3971141),
        mock.call(31, 992785, 3971141),
      ]
  assert private._MakeEphemeralKey() == (10, 768)
  assert prime.call_args_list == [mock.call(11)] * 1
  assert randint.call_args_list == [mock.call(1913, 3821)] * 2
  assert randbits.call_args_list == [mock.call(21)] + [mock.call(10)] * 6


@pytest.mark.slow
@pytest.mark.veryslow
@pytest.mark.stochastic
def test_DSA_keys_creation_multiple() -> None:
  """Test."""
  pr1: set[tuple[int, int]] = {dsa.NBitRandomDSAPrimes(200, 50, serial=False)[:2] for _ in range(5)}
  pr2: set[tuple[int, int]] = {dsa.NBitRandomDSAPrimes(200, 50, serial=True)[:2] for _ in range(5)}
  assert len(pr1) == len(pr2) == 5
  pr1 = pr1.union(pr2)
  assert len(pr1) == 10
  assert all((modmath.IsPrime(p) and modmath.IsPrime(q) and p % q == 1) for p, q in pr1)


@pytest.mark.parametrize(
  (
    'prime_modulus',
    'prime_seed',
    'group_base',
    'individual_base',
    'decrypt_exp',
    'message',
    'ephemeral',
    'expected_signed',
  ),
  [
    (3971141, 1097, 2508153, 3924338, 470, 10, 603, (387, 107)),  # one individual, message==10
    (
      3971141,
      1097,
      2508153,
      3924338,
      470,
      11,
      603,
      (387, 731),
    ),  # same ephemeral different message, first cypher is equal!
    (
      3971141,
      1097,
      2508153,
      3924338,
      470,
      10,
      486,
      (170, 345),
    ),  # different ephemeral same message, all changes
    (
      3971141,
      1097,
      2508153,
      1144026,
      807,
      10,
      603,
      (387, 618),
    ),  # another individual of the same group, first cypher is equal!
    # same thing again, but with larger numbers:
    (
      13778194025705455991,
      2373232541,
      6520293953707700537,
      10027622456776030168,
      615448826,
      10,
      2055930860,
      (1621446112, 1167266683),
    ),  # one individual, message==10
    (
      13778194025705455991,
      2373232541,
      6520293953707700537,
      10027622456776030168,
      615448826,
      11,
      2055930860,
      (1621446112, 596280744),
    ),  # same ephemeral different message, first cypher is equal!
    (
      13778194025705455991,
      2373232541,
      6520293953707700537,
      10027622456776030168,
      615448826,
      10,
      1972759958,
      (1552560713, 1687943019),
    ),  # different ephemeral same message, all changes
    (
      13778194025705455991,
      2373232541,
      6520293953707700537,
      13541469208505301060,
      426107211,
      10,
      2055930860,
      (1621446112, 1461014680),
    ),  # another individual of the same group, first cypher is equal!
  ],
)
@mock.patch('transcrypto.dsa.DSAPublicKey._MakeEphemeralKey', autospec=True)
def test_DSA_raw(
  make_ephemeral: mock.MagicMock,
  prime_modulus: int,
  prime_seed: int,
  group_base: int,
  individual_base: int,
  decrypt_exp: int,
  message: int,
  ephemeral: int,
  expected_signed: tuple[int, int],
) -> None:
  """Test."""
  # create keys
  shared = dsa.DSASharedPublicKey(
    prime_modulus=prime_modulus, prime_seed=prime_seed, group_base=group_base
  )
  private = dsa.DSAPrivateKey(
    prime_modulus=prime_modulus,
    prime_seed=prime_seed,
    group_base=group_base,
    individual_base=individual_base,
    decrypt_exp=decrypt_exp,
  )
  public = dsa.DSAPublicKey.Copy(private)
  aes._TestCryptoKeyEncoding(shared, dsa.DSASharedPublicKey)
  aes._TestCryptoKeyEncoding(private, dsa.DSAPrivateKey)
  aes._TestCryptoKeyEncoding(public, dsa.DSAPublicKey)
  make_ephemeral.return_value = (ephemeral, modmath.ModInv(ephemeral, prime_seed))
  # do private key operations
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawSign(0)
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawSign(prime_seed)
  signed: tuple[int, int] = private.RawSign(message)
  assert signed == expected_signed
  with pytest.raises(base.InputError, match='modulus/seed too small for signing operations'):
    public.Verify(b'msg', b'sig')
  with pytest.raises(base.InputError, match='modulus/seed too small for signing operations'):
    private.Sign(b'msg')
  with pytest.raises(base.CryptoError, match=r'hash output.*is out of range/invalid'):
    shared._DomainSeparatedHash(b'msg', b'aad', b's' * 64)
  # check signatures with public key
  assert public.RawVerify(message, signed)
  assert not public.RawVerify(message, (signed[0], signed[1] + 1))
  assert not public.RawVerify(message + 1, signed)
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawVerify(0, (3, 3))
  with pytest.raises(base.InputError, match='invalid signature'):
    private.RawVerify(10, (1, 3))
  with pytest.raises(base.InputError, match='invalid signature'):
    private.RawVerify(10, (3, prime_seed))
  assert make_ephemeral.call_args_list == [mock.call(private)]


@pytest.mark.slow
@pytest.mark.veryslow
def test_DSA() -> None:
  """Test."""
  shared: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(
    800, 609
  )  # not too slow, not too fast
  private: dsa.DSAPrivateKey = dsa.DSAPrivateKey.New(shared)
  public: dsa.DSAPublicKey = dsa.DSAPublicKey.Copy(private)
  assert private.modulus_size == shared.modulus_size == (100, 77)
  assert public.prime_modulus.bit_length() == 800
  aad: bytes | None
  for plaintext, aad, h_dsh in [  # parametrize here so we don't have to repeat key gen
    (b'', b'', '49ef4ca3b3b36c9c'),
    (b'abc', b'', 'e548b51939a9f1c4'),
    (b'abcd', b'', 'c8e8bd6106084560'),
    (b'abc', b'z', '2d8f648a3bb059f3'),
    (b'a0b1c2d3e4' * 10000000, b'e4d3c2b1a0' * 10000000, '47110bca1034a8ff'),
  ]:
    aad = aad or None  # make sure we test both None and b''  # noqa: PLW2901
    dsh: int = public._DomainSeparatedHash(plaintext, aad, b's' * 64)
    sg: bytes = private.Sign(plaintext, associated_data=aad)
    sg2: bytes = private.Sign(b'foo')
    assert public.Verify(plaintext, sg, associated_data=aad)
    assert public.Verify(b'foo', sg2)
    assert not public.Verify(plaintext, sg + b'x', associated_data=aad)  # wrong size
    assert not public.Verify(plaintext, sg2, associated_data=aad)  # incorrect signature
    assert not public.Verify(plaintext, b'\x00' * (64 + 77 + 77), associated_data=aad)  # zero sig
    assert not public.Verify(plaintext + b' ', sg, associated_data=aad)  # incorrect message
    assert not public.Verify(b'bar', sg2)  # incorrect message
    assert not public.Verify(plaintext, sg, associated_data=(aad or b'') + b'x')  # AAD
    assert base.BytesToHex(base.IntToBytes(dsh))[:16] == h_dsh


def test_DSAKey_invalid() -> None:
  """Test."""
  # DSASharedPublicKey
  dsa.DSASharedPublicKey(prime_modulus=2470031, prime_seed=1777, group_base=1853719)
  with pytest.raises(base.InputError, match='invalid prime_seed'):
    dsa.DSASharedPublicKey(prime_modulus=2470031, prime_seed=5, group_base=1853719)
  with pytest.raises(base.InputError, match='invalid prime_seed'):
    dsa.DSASharedPublicKey(prime_modulus=2470031, prime_seed=1776, group_base=1853719)
  with pytest.raises(base.InputError, match='invalid prime_modulus'):
    dsa.DSASharedPublicKey(prime_modulus=19, prime_seed=1777, group_base=1853719)
  with pytest.raises(base.InputError, match='invalid prime_modulus'):
    dsa.DSASharedPublicKey(prime_modulus=2470032, prime_seed=1777, group_base=1853719)
  with pytest.raises(base.InputError, match='invalid prime_modulus'):
    dsa.DSASharedPublicKey(prime_modulus=2470031, prime_seed=19, group_base=1853719)
  with pytest.raises(base.InputError, match='invalid group_base'):
    dsa.DSASharedPublicKey(prime_modulus=2470031, prime_seed=1777, group_base=2470031)
  with pytest.raises(base.InputError, match='invalid group_base'):
    dsa.DSASharedPublicKey(prime_modulus=2470031, prime_seed=1777, group_base=1777)
  # DSAPublicKey
  dsa.DSAPublicKey(
    prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=3924338
  )
  with pytest.raises(base.InputError, match='invalid individual_base'):
    dsa.DSAPublicKey(
      prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=2508153
    )
  with pytest.raises(base.InputError, match='invalid individual_base'):
    dsa.DSAPublicKey(
      prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=1097
    )
  with pytest.raises(base.InputError, match='invalid individual_base'):
    dsa.DSAPublicKey(
      prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=3971141
    )
  # DSAPrivateKey
  dsa.DSAPrivateKey(
    prime_modulus=3971141,
    prime_seed=1097,
    group_base=2508153,
    individual_base=1144026,
    decrypt_exp=807,
  )
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    dsa.DSAPrivateKey(
      prime_modulus=3971141,
      prime_seed=1097,
      group_base=2508153,
      individual_base=1144026,
      decrypt_exp=2,
    )
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    dsa.DSAPrivateKey(
      prime_modulus=3971141,
      prime_seed=1097,
      group_base=2508153,
      individual_base=1144026,
      decrypt_exp=1097,
    )
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    dsa.DSAPrivateKey(
      prime_modulus=3971141,
      prime_seed=1097,
      group_base=2508153,
      individual_base=1144026,
      decrypt_exp=2508153,
    )
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    dsa.DSAPrivateKey(
      prime_modulus=3971141,
      prime_seed=1097,
      group_base=2508153,
      individual_base=1144026,
      decrypt_exp=1144026,
    )
  with pytest.raises(base.CryptoError, match=r'inconsistent g.* == i'):
    dsa.DSAPrivateKey(
      prime_modulus=3971141,
      prime_seed=1097,
      group_base=2508153,
      individual_base=1144028,
      decrypt_exp=807,
    )
