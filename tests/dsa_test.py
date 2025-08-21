#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""dsa.py unittest."""

# import pdb
import sys
from unittest import mock

import pytest

from src.transcrypto import base
from src.transcrypto import dsa

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = dsa.__version__  # tests inherit version from module


@mock.patch('src.transcrypto.base.RandBits', autospec=True)
@mock.patch('src.transcrypto.base.RandInt', autospec=True)
@mock.patch('src.transcrypto.modmath.NBitRandomPrime', autospec=True)
def test_DSA_keys_creation(
    prime: mock.MagicMock, randint: mock.MagicMock, randbits: mock.MagicMock) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid q_bits length'):
    dsa.DSASharedPublicKey.NewShared(22, 10)
  with pytest.raises(base.InputError, match='invalid p_bits length'):
    dsa.DSASharedPublicKey.NewShared(21, 11)
  with pytest.raises(base.InputError, match='invalid q_bit length'):
    dsa.DSAPrivateKey.New(
        dsa.DSASharedPublicKey(prime_modulus=23, prime_seed=11, group_base=8))
  prime.side_effect = [1097, 1097]
  randint.side_effect = [3819, 3619, 3819, 3819]
  randbits.side_effect = [2498, 2508153, 807, 10, 10, 2508153, 10]
  group: dsa.DSASharedPublicKey = dsa.DSASharedPublicKey.NewShared(22, 11)
  assert group == dsa.DSASharedPublicKey(
      prime_modulus=3971141, prime_seed=1097, group_base=2508153)
  private: dsa.DSAPrivateKey = dsa.DSAPrivateKey.New(group)
  assert private == dsa.DSAPrivateKey(
      prime_modulus=3971141, prime_seed=1097, group_base=2508153,
      individual_base=1144026, decrypt_exp=807)
  with pytest.MonkeyPatch().context() as mp:
    mp.setattr(dsa, '_MAX_KEY_GENERATION_FAILURES', 2)
    with pytest.raises(base.CryptoError, match='failed primes generation'):
      dsa.NBitRandomDSAPrimes(22, 11)
    with mock.patch('src.transcrypto.modmath.ModExp', autospec=True) as mod_exp:
      mod_exp.return_value = 1144026
      with pytest.raises(base.CryptoError, match='failed key generation'):
        dsa.DSAPrivateKey.New(group)
  assert private._MakeEphemeralKey() == (10, 768)
  assert prime.call_args_list == [mock.call(11)] * 2
  assert randint.call_args_list == [mock.call(1913, 3821)] * 4
  assert randbits.call_args_list == [mock.call(21)] + [mock.call(10)] * 6


@pytest.mark.parametrize(
    'prime_modulus, prime_seed, group_base, individual_base, decrypt_exp, message, '
    'ephemeral, expected_signed',
    [
        (3971141, 1097, 2508153, 3924338, 470, 10, 603, (387, 107)),  # one individual, message==10
        (3971141, 1097, 2508153, 3924338, 470, 11, 603, (387, 731)),  # same ephemeral different message, first cypher is equal!
        (3971141, 1097, 2508153, 3924338, 470, 10, 486, (170, 345)),  # different ephemeral same message, all changes
        (3971141, 1097, 2508153, 1144026, 807, 10, 603, (387, 618)),  # another individual of the same group, first cypher is equal!
        # same thing again, but with larger numbers:
        (13778194025705455991, 2373232541, 6520293953707700537, 10027622456776030168, 615448826,
         10, 2055930860, (1621446112, 1167266683)),  # one individual, message==10
        (13778194025705455991, 2373232541, 6520293953707700537, 10027622456776030168, 615448826,
         11, 2055930860, (1621446112, 596280744)),   # same ephemeral different message, first cypher is equal!
        (13778194025705455991, 2373232541, 6520293953707700537, 10027622456776030168, 615448826,
         10, 1972759958, (1552560713, 1687943019)),  # different ephemeral same message, all changes
        (13778194025705455991, 2373232541, 6520293953707700537, 13541469208505301060, 426107211,
         10, 2055930860, (1621446112, 1461014680)),  # another individual of the same group, first cypher is equal!
    ])
@mock.patch('src.transcrypto.dsa.DSAPublicKey._MakeEphemeralKey', autospec=True)
def test_DSA(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    make_ephemeral: mock.MagicMock, prime_modulus: int, prime_seed: int, group_base: int,
    individual_base: int, decrypt_exp: int, message: int, ephemeral: int,
    expected_signed: tuple[int, int]) -> None:
  """Test."""
  # create keys
  dsa.DSASharedPublicKey(
      prime_modulus=prime_modulus, prime_seed=prime_seed, group_base=group_base)
  private = dsa.DSAPrivateKey(
      prime_modulus=prime_modulus, prime_seed=prime_seed, group_base=group_base,
      individual_base=individual_base, decrypt_exp=decrypt_exp)
  public = dsa.DSAPublicKey.Copy(private)
  make_ephemeral.return_value = (ephemeral, dsa.modmath.ModInv(ephemeral, prime_seed))
  # do private key operations
  with pytest.raises(base.InputError, match='invalid message'):
    private.Sign(0)
  with pytest.raises(base.InputError, match='invalid message'):
    private.Sign(prime_seed)
  signed: tuple[int, int] = private.Sign(message)
  assert signed == expected_signed
  # check signatures with public key
  assert public.VerifySignature(message, signed)
  assert not public.VerifySignature(message, (signed[0], signed[1] + 1))
  assert not public.VerifySignature(message + 1, signed)
  with pytest.raises(base.InputError, match='invalid message'):
    private.VerifySignature(0, (3, 3))
  with pytest.raises(base.InputError, match='invalid signature'):
    private.VerifySignature(10, (1, 3))
  with pytest.raises(base.InputError, match='invalid signature'):
    private.VerifySignature(10, (3, prime_seed))
  assert make_ephemeral.call_args_list == [mock.call(private)]


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
      prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=3924338)
  with pytest.raises(base.InputError, match='invalid individual_base'):
    dsa.DSAPublicKey(
        prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=2508153)
  with pytest.raises(base.InputError, match='invalid individual_base'):
    dsa.DSAPublicKey(
        prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=1097)
  with pytest.raises(base.InputError, match='invalid individual_base'):
    dsa.DSAPublicKey(
        prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=3971141)
  # DSAPrivateKey
  dsa.DSAPrivateKey(
      prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=1144026,
      decrypt_exp=807)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    dsa.DSAPrivateKey(
        prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=1144026,
        decrypt_exp=2)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    dsa.DSAPrivateKey(
        prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=1144026,
        decrypt_exp=1097)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    dsa.DSAPrivateKey(
        prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=1144026,
        decrypt_exp=2508153)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    dsa.DSAPrivateKey(
        prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=1144026,
        decrypt_exp=1144026)
  with pytest.raises(base.CryptoError, match=r'inconsistent g.* == i'):
    dsa.DSAPrivateKey(
        prime_modulus=3971141, prime_seed=1097, group_base=2508153, individual_base=1144028,
        decrypt_exp=807)


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
