#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""elgamal.py unittest."""

# import pdb
import sys
from unittest import mock

import pytest

from src.transcrypto import base
from src.transcrypto import modmath
from src.transcrypto import elgamal

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = elgamal.__version__  # tests inherit version from module


@mock.patch('src.transcrypto.base.RandBits', autospec=True)
@mock.patch('src.transcrypto.modmath.NBitRandomPrime', autospec=True)
def test_ElGamal_keys_creation(prime: mock.MagicMock, randbits: mock.MagicMock) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid bit length'):
    elgamal.ElGamalSharedPublicKey.New(10)
  with pytest.raises(base.InputError, match='invalid bit length'):
    elgamal.ElGamalPrivateKey.New(
        elgamal.ElGamalSharedPublicKey(prime_modulus=37, group_base=8))
  prime.side_effect = [1783]
  randbits.side_effect = [146, 146, 409, 1546, 1546, 146, 148, 149]  # ModExp(146, 1546, 1783) == 2
  group: elgamal.ElGamalSharedPublicKey = elgamal.ElGamalSharedPublicKey.New(11)
  assert group == elgamal.ElGamalSharedPublicKey(prime_modulus=1783, group_base=146)
  private: elgamal.ElGamalPrivateKey = elgamal.ElGamalPrivateKey.New(group)
  assert private == elgamal.ElGamalPrivateKey(
      prime_modulus=1783, group_base=146, individual_base=694, decrypt_exp=409)
  with pytest.MonkeyPatch().context() as mp:
    mp.setattr(elgamal, '_MAX_KEY_GENERATION_FAILURES', 2)
    with pytest.raises(base.CryptoError, match='failed key generation'):
      elgamal.ElGamalPrivateKey.New(group)
  assert private._MakeEphemeralKey() == (149, 299)
  assert prime.call_args_list == [mock.call(11)]
  assert randbits.call_args_list == [mock.call(10)] * 8


@pytest.mark.parametrize(
    'prime_modulus, group_base, individual_base, decrypt_exp, message, ephemeral, '
    'expected_cypher, expected_signed',
    [
        (1783, 146, 694, 409, 10, 5, (108, 1691), (108, 434)),     # one individual, message==10
        (1783, 146, 694, 409, 11, 5, (108, 612), (108, 1147)),     # same ephemeral different message, first cypher is equal!
        (1783, 146, 694, 409, 10, 919, (1260, 665), (1260, 370)),  # different ephemeral same message, all changes
        (1783, 146, 895, 66, 10, 5, (108, 1129), (108, 2)),        # another individual of the same group, first cypher is equal!
        # same thing again, but with larger numbers:
        (10683855263626377773, 4237160757485021964, 6347817109416065590, 7297922440270344179,
         10, 40297678502457365, (8344081885661343574, 396610340005941186),
         (8344081885661343574, 10066062009891327152)), # one individual, message==10
        (10683855263626377773, 4237160757485021964, 6347817109416065590, 7297922440270344179,
         11, 40297678502457365, (8344081885661343574, 8983355584907637523),
         (8344081885661343574, 4776610262917878445)),  # same ephemeral different message, first cypher is equal!
        (10683855263626377773, 4237160757485021964, 6347817109416065590, 7297922440270344179,
         10, 3984973770771867757, (4280206384080240986, 8684137473143402536),
         (4280206384080240986, 6323003457038402128)),  # different ephemeral same message, all changes
        (10683855263626377773, 4237160757485021964, 4502163680704027637, 8909246682740758948,
         10, 40297678502457365, (8344081885661343574, 9614389933915395270),
         (8344081885661343574, 4646135738472651478)),  # another individual of the same group, first cypher is equal!
    ])
@mock.patch('src.transcrypto.elgamal.ElGamalPublicKey._MakeEphemeralKey', autospec=True)
def test_ElGamal(
    make_ephemeral: mock.MagicMock, prime_modulus: int, group_base: int, individual_base: int,
    decrypt_exp: int, message: int, ephemeral: int, expected_cypher: tuple[int, int],
    expected_signed: tuple[int, int]) -> None:
  """Test."""
  # create keys
  spc = elgamal.ElGamalSharedPublicKey(prime_modulus=prime_modulus, group_base=group_base)
  private = elgamal.ElGamalPrivateKey(
      prime_modulus=prime_modulus, group_base=group_base,
      individual_base=individual_base, decrypt_exp=decrypt_exp)
  public = elgamal.ElGamalPublicKey.Copy(private)
  # do public key operations
  make_ephemeral.return_value = (
      ephemeral, elgamal.modmath.ModInv(ephemeral, prime_modulus - 1))
  with pytest.raises(base.InputError, match='invalid message'):
    public.Encrypt(0)
  with pytest.raises(base.InputError, match='invalid message'):
    public.Encrypt(prime_modulus)
  cypher: tuple[int, int] = public.Encrypt(message)
  assert cypher == expected_cypher
  # do private key operations
  with pytest.raises(base.InputError, match='invalid message'):
    private.Sign(0)
  with pytest.raises(base.InputError, match='invalid message'):
    private.Sign(prime_modulus)
  with pytest.raises(base.InputError, match='invalid message'):
    private.Decrypt((-1, 3))
  with pytest.raises(base.InputError, match='invalid message'):
    private.Decrypt((3, prime_modulus))
  assert private.Decrypt(cypher) == message
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
    private.VerifySignature(10, (3, prime_modulus - 1))


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
      prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=1007)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    elgamal.ElGamalPrivateKey(
        prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=2)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    elgamal.ElGamalPrivateKey(
        prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=1692)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    elgamal.ElGamalPrivateKey(
        prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=83)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    elgamal.ElGamalPrivateKey(
        prime_modulus=1693, group_base=83, individual_base=156, decrypt_exp=156)
  with pytest.raises(base.CryptoError, match=r'inconsistent g.* == i'):
    elgamal.ElGamalPrivateKey(
        prime_modulus=1693, group_base=82, individual_base=156, decrypt_exp=1007)


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
