#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""rsa.py unittest."""

# import pdb
import sys
from unittest import mock

import pytest

from src.transcrypto import base
from src.transcrypto import modmath
from src.transcrypto import rsa

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = rsa.__version__  # tests inherit version from module


@mock.patch('src.transcrypto.base.RandBits', autospec=True)
@mock.patch('src.transcrypto.modmath.NBitRandomPrime', autospec=True)
def test_RSA_creation(prime: mock.MagicMock, randbits: mock.MagicMock) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid bit length'):
    rsa.RSAPrivateKey.New(10)
  prime.side_effect = [17, 29, 29, 59, 31, 41,  # 2 failed tries
                       59, 31,                  # generates the key
                       17, 29, 29, 59, 31, 41]  # 22 failed tries for failed key generation
  randbits.side_effect = [31, 1000]
  private: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(11)
  with pytest.MonkeyPatch().context() as mp:
    mp.setattr(rsa, '_MAX_KEY_GENERATION_FAILURES', 2)
    with pytest.raises(base.CryptoError, match='failed key generation'):
      rsa.RSAPrivateKey.New(11)
  assert private == rsa.RSAPrivateKey(
      public_modulus=1829, encrypt_exp=7, modulus_p=31, modulus_q=59, decrypt_exp=1243,
      remainder_p=13, remainder_q=25, q_inverse_p=10)
  assert rsa.RSAObfuscationPair.New(rsa.RSAPublicKey.Copy(private)) == rsa.RSAObfuscationPair(
      public_modulus=1829, encrypt_exp=7, random_key=1000, key_inverse=1337)
  assert prime.call_args_list == [mock.call(n) for n in (5, 5, 6, 6, 5, 5, 5, 5, 5, 5, 6, 6, 5, 5)]
  assert randbits.call_args_list == [mock.call(10)] * 2


@pytest.mark.parametrize(
    'public_modulus, encrypt_exp, random_key, key_inverse, modulus_p, modulus_q, decrypt_exp, '
    'remainder_p, remainder_q, q_inverse_p, '
    'message, expected_cypher, expected_obfuscated, expected_signed, expected_obfuscated_signed',
    [
        (1357, 7, 695, 658, 23, 59, 547, 19, 25, 16, 2, 128, 1276, 601, 1096),
        (1357, 7, 695, 658, 23, 59, 547, 19, 25, 16, 10, 267, 952, 297, 151),
        (1357, 7, 695, 658, 23, 59, 547, 19, 25, 16, 20, 251, 547, 730, 1189),
        (37001, 7, 31618, 9087, 163, 227, 15691, 139, 97, 135, 10, 9730, 6006, 23858, 2857),
        (8628083, 65537, 8374570, 5137309, 2251, 3833, 4755473, 1223, 3793, 286,
         10, 4660799, 2979077, 6696343, 8467706),
    ])
def test_RSA(  # pylint: disable=too-many-locals,too-many-arguments,too-many-positional-arguments
    public_modulus: int, encrypt_exp: int, random_key: int, key_inverse: int,
    modulus_p: int, modulus_q: int, decrypt_exp: int, remainder_p: int,
    remainder_q: int, q_inverse_p: int,
    message: int, expected_cypher: int, expected_obfuscated: int,
    expected_signed: int, expected_obfuscated_signed: int) -> None:
  """Test."""
  # create keys
  ob = rsa.RSAObfuscationPair(
      public_modulus=public_modulus, encrypt_exp=encrypt_exp,
      random_key=random_key, key_inverse=key_inverse)
  private = rsa.RSAPrivateKey(
      public_modulus=public_modulus, encrypt_exp=encrypt_exp,
      modulus_p=modulus_p, modulus_q=modulus_q, decrypt_exp=decrypt_exp,
      remainder_p=remainder_p, remainder_q=remainder_q, q_inverse_p=q_inverse_p)
  public: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(private)
  # do public key operations
  with pytest.raises(base.InputError, match='invalid message'):
    public.Encrypt(0)
  with pytest.raises(base.InputError, match='invalid message'):
    public.Encrypt(public_modulus)
  cypher: int = public.Encrypt(message)
  with pytest.raises(base.InputError, match='invalid message'):
    ob.ObfuscateMessage(0)
  with pytest.raises(base.InputError, match='invalid message'):
    ob.ObfuscateMessage(public_modulus)
  obfuscated: int = ob.ObfuscateMessage(message)
  assert (cypher, obfuscated) == (expected_cypher, expected_obfuscated)
  # do private key operations
  with pytest.raises(base.InputError, match='invalid message'):
    private.Sign(0)
  with pytest.raises(base.InputError, match='invalid message'):
    private.Decrypt(public_modulus)
  assert private.Decrypt(cypher) == message
  assert modmath.ModExp(cypher, private.decrypt_exp, private.public_modulus) == message
  signed: int = private.Sign(message)
  obfuscated_signed: int = private.Sign(obfuscated)
  assert (signed, obfuscated_signed) == (expected_signed, expected_obfuscated_signed)
  # check signatures with public key
  assert public.VerifySignature(message, signed)
  assert not public.VerifySignature(message, signed + 1)
  assert not public.VerifySignature(message + 1, signed)
  assert ob.RevealOriginalSignature(message, obfuscated_signed) == signed
  with pytest.raises(base.CryptoError, match='obfuscated message was not signed'):
    ob.RevealOriginalSignature(message, obfuscated_signed + 1)
  with mock.patch(
      'src.transcrypto.rsa.RSAPublicKey.VerifySignature', autospec=True) as verify:
    verify.side_effect = [True, False]
    with pytest.raises(base.CryptoError, match='failed signature recovery'):
      ob.RevealOriginalSignature(message + 1, obfuscated_signed)


@mock.patch('src.transcrypto.base.RandBits', autospec=True)
def test_RSAObfuscationPair_New(mock_bits: mock.MagicMock) -> None:
  """Test."""
  mock_bits.side_effect = [3, 8, 3]
  public = rsa.RSAPublicKey(public_modulus=15, encrypt_exp=7)
  assert rsa.RSAObfuscationPair.New(public) == rsa.RSAObfuscationPair(
      public_modulus=15, encrypt_exp=7, random_key=8, key_inverse=2)
  with pytest.MonkeyPatch().context() as mp:
    mp.setattr(rsa, '_MAX_KEY_GENERATION_FAILURES', 1)
    with pytest.raises(base.CryptoError, match='failed key generation'):
      rsa.RSAObfuscationPair.New(public)
  assert mock_bits.call_args_list == [mock.call(3)] * 3


def test_RSAPublicKey_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid public_modulus'):
    rsa.RSAPublicKey(public_modulus=4, encrypt_exp=1)
  with pytest.raises(base.InputError, match='invalid public_modulus'):
    rsa.RSAPublicKey(public_modulus=7, encrypt_exp=1)
  with pytest.raises(base.InputError, match='invalid encrypt_exp'):
    rsa.RSAPublicKey(public_modulus=22, encrypt_exp=1)
  with pytest.raises(base.InputError, match='invalid encrypt_exp'):
    rsa.RSAPublicKey(public_modulus=22, encrypt_exp=22)
  rsa.RSAPublicKey(public_modulus=22, encrypt_exp=7)


def test_RSAObfuscationPair_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid keys'):
    rsa.RSAObfuscationPair(public_modulus=22, encrypt_exp=7, random_key=22, key_inverse=5)
  with pytest.raises(base.InputError, match='invalid keys'):
    rsa.RSAObfuscationPair(public_modulus=22, encrypt_exp=7, random_key=5, key_inverse=22)
  with pytest.raises(base.InputError, match='invalid keys'):
    rsa.RSAObfuscationPair(public_modulus=22, encrypt_exp=7, random_key=9, key_inverse=9)
  with pytest.raises(base.CryptoError, match='inconsistent keys'):
    rsa.RSAObfuscationPair(public_modulus=22, encrypt_exp=7, random_key=9, key_inverse=3)
  rsa.RSAObfuscationPair(public_modulus=22, encrypt_exp=7, random_key=9, key_inverse=5)


def test_RSAPrivateKey_invalid() -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid modulus_p or modulus_q'):
    rsa.RSAPrivateKey(
        public_modulus=1357, encrypt_exp=7, modulus_p=24, modulus_q=59, decrypt_exp=547,
        remainder_p=19, remainder_q=25, q_inverse_p=16)
  with pytest.raises(base.InputError, match='invalid modulus_p or modulus_q'):
    rsa.RSAPrivateKey(
        public_modulus=1357, encrypt_exp=7, modulus_p=17, modulus_q=19, decrypt_exp=547,
        remainder_p=19, remainder_q=25, q_inverse_p=16)
  with pytest.raises(base.InputError, match='invalid modulus_p or modulus_q'):
    rsa.RSAPrivateKey(
        public_modulus=1357, encrypt_exp=1279, modulus_p=23, modulus_q=59, decrypt_exp=547,
        remainder_p=19, remainder_q=25, q_inverse_p=16)
  with pytest.raises(base.InputError, match='invalid decrypt_exp'):
    rsa.RSAPrivateKey(
        public_modulus=1357, encrypt_exp=7, modulus_p=23, modulus_q=59, decrypt_exp=50,
        remainder_p=19, remainder_q=25, q_inverse_p=16)
  with pytest.raises(base.CryptoError, match=r'inconsistent modulus_p \* modulus_q'):
    rsa.RSAPrivateKey(
        public_modulus=1357, encrypt_exp=7, modulus_p=19, modulus_q=59, decrypt_exp=547,
        remainder_p=19, remainder_q=25, q_inverse_p=16)
  with pytest.raises(base.CryptoError, match='inconsistent exponents'):
    rsa.RSAPrivateKey(
        public_modulus=1357, encrypt_exp=7, modulus_p=23, modulus_q=59, decrypt_exp=546,
        remainder_p=19, remainder_q=25, q_inverse_p=16)
  with pytest.raises(base.InputError, match='trivial remainder_p/remainder_q/q_inverse_p'):
    rsa.RSAPrivateKey(
        public_modulus=1357, encrypt_exp=7, modulus_p=23, modulus_q=59, decrypt_exp=547,
        remainder_p=1, remainder_q=25, q_inverse_p=16)
  with pytest.raises(
      base.CryptoError, match='inconsistent speedup remainder_p/remainder_q/q_inverse_p'):
    rsa.RSAPrivateKey(
        public_modulus=1357, encrypt_exp=7, modulus_p=23, modulus_q=59, decrypt_exp=547,
        remainder_p=19, remainder_q=25, q_inverse_p=17)
  rsa.RSAPrivateKey(
      public_modulus=1357, encrypt_exp=7, modulus_p=23, modulus_q=59, decrypt_exp=547,
      remainder_p=19, remainder_q=25, q_inverse_p=16)


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
