#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""rsa.py unittest."""

from __future__ import annotations

# import pdb
import sys
from unittest import mock

import pytest

from src.transcrypto import base, rsa
from . import utils

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = rsa.__version__  # tests inherit version from module


@mock.patch('src.transcrypto.base.RandBits', autospec=True)
@mock.patch('src.transcrypto.modmath.NBitRandomPrimes', autospec=True)
def test_RSA_creation(prime: mock.MagicMock, randbits: mock.MagicMock) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='invalid bit length'):
    rsa.RSAPrivateKey.New(10)
  prime.side_effect = [
      {29, 43},   # attempt #1 → FAIL (φ multiple of 7)
      {29, 59},   # attempt #2 → FAIL (φ multiple of 7)
      {31, 41},   # attempt #3 → SUCCESS (11-bit modulus, gcd(7, φ) == 1)
      # Below: two more failing attempts to trip the failure counter when max=2
      {29, 43},   # attempt #1 after patching max → FAIL
      {29, 59},   # attempt #2 after patching max → FAIL → CryptoError
  ]
  randbits.side_effect = [31, 1000]
  private: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(11)
  with pytest.MonkeyPatch().context() as mp:
    mp.setattr(rsa, '_MAX_KEY_GENERATION_FAILURES', 2)
    with pytest.raises(base.CryptoError, match='failed key generation'):
      rsa.RSAPrivateKey.New(11)
  assert private == rsa.RSAPrivateKey(
      public_modulus=1271, encrypt_exp=7, modulus_p=31, modulus_q=41, decrypt_exp=343,
      remainder_p=13, remainder_q=23, q_inverse_p=28)
  ob_pair: rsa.RSAObfuscationPair = rsa.RSAObfuscationPair.New(private)
  assert private.modulus_size == ob_pair.modulus_size == 2
  assert ob_pair == rsa.RSAObfuscationPair(
      public_modulus=1271, encrypt_exp=7, random_key=1000, key_inverse=469)
  assert str(private) == (
      'RSAPrivateKey(RSAPublicKey(bits=11, public_modulus=BPc=, encrypt_exp=Bw==), '
      'modulus_p=4ff3abc9…, modulus_q=89970cf3…, decrypt_exp=b3e6c81d…)')
  assert private._DebugDump() == (
      'RSAPrivateKey(public_modulus=1271, encrypt_exp=7, modulus_p=31, modulus_q=41, '
      'decrypt_exp=343, remainder_p=13, remainder_q=23, q_inverse_p=28)')
  assert str(ob_pair) == (
      'RSAObfuscationPair(RSAPublicKey(bits=11, public_modulus=BPc=, encrypt_exp=Bw==), '
      'random_key=c597618a…, key_inverse=ee4b2e91…)')
  assert ob_pair._DebugDump() == (
      'RSAObfuscationPair(public_modulus=1271, encrypt_exp=7, random_key=1000, key_inverse=469)')
  assert prime.call_args_list == [mock.call(6, n_primes=2)] * 5
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
def test_RSA_raw(  # pylint: disable=too-many-locals,too-many-arguments,too-many-positional-arguments
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
  utils.TestCryptoKeyEncoding(private, rsa.RSAPrivateKey)
  utils.TestCryptoKeyEncoding(public, rsa.RSAPublicKey)
  utils.TestCryptoKeyEncoding(ob, rsa.RSAObfuscationPair)
  # do public key operations
  with pytest.raises(base.InputError, match='invalid message'):
    public.RawEncrypt(0)
  with pytest.raises(base.InputError, match='invalid message'):
    public.RawEncrypt(public_modulus)
  with pytest.raises(base.InputError, match='modulus too small for signing operations'):
    public.Verify(b'msg', b'sig')
  with pytest.raises(base.InputError, match='modulus too small for signing operations'):
    private.Sign(b'msg')
  with pytest.raises(base.CryptoError, match=r'hash output.*is out of range/invalid'):
    private._DomainSeparatedHash(b'msg', b'aad', b's' * 64)
  cypher: int = public.RawEncrypt(message)
  with pytest.raises(base.InputError, match='invalid message'):
    ob.ObfuscateMessage(0)
  with pytest.raises(base.InputError, match='invalid message'):
    ob.ObfuscateMessage(public_modulus)
  obfuscated: int = ob.ObfuscateMessage(message)
  assert (cypher, obfuscated) == (expected_cypher, expected_obfuscated)
  # do private key operations
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawSign(0)
  with pytest.raises(base.InputError, match='invalid message'):
    private.RawDecrypt(public_modulus)
  assert private.RawDecrypt(cypher) == message
  assert pow(cypher, private.decrypt_exp, private.public_modulus) == message
  signed: int = private.RawSign(message)
  obfuscated_signed: int = private.RawSign(obfuscated)
  assert (signed, obfuscated_signed) == (expected_signed, expected_obfuscated_signed)
  # check signatures with public key
  assert public.RawVerify(message, signed)
  assert not public.RawVerify(message, signed + 1)
  assert not public.RawVerify(message + 1, signed)
  assert ob.RevealOriginalSignature(message, obfuscated_signed) == signed
  with pytest.raises(base.CryptoError, match='obfuscated message was not signed'):
    ob.RevealOriginalSignature(message, obfuscated_signed + 1)
  with mock.patch('src.transcrypto.rsa.RSAPublicKey.RawVerify', autospec=True) as verify:
    verify.side_effect = [True, False]
    with pytest.raises(base.CryptoError, match='failed signature recovery'):
      ob.RevealOriginalSignature(message + 1, obfuscated_signed)


@pytest.mark.slow
@pytest.mark.veryslow
def test_RSA() -> None:
  """Test."""
  private: rsa.RSAPrivateKey = rsa.RSAPrivateKey.New(609)  # not too slow, not too fast
  public: rsa.RSAPublicKey = rsa.RSAPublicKey.Copy(private)
  assert private.modulus_size == public.modulus_size == 77
  assert public.public_modulus.bit_length() == 609
  aad: bytes | None
  for plaintext, aad, h_dsh in [  # parametrize here so we don't have to repeat key gen
      (b'', b'', 'bba5d24ecc975a54'),
      (b'abc', b'', 'e0f9ec10cef8e155'),
      (b'abcd', b'', '40b61d241baff180'),
      (b'abc', b'z', '768d7961ca8b6dc7'),
      (b'a0b1c2d3e4' * 10000000, b'e4d3c2b1a0' * 10000000, '5194fe1bf993ebbe'),
  ]:
    aad = aad if aad else None  # make sure we test both None and b''
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
    assert not public.Verify(plaintext, sg2, associated_data=aad)        # incorrect signature
    assert not public.Verify(plaintext, b'\x00' * (64 + 77), associated_data=aad)  # zero sig
    assert not public.Verify(plaintext + b' ', sg, associated_data=aad)  # incorrect message
    assert not public.Verify(b'bar', sg2)                                # incorrect message
    assert not public.Verify(plaintext, sg, associated_data=(aad if aad else b'') + b'x')  # AAD
    assert base.BytesToHex(base.IntToBytes(dsh))[:16] == h_dsh


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
