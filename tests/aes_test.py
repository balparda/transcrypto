#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""aes.py unittest."""

import base64
import collections
import concurrent.futures
import itertools
import pdb
import sys

import pytest

from src.transcrypto import base
from src.transcrypto import aes

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: str = base.__version__  # tests inherit version from module


def test_AESKey() -> None:
  """Test."""
  # constants that might break everything
  assert base.BytesToEncoded(aes._PASSWORD_SALT_256) == (
      'Y7Vv6SYO0_91KoajQU5DWOTY4-MbnbwW4R7BmAni88A=')  # fixed random salt: do NOT ever change!
  assert aes._PASSWORD_ITERATIONS == 2025103           # fixed iterations:  do NOT ever change!
  # failures
  with pytest.raises(base.InputError, match='invalid key256'):
    aes.AESKey(key256=b'abcd')
  with pytest.raises(base.InputError, match='empty passwords not allowed'):
    aes.AESKey.FromStaticPassword(' ')
  # password hash --- the FromStaticPassword() costs ~1 second CPU time!
  key = aes.AESKey.FromStaticPassword('daniel')
  assert key.encoded == '6gWMOO735KhgFFL1aekVdqm130scXWUT3cLWHmlg07Q='


@pytest.mark.parametrize('key, pth, ct1, ct101', [

    # values copied from Appendix B, page 16+ of:
    # <https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/aes/aesavs.pdf>
    # (it does not list the ct101, but it has the key, pth, and ct1 values)

    ('0000000000000000000000000000000000000000000000000000000000000000',
     '014730f80ac625fe84f026c60bfd547d',
     '5c9d844ed46f9885085e5d6a4f94c7d7', '922bb8a27bec3f16312c871744b90850'),

    ('0000000000000000000000000000000000000000000000000000000000000000',
     '0b24af36193ce4665f2825d7b4749c98',
     'a9ff75bd7cf6613d3731c77c3b6d0c04', '97ed71e1bd06c56ee02422abd9fa2935'),

    ('0000000000000000000000000000000000000000000000000000000000000000',
     '761c1fe41a18acf20d241650611d90f1',
     '623a52fcea5d443e48d9181ab32c7421', '604a75bd22f1af1a0d0dd91ec3bdb1ec'),

    ('0000000000000000000000000000000000000000000000000000000000000000',
     '8a560769d605868ad80d819bdba03771',
     '38f2c7ae10612415d27ca190d27da8b4', '0fef6fffdbcc5fcd8991b938d9f7120b'),

    ('0000000000000000000000000000000000000000000000000000000000000000',
     '91fbef2d15a97816060bee1feaa49afe',
     '1bc704f1bce135ceb810341b216d7abe', 'e062b4b12b70c07ee116eef714b94825'),

    ('c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558',
     '00000000000000000000000000000000',
     '46f2fb342d6f0ab477476fc501242c5f', '834d5271a5dfec5c0c4b642a00216c6c'),

    ('28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64',
     '00000000000000000000000000000000',
     '4bf3b0a69aeb6657794f2901b1440ad4', '048446e1b2b3cc7d8d1c350bdfc19864'),

    ('c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c',
     '00000000000000000000000000000000',
     '352065272169abf9856843927d0674fd', '8176ec1138a74695132230ba5b69b5c9'),

    ('984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627',
     '00000000000000000000000000000000',
     '4307456a9e67813b452e15fa8fffe398', '832ded2ca7b64773e4d7faae7a607ba5'),

    ('b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f',
     '00000000000000000000000000000000',
     '4663446607354989477a5c6f0f007ef4', '32b4286285fbe64d01cb71abbe6b5f94'),
     
])
def test_ECBEncoder(key: str, pth: str, ct1: str, ct101: str) -> None:
  """Test."""
  # create based on key and test basics
  key = aes.AESKey(key256=base.HexToBytes(key))
  encoder = key.ECBEncoder()
  assert encoder.name == 'AES/256-ECB/128'
  assert encoder.key_size == 256
  assert encoder.block_size == 128
  # first encryption
  pt: bytes = base.HexToBytes(pth)
  ct: bytes = encoder.Encrypt(pt)
  assert base.BytesToHex(ct) == ct1
  assert encoder.Decrypt(ct) == pt
  assert encoder.EncryptHex(pth) == ct1
  assert encoder.DecryptHex(ct1) == pth
  # stacked encryptions
  for _ in range(100):  # stack 100 encryptions
    ct = encoder.Encrypt(ct)
  assert base.BytesToHex(ct) == ct101
  for _ in range(101):  # unstack 100 plus the original encryption =101
    ct = encoder.Decrypt(ct)
  assert ct == pt       # we have to be back where we started
  # test error cases
  with pytest.raises(base.InputError, match='plaintext must be 16 bytes long'):
    encoder.Encrypt(b'\x00\x00\x00\x01\x00')
  with pytest.raises(base.InputError, match='ciphertext must be 16 bytes long'):
    encoder.Decrypt(b'\x00\x00\x00\x01\x00')


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
