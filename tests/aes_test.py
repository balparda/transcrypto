#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""aes.py unittest."""

# import pdb
import sys
from unittest import mock

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
  key: aes.AESKey = aes.AESKey.FromStaticPassword('daniel')
  assert key.encoded == '6gWMOO735KhgFFL1aekVdqm130scXWUT3cLWHmlg07Q='  # cspell:disable-line


@pytest.mark.parametrize('s_key, pth, ct1, ct101', [

    # values copied from Appendix B, page 16+ of:
    # <https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/aes/aesavs.pdf>
    # (it does not list the ct101, but it has the key, pth, and ct1 values)

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        '014730f80ac625fe84f026c60bfd547d',
        '5c9d844ed46f9885085e5d6a4f94c7d7', '922bb8a27bec3f16312c871744b90850',
        id='k0-1'),

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        '0b24af36193ce4665f2825d7b4749c98',
        'a9ff75bd7cf6613d3731c77c3b6d0c04', '97ed71e1bd06c56ee02422abd9fa2935',
        id='k0-2'),

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        '761c1fe41a18acf20d241650611d90f1',
        '623a52fcea5d443e48d9181ab32c7421', '604a75bd22f1af1a0d0dd91ec3bdb1ec',
        id='k0-3'),

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        '8a560769d605868ad80d819bdba03771',
        '38f2c7ae10612415d27ca190d27da8b4', '0fef6fffdbcc5fcd8991b938d9f7120b',
        id='k0-4'),

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        '91fbef2d15a97816060bee1feaa49afe',
        '1bc704f1bce135ceb810341b216d7abe', 'e062b4b12b70c07ee116eef714b94825',
        id='k0-5'),

    pytest.param(
        'c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558',
        '00000000000000000000000000000000',
        '46f2fb342d6f0ab477476fc501242c5f', '834d5271a5dfec5c0c4b642a00216c6c',
        id='p0-1'),

    pytest.param(
        '28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64',
        '00000000000000000000000000000000',
        '4bf3b0a69aeb6657794f2901b1440ad4', '048446e1b2b3cc7d8d1c350bdfc19864',
        id='p0-2'),

    pytest.param(
        'c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c',
        '00000000000000000000000000000000',
        '352065272169abf9856843927d0674fd', '8176ec1138a74695132230ba5b69b5c9',
        id='p0-3'),

    pytest.param(
        '984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627',
        '00000000000000000000000000000000',
        '4307456a9e67813b452e15fa8fffe398', '832ded2ca7b64773e4d7faae7a607ba5',
        id='p0-4'),

    pytest.param(
        'b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f',
        '00000000000000000000000000000000',
        '4663446607354989477a5c6f0f007ef4', '32b4286285fbe64d01cb71abbe6b5f94',
        id='p0-5'),

])
def test_ECBEncoder(s_key: str, pth: str, ct1: str, ct101: str) -> None:
  """Test."""
  # create based on key and test first encryption
  key = aes.AESKey(key256=base.HexToBytes(s_key))
  encoder: aes.AESKey.ECBEncoderClass = key.ECBEncoder()
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
  with pytest.raises(base.InputError, match='AES/ECB does not support associated_data'):
    encoder.Encrypt(pt, associated_data=b'123')
  with pytest.raises(base.InputError, match='ciphertext must be 16 bytes long'):
    encoder.Decrypt(b'\x00\x00\x00\x01\x00')
  with pytest.raises(base.InputError, match='AES/ECB does not support associated_data'):
    encoder.Decrypt(ct, associated_data=b'123')


@pytest.mark.parametrize('s_key, pt, aad, ct1', [

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        b'', b'', 'I2oZ71hoQLKtVIsNWDZu_FEoF0Pq78bFdyqXgknrCKI=',
        id='k0-1'),

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000001',
        b'', b'', 'I2oZ71hoQLKtVIsNWDZu_LJFIDNkt_y3czbcZMQETjA=',  # cspell:disable-line
        id='k0-2'),

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        b'x', b'', 'I2oZ71hoQLKtVIsNWDZu_IImut2YA4tk3ZNG4AMAYCra',
        id='k0-3'),

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        b'', b'x', 'I2oZ71hoQLKtVIsNWDZu_BBZcmenlnrpBm877qw1UqM=',  # cspell:disable-line
        id='k0-4'),

    pytest.param(
        '28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64',
        b'', b'', 'I2oZ71hoQLKtVIsNWDZu_MlswKhdvwW38RH3KN1ZBcg=',
        id='28d-small-1'),

    pytest.param(
        '28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64',
        b'x', b'', 'I2oZ71hoQLKtVIsNWDZu_GykcdRON2-SUEv2KLWrmRuz',
        id='28d-small-2'),

    pytest.param(
        '28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64',
        b'', b'x', 'I2oZ71hoQLKtVIsNWDZu_CqXFMqjs7ABAkCh1bYp7XY=',
        id='28d-small-3'),

    pytest.param(
        'b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f',
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi012345678901234567890', b'',  # cspell:disable-line
        'I2oZ71hoQLKtVIsNWDZu_Dg_p-b-a9fqCnMXyvE3R5bh4DjMz9bgaZuV0-LBb37bhiEvOwvN101VVW5TAy'
        'VpV_jt5rCkcN4ULPGQBrcmoT7SeuCEMrxKlDsZPe8wi2CNmK_Bb7eikT_RAzwK2oOt',
        id='b43-large-1'),

    pytest.param(
        'b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f',
        b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi012345678901234567890',  # cspell:disable-line
        b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',  # cspell:disable-line
        'I2oZ71hoQLKtVIsNWDZu_Dg_p-b-a9fqCnMXyvE3R5bh4DjMz9bgaZuV0-LBb37bhiEvOwvN101VVW5TAy'
        'VpV_jt5rCkcN4ULPGQBrcmoT7SeuCEMrxKlDsZPe8wi2DpxUmrTHIhozsmav3Dp4Q-',  # cspell:disable-line
        id='b43-large-2'),

    pytest.param(
        '0000000000000000000000000000000000000000000000000000000000000000',
        b'x' * 1000, b'a' * 1000,
        'I2oZ71hoQLKtVIsNWDZu_IIeuJcyUsz654agtcQ9ZRM6pOwHw0WYyfoNAue4mZpLKEfLlsAItHvL1AY-Y7'
        'ILDyTdBnpT46Uev247WaVYsVAmnoe1_OVY9h6u6G20IjxrP7i3v20JKcIiI17ieQI2HD55MgjJEFHpJQiN'
        'HDfWgyqhYMgdJy9l_HSclAcPKp6jDQNJptVwDguSbvAMJUi8dnwBvFxzp56TiUmpm79ks_EKvB6f6lle6j'
        'pO7r2dI--b54elWb10S_lPOBcgWn3IEVq_E8aTke6XvXtfsjpl77Ci2O2QoiebYbws5jX3ngQ791PFv9rZ'
        'Fhc4lq7mRfbpXD4e3_JEdOoOv0Y4VwRgH5bBqhPQbwbkuX5x16eNcWiyw7YBsTYwjO_XixB0vD4RSlaksl'
        'Us5Fy21jzIf55XLlCenQKF1Mqp9KuoXjKQl3QjJ86JK2vVaNHTT5-mNUnwIdM8w7p1wJSlsSdRQ-YhiJ2a'
        'vk19SvEyxfXpk6xABy8zK51-styJkpGEuCV7koiZraHRlNwUaf-KwHV4QGvFWVnpA_SvkgRdu63uxEUOIF'
        'WUGyx5TqFtL9oABkYtH_u_z52v2FCzDeuzEngLb_TtiJ2GzYiTBS7v9EO4fwKLrgCOoXZ5cqpAipw0CeGy'
        'CnVTVN-fQpVq1o0dE23J-an9M4tIV8uP9y5w1NtUyvMR1Pv-ir7DXQVnF-lwl6c5_XDly3CaedqldLWkgw'
        'a2YPvpI95vjBdBRl_FKQGE_Q641HsyV_4u0TdZPAZBDMYMArFeS8rA0nVGcLHcYzSq5H73pD_duVkOewb8'
        'P7qm0Y4BQtAibEHzCCaHczkuKHg4i2Uw3k6UPCeJRQbuHgT-6QFRygTV9HayA_EG_viIIsjCQWUvpYDKgn'
        'a1fxtS7HRMinJWLTCmrzoSS5ZPcu7R5KwQb1tmp58VMlkqCvEXSinDLLVHIkXr2GQqmaXdDwV4_A7uTPED'  # cspell:disable-line
        '6FKYW8gO8xLVKcfrJNSCBa-rmQ0yXRhL6_hQDv-F-MJnfW5gacbaQlc5GhDmq7bCJsE7j66Hk9EejrBYqm'
        'DzNuU7f1HcwGetsfla7Pfb_LaMRa0pYXvkUQ8aksNCnaya49nrB0OHZH2-lEDcRAzbeuMY3EIPVk5mO2ep'
        'CHm4nUqnCZYmNpQBaXHOUPu6iGsOPHoC6MUSJi4p7QvElcQsIojxGTuiE7fKp0fsrxOon0ZT3A8K0CmBhJ'
        'H8OImsNO2xkkOH7ZvMSj89e1c6CTP2Pn4MRGCo6wBwSqsiGVxeO860NW8fNZ9roypcBUt6jpYEcTzfPODN'
        'srmSIoruqBtZViEv05wAGGJc1EwUGbd0-nRbAHmuIZ-UBNxRb11OJC6ehb8ZmSfa',
        id='k0-huge'),

    pytest.param(
        'b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f',
        b'x' * 1000, b'a' * 1000,
        'I2oZ71hoQLKtVIsNWDZu_CElvPrjdcj6EGgL1-8oV4f6_CXS0Mbxe4eIzf3RfmzImz8wKxrfxFlLSn5CET'  # cspell:disable-line
        'Z9Quf996K3ZMsCPODYT_1t7XOcNaDFevUA33dUc6Bwyig4LD6W7h0mo4vYzyuQpC8qadgbTCNABcLoMAVB'  # cspell:disable-line
        '6JAJPpDoyryiiWe_fUzfAzkXJts0T9XHvccraDCJcm3bzjHJTsfLHsF7lSfoCHhy3TZVCtNyLNYodzO6n2'  # cspell:disable-line
        'bKOMiMdgJSbJ7d0OqjUfHvsmO8DBuDvS2jstZW9sYtQpuhce-GT6XQ8POMjIj8nYfI8T6oLM7LewqmMvHj'  # cspell:disable-line
        'cV3f7VB0ypmJV7D9ZgTs4f6wkmk-Yc2Le7k1785VOxgzycS9DsMVusw-FAcqYi3oY6agsCagaU3BDbpQxi'  # cspell:disable-line
        'HkVVYmUEeS_ASAcsh7DT-hdJ7KqNalyves75ioSGOOH2DJndx5Pt3LwliIXWhEn7gzFzVFUP6bJZSUZkAq'  # cspell:disable-line
        '2KrxxNv7x-aiYq0HomJ4mHvHFbsYHpL5q0UIRCejZVFd7aFcea9IhrRSlH_OmKNhmYbVs-Hyu4f1TBP_lS'  # cspell:disable-line
        'a6lIMJJtZaZxu17gteLk9gACXOA_MzkTjgT4wcLIs4cvu8-vp0PHPa14vPb__rfwRUl4aSzUSIlxolwClt'  # cspell:disable-line
        'tAnkVU5iQ8vCnVIpapOoFA7HJDDfRHwkbtv2MQWiSyZu8htnzE-hWe4nrMNtA-2GlpmvYjIrmwC9d3Z-qM'  # cspell:disable-line
        'qGmZA-K00tfHIVqXI9pxRfrHsbo8MCgTRiX6B7jhhrOKc_yDiabOLXqzhYsBN2f3vrsx2BuILUilbCu70D'  # cspell:disable-line
        'EIL7t6Z39TQOAffJcdhlgAoN-UovuJbe87Hq8oyujfDjEueqpL8oue0hWb2BkfV7Ynh5N9L15PkULPxUZX'  # cspell:disable-line
        'yxZju-ct_Gd7vRJDLnGydqhBPyQUlclUMVNj-1WwUBmlRF5Ya30J5GVjA_1prQBB5K7p0evfWaGlWhplv7'  # cspell:disable-line
        'ORGwXtzhuNhZsQsgut7Cs5FzLbTzXlS4DYrDmwnnp200bwBVh-_eXSId34kU6V6Ed3-41T_B0YEOS0AHyZ'  # cspell:disable-line
        'LkZb22tuHRsP1qmNBBhhpLMc2lKerfWmnFTapjXLgBJysvW4hTczfVM1vmSRYsCbgh8_vRxngPsykcW5yh'  # cspell:disable-line
        'ZfL9nUk52tkcHxjvpuqbgaMkRcGd7HXL33-wIyZQHiJ7BFRWUYghUsteDuymo_SB3XZRKjRlALC5Jg76P3'  # cspell:disable-line
        'wIfJvOduZzZ-08s6FSyQOlLuPIr5Fo0VpEg4rGxruA1cE-sd2EfdhoWykf4Dztyq-30D0Ep0xruHRlQQD-'  # cspell:disable-line
        'nl5n8T8p_dGBAVcuFwKPxkWTFbNXI0BFUcNCUTPBU1e-8fO3Rv242f2Y6wTLOUNF',                   # cspell:disable-line
        id='b43-huge'),

])
@mock.patch('src.transcrypto.base.RandBytes', autospec=True)
def test_GCMEncoder(rand_bytes: mock.MagicMock, s_key: str, pt: bytes, aad: bytes, ct1: str) -> None:
  """Test."""
  rand_bytes.return_value = base.HexToBytes('236a19ef586840b2ad548b0d58366efc')
  # create based on key and test basics
  key = aes.AESKey(key256=base.HexToBytes(s_key))
  ct: bytes = key.Encrypt(pt, associated_data=aad)
  assert base.BytesToEncoded(ct) == ct1
  assert key.Decrypt(ct, associated_data=aad) == pt
  ct = key.Encrypt(pt)
  assert base.BytesToEncoded(ct) != ct1 if aad else base.BytesToEncoded(ct) == ct1
  assert key.Decrypt(ct) == pt
  # test error cases
  if aad:
    with pytest.raises(base.CryptoError, match='failed decryption'):
      key.Decrypt(ct, associated_data=aad)  # should not have aad
  ct = key.Encrypt(pt, associated_data=aad)
  if len(aad) > 2:
    with pytest.raises(base.CryptoError, match='failed decryption'):
      bad_aad: bytearray = bytearray(ct)
      bad_aad[2] ^= 0x01  # flip a bit in the AAD
      key.Decrypt(ct, associated_data=bytes(bad_aad))  # should not have aad
  with pytest.raises(base.CryptoError, match='failed decryption'):
    bad_ct: bytearray = bytearray(ct)
    bad_ct[2] ^= 0x01  # flip a bit in the IV/nonce part
    key.Decrypt(bytes(bad_ct), associated_data=aad)
  if len(ct) > 2:
    with pytest.raises(base.CryptoError, match='failed decryption'):
      bad_ct = bytearray(ct)
      bad_ct[18] ^= 0x01  # flip a bit in the ciphertext part
      key.Decrypt(bytes(bad_ct), associated_data=aad)
  with pytest.raises(base.CryptoError, match='failed decryption'):
    bad_ct = bytearray(ct)
    bad_ct[-2] ^= 0x01  # flip a bit in the tag part
    key.Decrypt(bytes(bad_ct), associated_data=aad)
  # check calls
  assert rand_bytes.call_args_list == [mock.call(16)] * 3


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
