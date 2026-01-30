# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""core/hashes.py unittest.

Run with:
  poetry run pytest -vvv tests/core/hashes_test.py
"""

from __future__ import annotations

import tempfile

import pytest
import typeguard

from transcrypto.core import hashes
from transcrypto.utils import base


@pytest.mark.parametrize(
  ('data', 'hash256', 'hash512'),
  [
    # values copied from <https://www.di-mgt.com.au/sha_testvectors.html>
    pytest.param(
      '',
      'e3b0c44298fc1c14 9afbf4c8996fb924 27ae41e4649b934c a495991b7852b855',
      'cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce'
      '47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e',
      id='empty',
    ),
    pytest.param(
      'abc',
      'ba7816bf8f01cfea 414140de5dae2223 b00361a396177a9c b410ff61f20015ad',
      'ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a'
      '2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f',
      id='abc',
    ),
    pytest.param(
      'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',  # cspell:disable-line
      '248d6a61d20638b8 e5c026930c3e6039 a33ce45964ff2167 f6ecedd419db06c1',
      '204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335'
      '96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445',
      id='NIST-long-1',
    ),
    pytest.param(
      'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi'
      'jklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
      'cf5b16a778af8380 036ce59e7b049237 0b249b11e8f07a51 afac45037afee9d1',
      '8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018'
      '501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909',
      id='NIST-long-2',
    ),
    pytest.param(
      'a' * 1000000,
      'cdc76e5c9914fb92 81a1c7e284d73e67 f1809a48a497200e 046d39ccc7112cd0',
      'e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb'
      'de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b',
      id='a*1_000_000',
    ),
  ],
)
def test_Hash(data: str, hash256: str, hash512: str) -> None:
  """Test."""
  bytes_data: bytes = data.encode('utf-8')
  # raw SHA-256
  h1: bytes = hashes.Hash256(bytes_data)
  assert len(h1) == 32
  assert base.BytesToHex(h1) == hash256.replace(' ', '')
  # raw SHA-512
  h2: bytes = hashes.Hash512(bytes_data)
  assert len(h2) == 64
  assert base.BytesToHex(h2) == hash512.replace(' ', '')
  # save data to temp file
  with tempfile.NamedTemporaryFile() as temp_file:
    temp_file.write(bytes_data)
    temp_file.flush()
    file_path: str = temp_file.name
    # SHA-256 file
    h3: bytes = hashes.FileHash(file_path)
    assert len(h3) == 32
    assert base.BytesToHex(h3) == hash256.replace(' ', '')
    # SHA-512 file
    h4: bytes = hashes.FileHash(file_path, digest='sha512')
    assert len(h4) == 64
    assert base.BytesToHex(h4) == hash512.replace(' ', '')
    # invalid digest type, but file exits
    with pytest.raises(base.InputError, match='unrecognized digest'):
      hashes.FileHash(file_path, digest='sha100')


def test_FileHash_missing_file() -> None:
  """Test."""
  with pytest.raises(base.InputError, match=r'file .* not found for hashing'):
    hashes.FileHash('/path/to/surely/not/exist-123')


@typeguard.suppress_type_checks
def test_ObfuscateSecret() -> None:
  """Test."""
  assert hashes.ObfuscateSecret('abc') == 'ddaf35a1…'
  assert hashes.ObfuscateSecret(b'abcd') == 'd8022f20…'
  assert hashes.ObfuscateSecret(123) == 'c2d03c6e…'
  with pytest.raises(base.InputError, match=r'invalid type for data.*float'):
    hashes.ObfuscateSecret(123.4)  # type:ignore
