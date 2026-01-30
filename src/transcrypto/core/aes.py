# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto Advanced Encryption Standard (AES) library.

<https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>

<https://cryptography.io/en/latest/>

The Advanced Encryption Standard (AES), also known by its original name Rijndael
is a specification for the encryption of electronic data established by the
U.S. National Institute of Standards and Technology (NIST) in 2001.

We don't want to re-implement AES here, we will provide for good crypto
wrappers, consistent with the transcrypto style.
"""

from __future__ import annotations

import dataclasses
from typing import Self, cast

from cryptography import exceptions as crypt_exceptions
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.primitives import hashes as hazmat_hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.kdf import pbkdf2 as hazmat_pbkdf2

from transcrypto.core import hashes, key
from transcrypto.utils import base, saferandom

# these fixed salt/iterations are for password->key generation only; NEVER use them to
# build a database of passwords because it would not be safe; NEVER change them or the
# keys will change and previous databases/encryptions will become inconsistent/unreadable!
_PASSWORD_SALT_256: bytes = base.HexToBytes(
  '63b56fe9260ed3ff752a86a3414e4358e4d8e3e31b9dbc16e11ec19809e2f3c0'
)  # fixed random salt: do NOT ever change!
_PASSWORD_ITERATIONS = 2025103  # fixed iterations, purposefully huge: do NOT ever change!
assert base.BytesToEncoded(_PASSWORD_SALT_256) == 'Y7Vv6SYO0_91KoajQU5DWOTY4-MbnbwW4R7BmAni88A=', (  # noqa: S101
  'should never happen: constant'
)
assert _PASSWORD_ITERATIONS == (6075308 + 1) // 3, 'should never happen: constant'  # noqa: S101


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class AESKey(key.CryptoKey, key.Encryptor, key.Decryptor):
  """Advanced Encryption Standard (AES) 256 bits key (32 bytes).

  No measures are taken here to prevent timing attacks.

  Attributes:
    key256 (bytes): AES 256 bits key (32 bytes), so length is always 32

  """

  key256: bytes

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    if len(self.key256) != 32:  # noqa: PLR2004
      raise base.InputError(f'invalid key256: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the AESKey.

    Returns:
      string representation of AESKey without leaking secrets

    """
    return f'AESKey(key256={hashes.ObfuscateSecret(self.key256)})'

  @classmethod
  def FromStaticPassword(cls, str_password: str, /) -> Self:
    """Derive crypto key using string password.

    This is, purposefully, a very costly operation that should be cheap to execute once
    after the user typed a password, but costly for an attacker to run a dictionary campaign on.
    We do not use salt (or, more precisely, we use a fixed salt), as this is meant for direct use,
    not to store the key in a DB. To compensate, the number o iterations is set especially high:
    on the computer this was developed it takes ~1 sec to execute and is almost triple the
    recommended amount of 600,000 (see https://en.wikipedia.org/wiki/PBKDF2).

    The salt and the iteration number were randomly generated when this method was written
    so as to be unique to this implementation and not a standard one that can have a standard
    dictionary (i.e. attacks would have to generate a dictionary specific to this implementation).
    ON THE OTHER HAND, this only serves the purpose of generating keys from static passwords.
    NEVER use this method to save a database of keys. ONLY use it for direct user input.

    Docs: https://cryptography.io/en/latest/

    Args:
      str_password (str): Non-empty string password; empty spaces at start/end are IGNORED

    Returns:
      AESKey crypto key to use (URL-safe base64-encoded 32-byte key)

    Raises:
      base.InputError: empty password

    """
    str_password = str_password.strip()
    if not str_password:
      raise base.InputError('empty passwords not allowed, for safety reasons')
    kdf = hazmat_pbkdf2.PBKDF2HMAC(
      algorithm=hazmat_hashes.SHA256(),
      length=32,
      salt=_PASSWORD_SALT_256,
      iterations=_PASSWORD_ITERATIONS,
    )
    return cls(key256=kdf.derive(str_password.encode('utf-8')))

  class ECBEncoderClass(key.Encryptor, key.Decryptor):
    """The simplest encryption possible (UNSAFE if misused): 128 bit block AES-ECB, 256 bit key.

    Note: Due to ECB encoding, this class is only safe-ish for blocks of random-looking data,
    like hashes for example.

    Please DO **NOT** use this for regular cryptography. For regular crypto use Encrypt()/Decrypt().
    This class was specifically built to encode/decode 128 bit / 16 bytes blocks using a
    pre-existing key. No measures are taken here to prevent timing attacks.
    """

    def __init__(self, key256: AESKey, /) -> None:
      """Construct.

      Args:
        key256 (AESKey): key

      """
      self._cipher: ciphers.Cipher[modes.ECB] = ciphers.Cipher(
        algorithms.AES256(key256.key256),
        modes.ECB(),  # noqa: S305
      )
      alg: ciphers.BlockCipherAlgorithm = cast(
        'algorithms.BlockCipherAlgorithm',  # type: ignore
        self._cipher.algorithm,
      )
      assert alg.key_size == 256, (  # noqa: PLR2004, S101
        'should never happen: AES256+ECB should have 256 bits key'
      )
      assert alg.block_size == 128, (  # noqa: PLR2004, S101
        'should never happen: AES256+ECB should have 128 bits block'
      )

    def Encrypt(self, plaintext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
      """Encrypt a 128 bits block (16 bytes) `plaintext` and return `ciphertext` of 128 bits.

      Note: Due to ECB encoding, this method is only safe-ish for blocks of random-looking data,
      like hashes for example.

      Please DO **NOT** use this for regular cryptography.
      No measures are taken here to prevent timing attacks.

      Args:
        plaintext (bytes): Data to encrypt.
        associated_data (bytes, optional): DO NOT USE - not supported in ECB mode

      Returns:
        bytes: Ciphertext, a block of 128 bits (16 bytes)

      Raises:
        base.InputError: invalid inputs

      """
      if associated_data is not None:
        raise base.InputError('AES/ECB does not support associated_data')
      if len(plaintext) != 16:  # noqa: PLR2004
        raise base.InputError(f'plaintext must be 16 bytes long, got {len(plaintext)}')
      encryptor: ciphers.CipherContext = self._cipher.encryptor()
      return encryptor.update(plaintext) + encryptor.finalize()

    def Decrypt(self, ciphertext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
      """Decrypt a 128 bits block (16 bytes) `ciphertext` and return original 128 bits `plaintext`.

      Note: Due to ECB encoding, this method is only safe-ish for blocks of random-looking data,
      like hashes for example.

      Please DO **NOT** use this for regular cryptography.
      No measures are taken here to prevent timing attacks.

      Args:
        ciphertext (bytes): Data to decrypt (including any embedded nonce/tag if applicable)
        associated_data (bytes, optional): DO NOT USE - not supported in ECB mode

      Returns:
        bytes: Decrypted plaintext, a block of 128 bits (16 bytes)

      Raises:
        base.InputError: invalid inputs

      """
      if associated_data is not None:
        raise base.InputError('AES/ECB does not support associated_data')
      if len(ciphertext) != 16:  # noqa: PLR2004
        raise base.InputError(f'ciphertext must be 16 bytes long, got {len(ciphertext)}')
      decryptor: ciphers.CipherContext = self._cipher.decryptor()
      return decryptor.update(ciphertext) + decryptor.finalize()

    def EncryptHex(self, plaintext_hex: str, /) -> str:
      """Encrypt a 128 bits hexadecimal block, outputting also a 128 bits hexadecimal block.

      Note: Due to ECB encoding, this method is only safe-ish for blocks of random-looking data,
      like hashes for example.

      Args:
          plaintext_hex (str): plaintext hexadecimal block (length==32)

      Returns:
          str: encrypted hexadecimal block (length==32)

      """
      return base.BytesToHex(self.Encrypt(base.HexToBytes(plaintext_hex)))

    def EncryptHex256(self, plaintext_hex: str, /) -> str:
      """Encrypt a 256 bits hexadecimal block, outputting also a 256 bits hexadecimal block.

      Note: Due to ECB encoding, this method is only safe-ish for blocks of random-looking data,
      like hashes for example.

      Args:
          plaintext_hex (str): plaintext hexadecimal block (length==64)

      Returns:
          str: encrypted hexadecimal block (length==64)

      Raises:
          base.InputError: invalid inputs

      """
      if len(plaintext_hex) != 64:  # noqa: PLR2004
        raise base.InputError(f'plaintext_hex must be 64 chars long, got {len(plaintext_hex)}')
      return self.EncryptHex(plaintext_hex[:32]) + self.EncryptHex(plaintext_hex[32:])

    def DecryptHex(self, ciphertext_hex: str, /) -> str:
      """Decrypt a 128 bits hexadecimal block, outputting also a 128 bits hexadecimal block.

      Note: Due to ECB encoding, this method is only safe-ish for blocks of random-looking data,
      like hashes for example.

      Args:
          ciphertext_hex (str): encrypted hexadecimal block (length==32)

      Returns:
          str: plaintext hexadecimal block (length==32)

      """
      return base.BytesToHex(self.Decrypt(base.HexToBytes(ciphertext_hex)))

    def DecryptHex256(self, ciphertext_hex: str, /) -> str:
      """Decrypt a 256 bits hexadecimal block, outputting also a 256 bits hexadecimal block.

      Note: Due to ECB encoding, this method is only safe-ish for blocks of random-looking data,
      like hashes for example.

      Args:
          ciphertext_hex (str): encrypted hexadecimal block (length==64)

      Returns:
          str: plaintext hexadecimal block (length==64)

      Raises:
          base.InputError: invalid inputs

      """
      if len(ciphertext_hex) != 64:  # noqa: PLR2004
        raise base.InputError(f'ciphertext_hex must be 64 chars long, got {len(ciphertext_hex)}')
      return self.DecryptHex(ciphertext_hex[:32]) + self.DecryptHex(ciphertext_hex[32:])

  def ECBEncoder(self) -> AESKey.ECBEncoderClass:
    """Return a AESKey.ECBEncoderClass object using this key.

    Returns:
        AESKey.ECBEncoderClass: ECB encoder with same key as self

    """
    return AESKey.ECBEncoderClass(self)

  def Encrypt(self, plaintext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Encrypt `plaintext` and return `ciphertext` with AES-256 + GCM algorithm.

    <https://en.wikipedia.org/wiki/Galois/Counter_Mode>
    <https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM>

    No measures are taken here to prevent timing attacks.

    Args:
      plaintext (bytes): Data to encrypt.
      associated_data (bytes, optional): Optional AAD (Authenticated Associated Data),
          AEAD mode (authenticated encryption with associated data); must be provided
          again on decrypt

    Returns:
      bytes: Ciphertext; if a nonce/tag is needed for decryption, the implementation
      must encode it within the returned bytes (or document how to retrieve it)

    """
    iv: bytes = saferandom.RandBytes(16)
    cipher: ciphers.Cipher[modes.GCM] = ciphers.Cipher(
      algorithms.AES256(self.key256), modes.GCM(iv)
    )
    alg: ciphers.BlockCipherAlgorithm = cast(
      'algorithms.BlockCipherAlgorithm',  # type: ignore
      cipher.algorithm,
    )
    assert alg.key_size == 256, (  # noqa: PLR2004, S101
      'should never happen: AES256+GCM should have 256 bits key'
    )
    assert alg.block_size == 128, (  # noqa: PLR2004, S101
      'should never happen: AES256+GCM should have 128 bits block'
    )
    encryptor: ciphers.CipherContext = cipher.encryptor()
    if associated_data:
      encryptor.authenticate_additional_data(associated_data)  # type:ignore
    ciphertext: bytes = (
      encryptor.update(plaintext) + encryptor.finalize()
    )  # GCM doesn't need padding
    tag: bytes = encryptor.tag  # type:ignore
    assert len(iv) == 16, 'should never happen: AES256+GCM should have 128 bits IV/nonce'  # noqa: PLR2004, S101
    assert len(tag) == 16, 'should never happen: AES256+GCM should have 128 bits tag'  # noqa: PLR2004, S101
    return iv + ciphertext + tag

  def Decrypt(self, ciphertext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Decrypt `ciphertext` and return the original `plaintext` with AES-256 + GCM algorithm.

    <https://en.wikipedia.org/wiki/Galois/Counter_Mode>
    <https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM>

    No measures are taken here to prevent timing attacks.

    Args:
      ciphertext (bytes): Data to decrypt (including any embedded nonce/tag if applicable)
      associated_data (bytes, optional): Optional AAD (Authenticated Associated Data);
          must match what was used during encrypt

    Returns:
      bytes: Decrypted plaintext bytes

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: internal crypto failures, authentication failure, key mismatch, etc

    """
    if len(ciphertext) < 32:  # noqa: PLR2004
      raise base.InputError(f'AES256+GCM should have ≥32 bytes IV/CT/tag: {len(ciphertext)}')
    iv: bytes
    tag: bytes
    iv, tag = ciphertext[:16], ciphertext[-16:]
    decryptor: ciphers.CipherContext = ciphers.Cipher(
      algorithms.AES256(self.key256), modes.GCM(iv, tag)
    ).decryptor()
    if associated_data:
      decryptor.authenticate_additional_data(associated_data)  # type:ignore
    try:
      return decryptor.update(ciphertext[16:-16]) + decryptor.finalize()
    except crypt_exceptions.InvalidTag as err:
      raise key.CryptoError('failed decryption') from err
