# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto El-Gamal library.

<https://en.wikipedia.org/wiki/ElGamal_encryption>
<https://en.wikipedia.org/wiki/ElGamal_signature_scheme>

ATTENTION: This is pure El-Gamal, **NOT** DSA (Digital Signature Algorithm).
For DSA, see the dsa.py library.

ALSO: ElGamal encryption is unconditionally malleable, and therefore is
not secure under chosen ciphertext attack. For example, given an encryption
`(c1,c2)` of some (possibly unknown) message `m`, one can easily construct
a valid encryption `(c1,2*c2)` of the message `2*m`.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Self

import gmpy2

from transcrypto.core import aes, hashes, key, modmath
from transcrypto.utils import base, saferandom

_MAX_KEY_GENERATION_FAILURES = 15

# fixed prefixes: do NOT ever change! will break all encryption and signature schemes
_ELGAMAL_ENCRYPTION_AAD_PREFIX = b'transcrypto.ElGamal.Encryption.1.0\x00'
_ELGAMAL_SIGNATURE_HASH_PREFIX = b'transcrypto.ElGamal.Signature.1.0\x00'


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class ElGamalSharedPublicKey(key.CryptoKey):
  """El-Gamal shared public key. This key can be shared by a group.

  BEWARE: This is **NOT** DSA! No measures are taken here to prevent timing attacks.

  Attributes:
    prime_modulus (int): prime modulus, ≥ 7
    group_base (int): shared encryption group public base, 3 ≤ g < prime_modulus

  """

  prime_modulus: int
  group_base: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    if self.prime_modulus < 7 or not modmath.IsPrime(self.prime_modulus):  # noqa: PLR2004
      raise base.InputError(f'invalid prime_modulus: {self}')
    if not 2 < self.group_base < self.prime_modulus - 1:  # noqa: PLR2004
      raise base.InputError(f'invalid group_base: {self}')

  def __str__(self) -> str:
    """Safe string representation of the ElGamalSharedPublicKey.

    Returns:
      string representation of ElGamalSharedPublicKey

    """
    return (
      'ElGamalSharedPublicKey('
      f'bits={self.prime_modulus.bit_length()}, '
      f'prime_modulus={base.IntToEncoded(self.prime_modulus)}, '
      f'group_base={base.IntToEncoded(self.group_base)})'
    )

  @property
  def modulus_size(self) -> int:
    """Modulus size in bytes. The number of bytes used in Encrypt/Decrypt/Sign/Verify."""
    return (self.prime_modulus.bit_length() + 7) // 8

  def _DomainSeparatedHash(
    self, message: bytes, associated_data: bytes | None, salt: bytes, /
  ) -> int:
    """Compute the domain-separated hash for signing and verifying.

    Args:
      message (bytes): message to sign/verify
      associated_data (bytes | None): optional associated data
      salt (bytes): salt to use in the hash

    Returns:
      int: integer representation of the hash output;
      Hash512("prefix" || len(aad) || aad || message || salt)

    Raises:
      key.CryptoError: hash output is out of range

    """
    aad: bytes = b'' if associated_data is None else associated_data
    la: bytes = base.IntToFixedBytes(len(aad), 8)
    assert len(salt) == 64, 'should never happen: salt should be exactly 64 bytes'  # noqa: PLR2004, S101
    y: int = base.BytesToInt(
      hashes.Hash512(_ELGAMAL_SIGNATURE_HASH_PREFIX + la + aad + message + salt)
    )
    if not 1 < y < self.prime_modulus:
      # will only reasonably happen if modulus is small
      raise key.CryptoError(f'hash output {y} is out of range/invalid {self.prime_modulus}')
    return y

  @classmethod
  def NewShared(cls, bit_length: int, /) -> Self:
    """Make a new shared public key of `bit_length` bits.

    Args:
      bit_length (int): number of bits in the prime modulus, ≥ 11

    Returns:
      ElGamalSharedPublicKey object ready for use

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if bit_length < 11:  # noqa: PLR2004
      raise base.InputError(f'invalid bit length: {bit_length=}')
    # generate random prime and number, create object (should never fail)
    p: int = modmath.NBitRandomPrimes(bit_length).pop()
    g: int = 0
    while not 2 < g < p:  # noqa: PLR2004
      g = saferandom.RandBits(bit_length)
    return cls(prime_modulus=p, group_base=g)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class ElGamalPublicKey(ElGamalSharedPublicKey, key.Encryptor, key.Verifier):
  """El-Gamal public key. This is an individual public key.

  BEWARE: This is **NOT** DSA! No measures are taken here to prevent timing attacks.

  Attributes:
    individual_base (int): individual encryption public base, 3 ≤ i < prime_modulus

  """

  individual_base: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    super(ElGamalPublicKey, self).__post_init__()
    if (
      not 2 < self.individual_base < self.prime_modulus - 1  # noqa: PLR2004
      or self.individual_base == self.group_base
    ):
      raise base.InputError(f'invalid individual_base: {self}')

  def __str__(self) -> str:
    """Safe string representation of the ElGamalPublicKey.

    Returns:
      string representation of ElGamalPublicKey

    """
    return (
      'ElGamalPublicKey('
      f'{super(ElGamalPublicKey, self).__str__()}, '
      f'individual_base={base.IntToEncoded(self.individual_base)})'
    )

  def _MakeEphemeralKey(self) -> tuple[int, int]:
    """Make an ephemeral key adequate to be used with El-Gamal.

    Returns:
      (key, key_inverse), where 2 ≤ k < modulus and
          GCD(k, modulus - 1) == 1 and (k*i) % (p-1) == 1

    """
    ephemeral_key: int = 0
    p_1: int = self.prime_modulus - 1
    bit_length: int = self.prime_modulus.bit_length()
    while not 1 < ephemeral_key < self.prime_modulus or ephemeral_key in {
      self.group_base,
      self.individual_base,
    }:
      ephemeral_key = saferandom.RandBits(bit_length)
      if modmath.GCD(ephemeral_key, p_1) != 1:
        ephemeral_key = 0  # we have to try again
    return (ephemeral_key, modmath.ModInv(ephemeral_key, p_1))

  def RawEncrypt(self, message: int, /) -> tuple[int, int]:
    """Encrypt `message` with this public key.

    BEWARE: This is raw El-Gamal, no ECIES-style KEM/DEM padding or validation! This is **NOT** DSA!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to encrypt, 1 ≤ m < modulus

    Returns:
      ciphertext message tuple ((int, int), 2 ≤ c1,c2 < modulus)

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 < message < self.prime_modulus:
      raise base.InputError(f'invalid message: {message=}')
    # encrypt
    a: int = 0
    b: int = 0
    while a < 2 or b < 2:  # noqa: PLR2004
      ephemeral_key: int = self._MakeEphemeralKey()[0]
      a = int(gmpy2.powmod(self.group_base, ephemeral_key, self.prime_modulus))
      s: int = int(gmpy2.powmod(self.individual_base, ephemeral_key, self.prime_modulus))
      b = (message * s) % self.prime_modulus
    return (a, b)

  def Encrypt(self, plaintext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Encrypt `plaintext` and return `ciphertext`.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Pick random r ∈ [2, n-1]
    • ct1, ct2 = ElGamal(r)
    • return Padded(ct1, k) + Padded(ct2, k) +
             AES-256-GCM(key=SHA512(r)[32:], plaintext,
                         associated_data="prefix" + len(aad) + aad +
                                         Padded(ct1, k) + Padded(ct2, k))

    We pick fresh random r, send ct = ElGamal(r), and derive the DEM key from r,
    then use AES-GCM for the payload. This is the classic El-Gamal-KEM construction.
    With AEAD as the DEM, we get strong confidentiality and ciphertext integrity
    (CCA resistance in the ROM under standard assumptions). There are no
    Bleichenbacher-style issue because we do not expose any padding semantics.

    Args:
      plaintext (bytes): Data to encrypt.
      associated_data (bytes, optional): Optional AAD; must be provided again on decrypt

    Returns:
      bytes: Ciphertext; see above:
      Padded(ct1, k) + Padded(ct2, k) + AES-256-GCM(key=SHA512(r)[32:], plaintext,
                                                    associated_data="prefix" + len(aad) + aad +
                                                                    Padded(ct1, k) + Padded(ct2, k))

    """
    # generate random r and encrypt it
    r: int = 0
    while not 1 < r < self.prime_modulus:
      r = saferandom.RandBits(self.prime_modulus.bit_length())
    k: int = self.modulus_size
    i_ct: tuple[int, int] = self.RawEncrypt(r)
    ct: bytes = base.IntToFixedBytes(i_ct[0], k) + base.IntToFixedBytes(i_ct[1], k)
    assert len(ct) == 2 * k, 'should never happen: c_kem should be exactly 2k bytes'  # noqa: S101
    # encrypt plaintext with AES-256-GCM using SHA512(r)[32:] as key; return ct || Encrypt(...)
    ss: bytes = hashes.Hash512(base.IntToFixedBytes(r, k))
    aad: bytes = b'' if associated_data is None else associated_data
    aad_prime: bytes = _ELGAMAL_ENCRYPTION_AAD_PREFIX + base.IntToFixedBytes(len(aad), 8) + aad + ct
    return ct + aes.AESKey(key256=ss[32:]).Encrypt(plaintext, associated_data=aad_prime)

  def RawVerify(self, message: int, signature: tuple[int, int], /) -> bool:
    """Verify a signature. True if OK; False if failed verification.

    BEWARE: This is raw El-Gamal, no ECIES-style KEM/DEM padding or validation! This is **NOT** DSA!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message that was signed by key owner, 0 < m < modulus
      signature (tuple[int, int]): signature, 2 ≤ s1 < modulus, 2 ≤ s2 < modulus-1

    Returns:
      True if signature is valid, False otherwise

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 < message < self.prime_modulus:
      raise base.InputError(f'invalid message: {message=}')
    if not 2 <= signature[0] < self.prime_modulus or not 2 <= signature[1] < self.prime_modulus - 1:  # noqa: PLR2004
      raise base.InputError(f'invalid signature: {signature=}')
    # verify
    a: int = int(gmpy2.powmod(self.group_base, message, self.prime_modulus))
    b: int = int(gmpy2.powmod(signature[0], signature[1], self.prime_modulus))
    c: int = int(gmpy2.powmod(self.individual_base, signature[0], self.prime_modulus))
    return a == (b * c) % self.prime_modulus

  def Verify(
    self, message: bytes, signature: bytes, /, *, associated_data: bytes | None = None
  ) -> bool:
    """Verify a `signature` for `message`. True if OK; False if failed verification.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Split signature in 3 parts: the first 64 bytes is salt, the rest is s1 and s2
    • y_check = ElGamal(s1, s2)
    • return y_check == Hash512("prefix" || len(aad) || aad || message || salt)
    • return False for any malformed signature

    Args:
      message (bytes): Data that was signed
      signature (bytes): Signature data to verify
      associated_data (bytes, optional): Optional AAD (must match what was used during signing)

    Returns:
      True if signature is valid, False otherwise

    Raises:
      base.InputError: invalid inputs

    """
    k: int = self.modulus_size
    if k <= 64:  # noqa: PLR2004
      raise base.InputError(f'modulus too small for signing operations: {k} bytes')
    if len(signature) != (64 + k + k):
      logging.info(f'invalid signature length: {len(signature)} ; expected {64 + k + k}')
      return False
    try:
      return self.RawVerify(
        self._DomainSeparatedHash(message, associated_data, signature[:64]),
        (base.BytesToInt(signature[64 : 64 + k]), base.BytesToInt(signature[64 + k :])),
      )
    except base.InputError as err:
      logging.info(err)
      return False

  @classmethod
  def Copy(cls, other: ElGamalPublicKey, /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key.

    Args:
        other (ElGamalPublicKey): object to copy from

    Returns:
        Self: a new ElGamalPublicKey

    """
    return cls(
      prime_modulus=other.prime_modulus,
      group_base=other.group_base,
      individual_base=other.individual_base,
    )


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class ElGamalPrivateKey(ElGamalPublicKey, key.Decryptor, key.Signer):
  """El-Gamal private key.

  BEWARE: This is **NOT** DSA! No measures are taken here to prevent timing attacks.

  Attributes:
    decrypt_exp (int): individual decryption exponent, 3 ≤ i < prime_modulus

  """

  decrypt_exp: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: modulus math is inconsistent with values

    """
    super(ElGamalPrivateKey, self).__post_init__()
    if not 2 < self.decrypt_exp < self.prime_modulus - 1 or self.decrypt_exp in {  # noqa: PLR2004
      self.group_base,
      self.individual_base,
    }:
      raise base.InputError(f'invalid decrypt_exp: {self}')
    if gmpy2.powmod(self.group_base, self.decrypt_exp, self.prime_modulus) != self.individual_base:
      raise key.CryptoError(f'inconsistent g**e % p == i: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the ElGamalPrivateKey.

    Returns:
      string representation of ElGamalPrivateKey without leaking secrets

    """
    return (
      'ElGamalPrivateKey('
      f'{super(ElGamalPrivateKey, self).__str__()}, '
      f'decrypt_exp={hashes.ObfuscateSecret(self.decrypt_exp)})'
    )

  def RawDecrypt(self, ciphertext: tuple[int, int], /) -> int:
    """Decrypt `ciphertext` tuple with this private key.

    BEWARE: This is raw El-Gamal, no ECIES-style KEM/DEM padding or validation! This is **NOT** DSA!
    These are pedagogical/raw primitives; do not use for new protocols.

    Args:
      ciphertext (tuple[int, int]): ciphertext to decrypt, 0 ≤ c1,c2 < modulus

    Returns:
      decrypted message (int, 1 ≤ m < modulus)

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 2 <= ciphertext[0] < self.prime_modulus or not 2 <= ciphertext[1] < self.prime_modulus:  # noqa: PLR2004
      raise base.InputError(f'invalid message: {ciphertext=}')
    # decrypt
    csi: int = int(
      gmpy2.powmod(ciphertext[0], self.prime_modulus - 1 - self.decrypt_exp, self.prime_modulus)
    )
    return (ciphertext[1] * csi) % self.prime_modulus

  def Decrypt(self, ciphertext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Decrypt `ciphertext` and return the original `plaintext`.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Split ciphertext in 3 parts: k bytes for ct1, k bytes for ct2, the rest is AES-256-GCM
    • r = ElGamal(ct1, ct2)
    • return AES-256-GCM(key=SHA512(r)[32:], ciphertext,
                         associated_data="prefix" + len(aad) + aad +
                                         Padded(ct1, k) + Padded(ct2, k))

    Args:
      ciphertext (bytes): Data to decrypt; see Encrypt() above:
          Padded(ct1, k) + Padded(ct2, k) +
          AES-256-GCM(key=SHA512(r)[32:], plaintext,
                      associated_data="prefix" + len(aad) + aad + Padded(ct1, k) + Padded(ct2, k))
      associated_data (bytes, optional): Optional AAD (must match what was used during encrypt)

    Returns:
      bytes: Decrypted plaintext bytes

    Raises:
      base.InputError: invalid inputs

    """
    k: int = self.modulus_size
    if len(ciphertext) < (k + k + 32):
      raise base.InputError(f'invalid ciphertext length: {len(ciphertext)} ; {k=}')
    # split ciphertext in 3 parts: the first 2k bytes is ct, the rest is AES-256-GCM
    ct1, ct2, aes_ct = ciphertext[:k], ciphertext[k : 2 * k], ciphertext[2 * k :]
    r: int = self.RawDecrypt((base.BytesToInt(ct1), base.BytesToInt(ct2)))
    ss: bytes = hashes.Hash512(base.IntToFixedBytes(r, k))
    aad: bytes = b'' if associated_data is None else associated_data
    aad_prime: bytes = (
      _ELGAMAL_ENCRYPTION_AAD_PREFIX + base.IntToFixedBytes(len(aad), 8) + aad + ct1 + ct2
    )
    return aes.AESKey(key256=ss[32:]).Decrypt(aes_ct, associated_data=aad_prime)

  def RawSign(self, message: int, /) -> tuple[int, int]:
    """Sign `message` with this private key.

    BEWARE: This is raw El-Gamal, no ECIES-style KEM/DEM padding or validation! This is **NOT** DSA!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to sign, 1 ≤ m < modulus

    Returns:
      signed message tuple ((int, int), 2 ≤ s1 < modulus, 2 ≤ s2 < modulus-1)

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 < message < self.prime_modulus:
      raise base.InputError(f'invalid message: {message=}')
    # sign
    a: int = 0
    b: int = 0
    p_1: int = self.prime_modulus - 1
    while a < 2 or b < 2:  # noqa: PLR2004
      ephemeral_key, ephemeral_inv = self._MakeEphemeralKey()
      a = int(gmpy2.powmod(self.group_base, ephemeral_key, self.prime_modulus))
      b = (ephemeral_inv * ((message - a * self.decrypt_exp) % p_1)) % p_1
    return (a, b)

  def Sign(self, message: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Sign `message` and return the `signature`.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Pick random salt of 64 bytes
    • s1, s2 = ElGamal(Hash512("prefix" || len(aad) || aad || message || salt))
    • return salt || Padded(s1, k) || Padded(s2, k)

    This is basically Full-Domain Hash El-Gamal with a 512-bit hash and per-signature salt,
    which is EUF-CMA secure in the ROM. Our domain-separation prefix and explicit AAD
    length prefix are both correct and remove composition/ambiguity pitfalls.
    There are no Bleichenbacher-style issue because we do not expose any padding semantics.

    Args:
      message (bytes): Data to sign.
      associated_data (bytes, optional): Optional AAD for AEAD modes; must be
          provided again on decrypt

    Returns:
      bytes: Signature; salt || Padded(s, k) - see above

    Raises:
      base.InputError: invalid inputs

    """
    k: int = self.modulus_size
    if k <= 64:  # noqa: PLR2004
      raise base.InputError(f'modulus too small for signing operations: {k} bytes')
    salt: bytes = saferandom.RandBytes(64)
    s_int: tuple[int, int] = self.RawSign(self._DomainSeparatedHash(message, associated_data, salt))
    s_bytes: bytes = base.IntToFixedBytes(s_int[0], k) + base.IntToFixedBytes(s_int[1], k)
    assert len(s_bytes) == 2 * k, 'should never happen: s_bytes should be exactly 2k bytes'  # noqa: S101
    return salt + s_bytes

  @classmethod
  def New(cls, shared_key: ElGamalSharedPublicKey, /) -> Self:
    """Make a new private key based on an existing shared public key.

    Args:
      shared_key (ElGamalSharedPublicKey): shared public key

    Returns:
      ElGamalPrivateKey object ready for use

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: failed generation

    """
    # test inputs
    bit_length: int = shared_key.prime_modulus.bit_length()
    if bit_length < 11:  # noqa: PLR2004
      raise base.InputError(f'invalid bit length: {bit_length=}')
    # loop until we have an object
    failures: int = 0
    while True:
      try:
        # generate private key differing from group_base
        decrypt_exp: int = 0
        while (
          not 2 < decrypt_exp < shared_key.prime_modulus or decrypt_exp == shared_key.group_base  # noqa: PLR2004
        ):
          decrypt_exp = saferandom.RandBits(bit_length)
        # make the object
        return cls(
          prime_modulus=shared_key.prime_modulus,
          group_base=shared_key.group_base,
          individual_base=int(
            gmpy2.powmod(shared_key.group_base, decrypt_exp, shared_key.prime_modulus)
          ),
          decrypt_exp=decrypt_exp,
        )
      except base.InputError as err:
        failures += 1
        if failures >= _MAX_KEY_GENERATION_FAILURES:
          raise key.CryptoError(f'failed key generation {failures} times') from err
        logging.warning(err)
