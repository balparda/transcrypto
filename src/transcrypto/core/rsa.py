# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto RSA (Rivest-Shamir-Adleman) library.

<https://en.wikipedia.org/wiki/RSA_cryptosystem>
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Self

import gmpy2

from transcrypto.core import aes, hashes, key, modmath
from transcrypto.utils import base, saferandom

_SMALL_ENCRYPTION_EXPONENT = 7
_BIG_ENCRYPTION_EXPONENT = 2**16 + 1  # 65537

_MAX_KEY_GENERATION_FAILURES = 15

# fixed prefixes: do NOT ever change! will break all encryption and signature schemes
_RSA_ENCRYPTION_AAD_PREFIX = b'transcrypto.RSA.Encryption.1.0\x00'
_RSA_SIGNATURE_HASH_PREFIX = b'transcrypto.RSA.Signature.1.0\x00'


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class RSAPublicKey(key.CryptoKey, key.Encryptor, key.Verifier):
  """RSA (Rivest-Shamir-Adleman) key, with the public part of the key.

  No measures are taken here to prevent timing attacks.

  By default and deliberate choice the encryption exponent will be either 7 or 65537,
  depending on the size of phi=(p-1)*(q-1). If phi allows it the larger one will be chosen
  to avoid Coppersmith attacks.

  Attributes:
    public_modulus (int): modulus (p * q), ≥ 6
    encrypt_exp (int): encryption exponent, 3 ≤ e < modulus, (e * decrypt) % ((p-1) * (q-1)) == 1

  """

  public_modulus: int
  encrypt_exp: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    if self.public_modulus < 6 or modmath.IsPrime(self.public_modulus):  # noqa: PLR2004
      # only a full factors check can prove modulus is product of only 2 primes, which is impossible
      # to do for large numbers here; the private key checks the relationship though
      raise base.InputError(f'invalid public_modulus: {self}')
    if not 2 < self.encrypt_exp < self.public_modulus or not modmath.IsPrime(self.encrypt_exp):  # noqa: PLR2004
      # technically, encrypt_exp < phi, but again the private key tests for this explicitly
      raise base.InputError(f'invalid encrypt_exp: {self}')

  def __str__(self) -> str:
    """Safe string representation of the RSAPublicKey.

    Returns:
      string representation of RSAPublicKey

    """
    return (
      'RSAPublicKey('
      f'bits={self.public_modulus.bit_length()}, '
      f'public_modulus={base.IntToEncoded(self.public_modulus)}, '
      f'encrypt_exp={base.IntToEncoded(self.encrypt_exp)})'
    )

  @property
  def modulus_size(self) -> int:
    """Modulus size in bytes. The number of bytes used in Encrypt/Decrypt/Sign/Verify."""
    return (self.public_modulus.bit_length() + 7) // 8

  def RawEncrypt(self, message: int, /) -> int:
    """Encrypt `message` with this public key.

    BEWARE: This is raw RSA, no OAEP or PSS padding or validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to encrypt, 1 ≤ m < modulus

    Returns:
      ciphertext message (int, 1 ≤ c < modulus) = (m ** encrypt_exp) mod modulus

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 < message < self.public_modulus:
      raise base.InputError(f'invalid message: {message=}')
    # encrypt
    return int(gmpy2.powmod(message, self.encrypt_exp, self.public_modulus))

  def Encrypt(self, plaintext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Encrypt `plaintext` and return `ciphertext`.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Pick random r ∈ [2, n-1]
    • ct = r^e mod n
    • return Padded(ct, k) + AES-256-GCM(key=SHA512(r)[32:], plaintext,
                                         associated_data="prefix" + len(aad) + aad + Padded(ct, k))

    We pick fresh random r, send ct = r^e mod n, and derive the DEM key from r,
    then use AES-GCM for the payload. This is the classic RSA-KEM construction.
    With AEAD as the DEM, we get strong confidentiality and ciphertext integrity
    (CCA resistance in the ROM under standard assumptions). There are no
    Bleichenbacher-style issue because we do not expose any padding semantics.

    Args:
      plaintext (bytes): Data to encrypt.
      associated_data (bytes, optional): Optional AAD; must be provided again on decrypt

    Returns:
      bytes: Ciphertext; see above:
      Padded(ct, k) + AES-256-GCM(key=SHA512(r)[32:], plaintext,
                                  associated_data="prefix" + len(aad) + aad + Padded(ct, k))

    """
    # generate random r and encrypt it
    r: int = 0
    while not 1 < r < self.public_modulus or modmath.GCD(r, self.public_modulus) != 1:
      r = saferandom.RandBits(self.public_modulus.bit_length())
    k: int = self.modulus_size
    ct: bytes = base.IntToFixedBytes(self.RawEncrypt(r), k)
    assert len(ct) == k, 'should never happen: c_kem should be exactly k bytes'  # noqa: S101
    # encrypt plaintext with AES-256-GCM using SHA512(r)[32:] as key; return ct || Encrypt(...)
    ss: bytes = hashes.Hash512(base.IntToFixedBytes(r, k))
    aad: bytes = b'' if associated_data is None else associated_data
    aad_prime: bytes = _RSA_ENCRYPTION_AAD_PREFIX + base.IntToFixedBytes(len(aad), 8) + aad + ct
    return ct + aes.AESKey(key256=ss[32:]).Encrypt(plaintext, associated_data=aad_prime)

  def RawVerify(self, message: int, signature: int, /) -> bool:
    """Verify a signature. True if OK; False if failed verification.

    BEWARE: This is raw RSA, no OAEP or PSS padding or validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message that was signed by key owner, 1 ≤ m < modulus
      signature (int): signature, 1 ≤ s < modulus

    Returns:
      True if signature is valid, False otherwise;
      (signature ** encrypt_exp) mod modulus == message

    """
    return self.RawEncrypt(signature) == message

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
    y: int = base.BytesToInt(hashes.Hash512(_RSA_SIGNATURE_HASH_PREFIX + la + aad + message + salt))
    if not 1 < y < self.public_modulus or modmath.GCD(y, self.public_modulus) != 1:
      # will only reasonably happen if modulus is small
      raise key.CryptoError(f'hash output {y} is out of range/invalid {self.public_modulus}')
    return y

  def Verify(
    self, message: bytes, signature: bytes, /, *, associated_data: bytes | None = None
  ) -> bool:
    """Verify a `signature` for `message`. True if OK; False if failed verification.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Split signature in two parts: the first 64 bytes is salt, the rest is s
    • y_check = s^e mod n
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
    if len(signature) != (64 + k):
      logging.info(f'invalid signature length: {len(signature)} ; expected {64 + k}')
      return False
    try:
      return self.RawVerify(
        self._DomainSeparatedHash(message, associated_data, signature[:64]),
        base.BytesToInt(signature[64:]),
      )
    except base.InputError as err:
      logging.info(err)
      return False

  @classmethod
  def Copy(cls, other: RSAPublicKey, /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key.

    Args:
        other (RSAPublicKey): object to copy from

    Returns:
        Self: a new RSAPublicKey

    """
    return cls(public_modulus=other.public_modulus, encrypt_exp=other.encrypt_exp)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class RSAObfuscationPair(RSAPublicKey):
  """RSA (Rivest-Shamir-Adleman) obfuscation pair for a public key.

  BEWARE: This only works on raw RSA, no OAEP or PSS padding or validation!
  These are pedagogical/raw primitives; do not use for new protocols.
  No measures are taken here to prevent timing attacks.

  Attributes:
    random_key (int): random value key, 2 ≤ k < modulus
    key_inverse (int): inverse for `random_key` in relation to the RSA public key, 2 ≤ i < modulus

  """

  random_key: int
  key_inverse: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: modulus math is inconsistent with values

    """
    super(RSAObfuscationPair, self).__post_init__()
    if (
      not 1 < self.random_key < self.public_modulus
      or not 1 < self.key_inverse < self.public_modulus
      or self.random_key in {self.key_inverse, self.encrypt_exp, self.public_modulus}
    ):
      raise base.InputError(f'invalid keys: {self}')
    if (self.random_key * self.key_inverse) % self.public_modulus != 1:
      raise key.CryptoError(f'inconsistent keys: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the RSAObfuscationPair.

    Returns:
      string representation of RSAObfuscationPair without leaking secrets

    """
    return (
      'RSAObfuscationPair('
      f'{super(RSAObfuscationPair, self).__str__()}, '
      f'random_key={hashes.ObfuscateSecret(self.random_key)}, '
      f'key_inverse={hashes.ObfuscateSecret(self.key_inverse)})'
    )

  def ObfuscateMessage(self, message: int, /) -> int:
    """Convert message to an obfuscated message to be signed by this key's owner.

    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to obfuscate before signature, 1 ≤ m < modulus

    Returns:
      obfuscated message (int, 1 ≤ o < modulus) = (m * (random_key ** encrypt_exp)) mod modulus

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 < message < self.public_modulus:
      raise base.InputError(f'invalid message: {message=}')
    # encrypt
    return (
      message * int(gmpy2.powmod(self.random_key, self.encrypt_exp, self.public_modulus))
    ) % self.public_modulus

  def RevealOriginalSignature(self, message: int, signature: int, /) -> int:
    """Recover original signature for `message` from obfuscated `signature`.

    We explicitly disallow `message` to be zero.

    Args:
      message (int): original message before obfuscation, 1 ≤ m < modulus
      signature (int): signature for obfuscated message (not `message`!), 1 ≤ s < modulus

    Returns:
      original signature (int, 1 ≤ s < modulus) to `message`;
      signature * key_inverse mod modulus

    Raises:
      key.CryptoError: some signatures were invalid (either plain or obfuscated)

    """
    # verify that obfuscated signature is valid
    obfuscated: int = self.ObfuscateMessage(message)
    if not self.RawVerify(obfuscated, signature):
      raise key.CryptoError(f'obfuscated message was not signed: {message=} ; {signature=}')
    # compute signature for original message and check it
    original: int = (signature * self.key_inverse) % self.public_modulus
    if not self.RawVerify(message, original):
      raise key.CryptoError(f'failed signature recovery: {message=} ; {signature=}')
    return original

  @classmethod
  def New(cls, rsa_key: RSAPublicKey, /) -> Self:
    """Generate new obfuscation pair for this `rsa_key`, respecting the size of the public modulus.

    Args:
      rsa_key (RSAPublicKey): public RSA key to use as base for a new RSAObfuscationPair

    Returns:
      RSAObfuscationPair object ready for use

    Raises:
      key.CryptoError: failed generation

    """
    # find a suitable random key based on the bit_length
    random_key: int = 0
    key_inverse: int = 0
    failures: int = 0
    while (
      not random_key
      or not key_inverse
      or random_key in {rsa_key.encrypt_exp, key_inverse}
      or key_inverse == rsa_key.encrypt_exp
    ):
      random_key = saferandom.RandBits(rsa_key.public_modulus.bit_length() - 1)
      try:
        key_inverse = modmath.ModInv(random_key, rsa_key.public_modulus)
      except modmath.ModularDivideError as err:
        key_inverse = 0
        failures += 1
        if failures >= _MAX_KEY_GENERATION_FAILURES:
          raise key.CryptoError(f'failed key generation {failures} times') from err
        logging.warning(err)
    # build object
    return cls(
      public_modulus=rsa_key.public_modulus,
      encrypt_exp=rsa_key.encrypt_exp,
      random_key=random_key,
      key_inverse=key_inverse,
    )


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class RSAPrivateKey(RSAPublicKey, key.Decryptor, key.Signer):
  """RSA (Rivest-Shamir-Adleman) private key.

  No measures are taken here to prevent timing attacks.

  The attributes modulus_p (p), modulus_q (q) and decrypt_exp (d) are "enough" for a working key,
  but we have the other 3 (remainder_p, remainder_q, q_inverse_p) to speedup decryption/signing
  by a factor of 4 using the Chinese Remainder Theorem.

  Attributes:
    modulus_p (int): prime number p, ≥ 2
    modulus_q (int): prime number q, ≥ 3 and > p
    decrypt_exp (int): decryption exponent, 2 ≤ d < modulus, (encrypt * d) % ((p-1) * (q-1)) == 1
    remainder_p (int): pre-computed, = d % (p - 1), 2 ≤ r_p < modulus
    remainder_q (int): pre-computed, = d % (q - 1), 2 ≤ r_q < modulus
    q_inverse_p (int): pre-computed, = ModInv(q, p), 2 ≤ q_i_p < modulus

  """

  modulus_p: int
  modulus_q: int
  decrypt_exp: int

  remainder_p: int  # these 3 are derived from the previous 3 and are used for speedup only!
  remainder_q: int  # because of that they will not be printed in __str__()
  q_inverse_p: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: modulus math is inconsistent with values

    """
    super(RSAPrivateKey, self).__post_init__()
    phi: int = (self.modulus_p - 1) * (self.modulus_q - 1)
    min_prime_distance: int = 1 << (self.public_modulus.bit_length() // 4)  # ≈ n**(1/4)
    if (
      self.modulus_p < 2  # noqa: PLR0916, PLR2004
      or not modmath.IsPrime(self.modulus_p)
      or self.modulus_q < 3  # noqa: PLR2004
      or not modmath.IsPrime(self.modulus_q)
      or self.modulus_q <= self.modulus_p
      or (self.modulus_q - self.modulus_p) < min_prime_distance
      or self.encrypt_exp in {self.modulus_p, self.modulus_q}
      or self.encrypt_exp >= phi
      or self.decrypt_exp in {self.encrypt_exp, self.modulus_p, self.modulus_q, phi}
    ):
      # encrypt_exp has to be less than phi;
      # if p - q < 2*(n**(1/4)) then solving for p and q is trivial
      raise base.InputError(f'invalid modulus_p or modulus_q: {self}')
    min_decrypt_length: int = self.public_modulus.bit_length() // 2 + 1
    if not (2**min_decrypt_length) < self.decrypt_exp < self.public_modulus:
      # if decrypt_exp < public_modulus**(1/4)/3, then decrypt_exp can be computed efficiently
      # from public_modulus and encrypt_exp so we make sure it is larger than public_modulus**(1/2)
      raise base.InputError(f'invalid decrypt_exp: {self}')
    if self.remainder_p < 2 or self.remainder_q < 2 or self.q_inverse_p < 2:  # noqa: PLR2004
      raise base.InputError(f'trivial remainder_p/remainder_q/q_inverse_p: {self}')
    if self.modulus_p * self.modulus_q != self.public_modulus:
      raise key.CryptoError(f'inconsistent modulus_p * modulus_q: {self}')
    if (self.encrypt_exp * self.decrypt_exp) % phi != 1:
      raise key.CryptoError(f'inconsistent exponents: {self}')
    if (
      self.remainder_p != self.decrypt_exp % (self.modulus_p - 1)
      or self.remainder_q != self.decrypt_exp % (self.modulus_q - 1)
      or (self.q_inverse_p * self.modulus_q) % self.modulus_p != 1
    ):
      raise key.CryptoError(f'inconsistent speedup remainder_p/remainder_q/q_inverse_p: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the RSAPrivateKey.

    Returns:
      string representation of RSAPrivateKey without leaking secrets

    """
    return (
      'RSAPrivateKey('
      f'{super(RSAPrivateKey, self).__str__()}, '
      f'modulus_p={hashes.ObfuscateSecret(self.modulus_p)}, '
      f'modulus_q={hashes.ObfuscateSecret(self.modulus_q)}, '
      f'decrypt_exp={hashes.ObfuscateSecret(self.decrypt_exp)})'
    )

  def RawDecrypt(self, ciphertext: int, /) -> int:
    """Decrypt `ciphertext` with this private key.

    BEWARE: This is raw RSA, no OAEP or PSS padding or validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly allow `ciphertext` to be zero for completeness, but it shouldn't be in practice.

    Args:
      ciphertext (int): ciphertext to decrypt, 0 ≤ c < modulus

    Returns:
      decrypted message (int, 1 ≤ m < modulus) = (m ** decrypt_exp) mod modulus

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 <= ciphertext < self.public_modulus:
      raise base.InputError(f'invalid message: {ciphertext=}')
    # decrypt using CRT (Chinese Remainder Theorem); 4x speedup; all the below is equivalent
    # of doing: return pow(ciphertext, self.decrypt_exp, self.public_modulus)
    m_p: int = int(gmpy2.powmod(ciphertext % self.modulus_p, self.remainder_p, self.modulus_p))
    m_q: int = int(gmpy2.powmod(ciphertext % self.modulus_q, self.remainder_q, self.modulus_q))
    h: int = (self.q_inverse_p * (m_p - m_q)) % self.modulus_p
    return (m_q + h * self.modulus_q) % self.public_modulus

  def Decrypt(self, ciphertext: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Decrypt `ciphertext` and return the original `plaintext`.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Split ciphertext in two parts: the first k bytes is ct, the rest is AES-256-GCM
    • r = ct^d mod n
    • return AES-256-GCM(key=SHA512(r)[32:], ciphertext,
                         associated_data="prefix" + len(aad) + aad + Padded(ct, k))

    Args:
      ciphertext (bytes): Data to decrypt; see Encrypt() above:
          Padded(ct, k) + AES-256-GCM(key=SHA512(r)[32:], plaintext,
                                      associated_data="prefix" + len(aad) + aad + Padded(ct, k))
      associated_data (bytes, optional): Optional AAD (must match what was used during encrypt)

    Returns:
      bytes: Decrypted plaintext bytes

    Raises:
      base.InputError: invalid inputs

    """
    k: int = self.modulus_size
    if len(ciphertext) < (k + 32):
      raise base.InputError(f'invalid ciphertext length: {len(ciphertext)} ; {k=}')
    # split ciphertext in two parts: the first k bytes is ct, the rest is AES-256-GCM
    rsa_ct, aes_ct = ciphertext[:k], ciphertext[k:]
    r: int = self.RawDecrypt(base.BytesToInt(rsa_ct))
    ss: bytes = hashes.Hash512(base.IntToFixedBytes(r, k))
    aad: bytes = b'' if associated_data is None else associated_data
    aad_prime: bytes = _RSA_ENCRYPTION_AAD_PREFIX + base.IntToFixedBytes(len(aad), 8) + aad + rsa_ct
    return aes.AESKey(key256=ss[32:]).Decrypt(aes_ct, associated_data=aad_prime)

  def RawSign(self, message: int, /) -> int:
    """Sign `message` with this private key.

    BEWARE: This is raw RSA, no OAEP or PSS padding or validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to sign, 1 ≤ m < modulus

    Returns:
      signed message (int, 1 ≤ m < modulus) = (m ** decrypt_exp) mod modulus;
      identical to Decrypt()

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 < message < self.public_modulus:
      raise base.InputError(f'invalid message: {message=}')
    # call decryption
    return self.RawDecrypt(message)

  def Sign(self, message: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Sign `message` and return the `signature`.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Pick random salt of 64 bytes
    • s = (Hash512("prefix" || len(aad) || aad || message || salt))^d mod n
    • return salt || Padded(s, k)

    This is basically Full-Domain Hash RSA with a 512-bit hash and per-signature salt,
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
    s_int: int = self.RawSign(self._DomainSeparatedHash(message, associated_data, salt))
    s_bytes: bytes = base.IntToFixedBytes(s_int, k)
    assert len(s_bytes) == k, 'should never happen: s_bytes should be exactly k bytes'  # noqa: S101
    return salt + s_bytes

  @classmethod
  def New(cls, bit_length: int, /) -> Self:
    """Make a new private key of `bit_length` bits (primes p & q will be ~half this length).

    Args:
      bit_length (int): number of bits in the modulus, ≥ 11; primes p & q will be half this length

    Returns:
      RSAPrivateKey object ready for use

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: failed generation

    """
    # test inputs
    if bit_length < 11:  # noqa: PLR2004
      raise base.InputError(f'invalid bit length: {bit_length=}')
    # generate primes / modulus
    failures: int = 0
    while True:
      try:
        primes: set[int] = set()
        modulus: int = 0
        p: int = 0
        q: int = 0
        while modulus.bit_length() != bit_length:
          primes = modmath.NBitRandomPrimes((bit_length + 1) // 2, n_primes=2)
          p, q = min(primes), max(primes)  # "p" is always the smaller, "q" the larger
          modulus = p * q
        # build object
        phi: int = (p - 1) * (q - 1)
        prime_exp: int = (
          _SMALL_ENCRYPTION_EXPONENT
          if phi <= _BIG_ENCRYPTION_EXPONENT
          else _BIG_ENCRYPTION_EXPONENT
        )
        decrypt_exp: int = modmath.ModInv(prime_exp, phi)
        return cls(
          modulus_p=p,
          modulus_q=q,
          public_modulus=modulus,
          encrypt_exp=prime_exp,
          decrypt_exp=decrypt_exp,
          remainder_p=decrypt_exp % (p - 1),
          remainder_q=decrypt_exp % (q - 1),
          q_inverse_p=modmath.ModInv(q, p),
        )
      except (base.InputError, modmath.ModularDivideError) as err:
        failures += 1
        if failures >= _MAX_KEY_GENERATION_FAILURES:
          raise key.CryptoError(f'failed key generation {failures} times') from err
        logging.warning(err)
