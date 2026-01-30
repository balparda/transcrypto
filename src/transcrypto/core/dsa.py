# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""Balparda's TransCrypto DSA (Digital Signature Algorithm) library.

<https://en.wikipedia.org/wiki/Digital_Signature_Algorithm>

BEWARE: For now, this implementation is raw DSA, no padding, no hash!
In the future we will design a proper DSA+Hash implementation.
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import logging
import multiprocessing
import os
from typing import Self

import gmpy2

from transcrypto.core import constants, hashes, key, modmath
from transcrypto.utils import base, saferandom

_MAX_KEY_GENERATION_FAILURES = 15

# fixed prefixes: do NOT ever change! will break all encryption and signature schemes
_DSA_SIGNATURE_HASH_PREFIX = b'transcrypto.DSA.Signature.1.0\x00'


def NBitRandomDSAPrimes(
  p_bits: int, q_bits: int, /, *, serial: bool = True
) -> tuple[int, int, int]:
  """Generate 2 random DSA primes p & q with `x_bits` size and (p-1)%q==0.

  Uses an aggressive small-prime wheel sieve:
  Before any Miller-Rabin we reject p = m·q + 1 if it is divisible by a small prime.
  We precompute forbidden residues for m:
  • For each small prime r (all primes up to, say, 100 000), we compute
    m_forbidden ≡ -q⁻¹ (mod r) (because (m·q + 1) % r == 0 ⇔ m ≡ -q⁻¹ (mod r))
  • When we iterate m, we skip values that hit any forbidden residue class.

  Method will decide if executes on one thread or many.

  $ poetry run profiler -s -n 100 -b 1000,11000,1000 -c 98 dsa  # single-thread, Mac M2 Max, 2025
  1000 → 101.069 ms ± 19.714 ms [81.354 ms … 120.783 ms]98%CI@100
  2000 → 471.038 ms ± 98.810 ms [372.229 ms … 569.848 ms]98%CI@100
  3000 → 1.45 s ± 253.462 ms [1.20 s … 1.70 s]98%CI@100
  4000 → 3.09 s ± 592.267 ms [2.50 s … 3.69 s]98%CI@100
  5000 → 5.52 s ± 1.22 s [4.30 s … 6.74 s]98%CI@100
  6000 → 8.33 s ± 2.02 s [6.31 s … 10.35 s]98%CI@100
  7000 → 15.76 s ± 3.55 s [12.21 s … 19.31 s]98%CI@100
  8000 → 25.66 s ± 6.66 s [18.99 s … 32.32 s]98%CI@100
  9000 → 35.02 s ± 8.68 s [26.34 s … 43.70 s]98%CI@100
  10000 → 1.01 min ± 13.64 s [47.13 s … 1.24 min]98%CI@100

  Rule of thumb: double the bits requires ~10x execution time

  Args:
    p_bits (int): Number of guaranteed bits in `p` prime representation,
        p_bits ≥ q_bits + 11
    q_bits (int): Number of guaranteed bits in `q` prime representation, ≥ 11
    serial (bool, optional): True (default) will force one thread; False will allow parallelism;
       we have temporarily disabled parallelism with a default of True because it is not making
       things faster...

  Returns:
    random primes tuple (p, q, m), with p-1 a random multiple m of q, such
    that p % q == 1 and m == (p - 1) // q

  Raises:
    base.InputError: invalid inputs
    base.Error: prime search failed

  """
  # test inputs
  if q_bits < 11:  # noqa: PLR2004
    raise base.InputError(f'invalid q_bits length: {q_bits=}')
  if p_bits < q_bits + 11:
    raise base.InputError(f'invalid p_bits length: {p_bits=}')
  # make q
  q: int = modmath.NBitRandomPrimes(q_bits).pop()
  # get number of CPUs and decide if we do parallel or not
  n_workers: int = min(4, os.cpu_count() or 1)
  pr: int | None = None
  m: int | None = None
  if serial or n_workers <= 1 or p_bits < 200:  # noqa: PLR2004
    # do one worker
    while pr is None or m is None or pr.bit_length() != p_bits:
      pr, m = _PrimePSearchShard(q, p_bits)
    return (pr, q, m)
  # parallel: keep a small pool of bounded shards; stop on first hit
  multiprocessing.set_start_method('fork', force=True)
  with concurrent.futures.ProcessPoolExecutor(max_workers=n_workers) as pool:
    workers: set[concurrent.futures.Future[tuple[int | None, int | None]]] = {
      pool.submit(_PrimePSearchShard, q, p_bits) for _ in range(n_workers)
    }
    while workers:
      done: set[concurrent.futures.Future[tuple[int | None, int | None]]] = concurrent.futures.wait(
        workers, return_when=concurrent.futures.FIRST_COMPLETED
      )[0]
      for worker in done:
        workers.remove(worker)
        pr, m = worker.result()
        if pr is not None and m is not None and pr.bit_length() == p_bits:
          return (pr, q, m)
        # no hit in that shard: keep the pool full with a fresh shard
        workers.add(pool.submit(_PrimePSearchShard, q, p_bits))  # pragma: no cover
  # can never reach this point, but leave this here; remove line from coverage
  raise base.Error(f'could not find prime with {p_bits=}/{q_bits=} bits')  # pragma: no cover


def _PrimePSearchShard(q: int, p_bits: int) -> tuple[int | None, int | None]:
  """Search for a `p_bits` random prime, starting from a random point, for ~6x expected prime gap.

  Args:
    q (int): Prime `q` for DSA
    p_bits (int): Number of guaranteed bits in prime `p` representation

  Returns:
    tuple[int | None, int | None]: either the prime `p` and multiple `m` or None if no prime found

  """
  q_bits: int = q.bit_length()
  shard_len: int = max(2000, 6 * int(0.693 * p_bits))  # ~6x expected prime gap ~2^k (≈ 0.693*k)
  # find range of multiples to use
  min_p: int = 2 ** (p_bits - 1)
  max_p: int = 2**p_bits - 1
  min_m: int = min_p // q + 2
  max_m: int = max_p // q - 2
  assert max_m - min_m > 1000  # make sure we'll have options!  # noqa: PLR2004, S101
  # make list of small primes to use for sieving
  approx_q_root: int = 1 << (q_bits // 2)
  pr: int
  forbidden: dict[int, int] = {  # (modulus: forbidden residue)
    pr: ((-modmath.ModInv(q % pr, pr)) % pr)
    for pr in constants.FIRST_5K_PRIMES_SORTED[1 : min(1000, approx_q_root)]
  }  # skip pr==2

  def _PassesSieve(m: int) -> bool:
    return all(m % r != f for r, f in forbidden.items())

  # try searching starting here
  m: int = saferandom.RandInt(min_m, max_m)
  if m % 2:
    m += 1  # make even
  count: int = 0
  pr = 0
  while count < shard_len:
    pr = q * m + 1
    if pr > max_p:
      break
    # first do a quick sieve test
    if _PassesSieve(m) and modmath.IsPrime(pr):  # passed sieve, do full test
      return (pr, m)  # found a suitable prime set!
    count += 1
    m += 2  # next even number
  return (None, None)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class DSASharedPublicKey(key.CryptoKey):
  """DSA shared public key. This key can be shared by a group.

  No measures are taken here to prevent timing attacks.

  Attributes:
    prime_modulus (int): prime modulus (p), > prime_seed
    prime_seed (int): prime seed (q), ≥ 7
    group_base (int): shared encryption group public base, 3 ≤ g < prime_modulus

  """

  prime_modulus: int
  prime_seed: int
  group_base: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    if self.prime_seed < 7 or not modmath.IsPrime(self.prime_seed):  # noqa: PLR2004
      raise base.InputError(f'invalid prime_seed: {self}')
    if (
      self.prime_modulus <= self.prime_seed
      or self.prime_modulus % self.prime_seed != 1
      or not modmath.IsPrime(self.prime_modulus)
    ):
      raise base.InputError(f'invalid prime_modulus: {self}')
    if not 2 < self.group_base < self.prime_modulus or self.group_base == self.prime_seed:  # noqa: PLR2004
      raise base.InputError(f'invalid group_base: {self}')

  def __str__(self) -> str:
    """Safe string representation of the DSASharedPublicKey.

    Returns:
      string representation of DSASharedPublicKey

    """
    return (
      'DSASharedPublicKey('
      f'bits=[{self.prime_modulus.bit_length()}, {self.prime_seed.bit_length()}], '
      f'prime_modulus={base.IntToEncoded(self.prime_modulus)}, '
      f'prime_seed={base.IntToEncoded(self.prime_seed)}, '
      f'group_base={base.IntToEncoded(self.group_base)})'
    )

  @property
  def modulus_size(self) -> tuple[int, int]:
    """Modulus size in bytes. The number of bytes used in Sign/Verify."""
    return ((self.prime_modulus.bit_length() + 7) // 8, (self.prime_seed.bit_length() + 7) // 8)

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
    y: int = base.BytesToInt(hashes.Hash512(_DSA_SIGNATURE_HASH_PREFIX + la + aad + message + salt))
    if not 1 < y < self.prime_seed - 1:
      # will only reasonably happen if prime seed is small
      raise key.CryptoError(f'hash output {y} is out of range/invalid {self.prime_seed}')
    return y

  @classmethod
  def NewShared(cls, p_bits: int, q_bits: int, /) -> Self:
    """Make a new shared public key of `bit_length` bits.

    Args:
      p_bits (int): Number of guaranteed bits in `p` prime representation,
        p_bits ≥ q_bits + 11
      q_bits (int): Number of guaranteed bits in `q` prime representation, ≥ 11

    Returns:
      DSASharedPublicKey object ready for use

    """
    # test inputs and generate primes
    p, q, m = NBitRandomDSAPrimes(p_bits, q_bits)
    # generate random number, create object (should never fail)
    g: int = 0
    while g < 3:  # noqa: PLR2004
      h: int = saferandom.RandBits(p_bits - 1)
      g = int(gmpy2.powmod(h, m, p))
    return cls(prime_modulus=p, prime_seed=q, group_base=g)


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class DSAPublicKey(DSASharedPublicKey, key.Verifier):
  """DSA public key. This is an individual public key.

  No measures are taken here to prevent timing attacks.

  Attributes:
    individual_base (int): individual encryption public base, 3 ≤ i < prime_modulus

  """

  individual_base: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs

    """
    super(DSAPublicKey, self).__post_init__()
    if not 2 < self.individual_base < self.prime_modulus or self.individual_base in {  # noqa: PLR2004
      self.group_base,
      self.prime_seed,
    }:
      raise base.InputError(f'invalid individual_base: {self}')

  def __str__(self) -> str:
    """Safe string representation of the DSAPublicKey.

    Returns:
      string representation of DSAPublicKey

    """
    return (
      'DSAPublicKey('
      f'{super(DSAPublicKey, self).__str__()}, '
      f'individual_base={base.IntToEncoded(self.individual_base)})'
    )

  def _MakeEphemeralKey(self) -> tuple[int, int]:
    """Make an ephemeral key adequate to be used with DSA.

    Returns:
      (key, key_inverse), where 3 ≤ k < p_seed and (k*i) % p_seed == 1

    """
    ephemeral_key: int = 0
    bit_length: int = self.prime_seed.bit_length()
    while not 2 < ephemeral_key < self.prime_seed or ephemeral_key in {  # noqa: PLR2004
      self.group_base,
      self.individual_base,
    }:
      ephemeral_key = saferandom.RandBits(bit_length - 1)
    return (ephemeral_key, modmath.ModInv(ephemeral_key, self.prime_seed))

  def RawVerify(self, message: int, signature: tuple[int, int], /) -> bool:
    """Verify a signature. True if OK; False if failed verification.

    BEWARE: This is raw DSA, no ECDSA/EdDSA padding, no hash, no validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message that was signed by key owner, 0 < m < prime_seed
      signature (tuple[int, int]): signature, 2 ≤ s1,s2 < prime_seed

    Returns:
      True if signature is valid, False otherwise

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 < message < self.prime_seed:
      raise base.InputError(f'invalid message: {message=}')
    if not 2 <= signature[0] < self.prime_seed or not 2 <= signature[1] < self.prime_seed:  # noqa: PLR2004
      raise base.InputError(f'invalid signature: {signature=}')
    # verify
    inv: int = modmath.ModInv(signature[1], self.prime_seed)
    a: int = int(
      gmpy2.powmod(self.group_base, (message * inv) % self.prime_seed, self.prime_modulus)
    )
    b: int = int(
      gmpy2.powmod(self.individual_base, (signature[0] * inv) % self.prime_seed, self.prime_modulus)
    )
    return ((a * b) % self.prime_modulus) % self.prime_seed == signature[0]

  def Verify(
    self, message: bytes, signature: bytes, /, *, associated_data: bytes | None = None
  ) -> bool:
    """Verify a `signature` for `message`. True if OK; False if failed verification.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Split signature in 3 parts: the first 64 bytes is salt, the rest is s1 and s2
    • y_check = DSA(s1, s2)
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
    k: int = self.modulus_size[1]  # use prime_seed size
    if k <= 64:  # noqa: PLR2004
      raise base.InputError(f'modulus/seed too small for signing operations: {k} bytes')
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
  def Copy(cls, other: DSAPublicKey, /) -> Self:
    """Initialize a public key by taking the public parts of a public/private key.

    Args:
        other (DSAPublicKey): object to copy from

    Returns:
        Self: a new DSAPublicKey

    """
    return cls(
      prime_modulus=other.prime_modulus,
      prime_seed=other.prime_seed,
      group_base=other.group_base,
      individual_base=other.individual_base,
    )


@dataclasses.dataclass(kw_only=True, slots=True, frozen=True, repr=False)
class DSAPrivateKey(DSAPublicKey, key.Signer):
  """DSA private key.

  No measures are taken here to prevent timing attacks.

  Attributes:
    decrypt_exp (int): individual decryption exponent, 3 ≤ i < prime_seed

  """

  decrypt_exp: int

  def __post_init__(self) -> None:
    """Check data.

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: modulus math is inconsistent with values

    """
    super(DSAPrivateKey, self).__post_init__()
    if not 2 < self.decrypt_exp < self.prime_seed or self.decrypt_exp in {  # noqa: PLR2004
      self.group_base,
      self.individual_base,
    }:
      raise base.InputError(f'invalid decrypt_exp: {self}')
    if gmpy2.powmod(self.group_base, self.decrypt_exp, self.prime_modulus) != self.individual_base:
      raise key.CryptoError(f'inconsistent g**d % p == i: {self}')

  def __str__(self) -> str:
    """Safe (no secrets) string representation of the DSAPrivateKey.

    Returns:
      string representation of DSAPrivateKey without leaking secrets

    """
    return (
      'DSAPrivateKey('
      f'{super(DSAPrivateKey, self).__str__()}, '
      f'decrypt_exp={hashes.ObfuscateSecret(self.decrypt_exp)})'
    )

  def RawSign(self, message: int, /) -> tuple[int, int]:
    """Sign `message` with this private key.

    BEWARE: This is raw DSA, no ECDSA/EdDSA padding, no hash, no validation!
    These are pedagogical/raw primitives; do not use for new protocols.
    We explicitly disallow `message` to be zero.

    Args:
      message (int): message to sign, 1 ≤ m < prime_seed

    Returns:
      signed message tuple ((int, int), 2 ≤ s1,s2 < prime_seed

    Raises:
      base.InputError: invalid inputs

    """
    # test inputs
    if not 0 < message < self.prime_seed:
      raise base.InputError(f'invalid message: {message=}')
    # sign
    a: int = 0
    b: int = 0
    while a < 2 or b < 2:  # noqa: PLR2004
      ephemeral_key, ephemeral_inv = self._MakeEphemeralKey()
      a = int(gmpy2.powmod(self.group_base, ephemeral_key, self.prime_modulus) % self.prime_seed)
      b = (ephemeral_inv * ((message + a * self.decrypt_exp) % self.prime_seed)) % self.prime_seed
    return (a, b)

  def Sign(self, message: bytes, /, *, associated_data: bytes | None = None) -> bytes:
    """Sign `message` and return the `signature`.

    • Let k = ceil(log2(n))/8 be the modulus size in bytes.
    • Pick random salt of 64 bytes
    • s1, s2 = DSA(Hash512("prefix" || len(aad) || aad || message || salt))
    • return salt || Padded(s1, k) || Padded(s2, k)

    This is basically Full-Domain Hash DSA with a 512-bit hash and per-signature salt,
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
    k: int = self.modulus_size[1]  # use prime_seed size
    if k <= 64:  # noqa: PLR2004
      raise base.InputError(f'modulus/seed too small for signing operations: {k} bytes')
    salt: bytes = saferandom.RandBytes(64)
    s_int: tuple[int, int] = self.RawSign(self._DomainSeparatedHash(message, associated_data, salt))
    s_bytes: bytes = base.IntToFixedBytes(s_int[0], k) + base.IntToFixedBytes(s_int[1], k)
    assert len(s_bytes) == 2 * k, 'should never happen: s_bytes should be exactly 2k bytes'  # noqa: S101
    return salt + s_bytes

  @classmethod
  def New(cls, shared_key: DSASharedPublicKey, /) -> Self:
    """Make a new private key based on an existing shared public key.

    Args:
      shared_key (DSASharedPublicKey): shared public key

    Returns:
      DSAPrivateKey object ready for use

    Raises:
      base.InputError: invalid inputs
      key.CryptoError: failed generation

    """
    # test inputs
    bit_length: int = shared_key.prime_seed.bit_length()
    if bit_length < 11:  # noqa: PLR2004
      raise base.InputError(f'invalid q_bit length: {bit_length=}')
    # loop until we have an object
    failures: int = 0
    while True:
      try:
        # generate private key differing from group_base
        decrypt_exp: int = 0
        while (
          not 2 < decrypt_exp < shared_key.prime_seed or decrypt_exp == shared_key.group_base  # noqa: PLR2004
        ):
          decrypt_exp = saferandom.RandBits(bit_length - 1)
        # make the object
        return cls(
          prime_modulus=shared_key.prime_modulus,
          prime_seed=shared_key.prime_seed,
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
