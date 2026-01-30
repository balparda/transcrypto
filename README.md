# TransCrypto

Basic cryptography primitives implementation, a companion to *"Criptografia, Métodos e Algoritmos"*.

Started in July/2025, by Daniel Balparda. Since version 1.0.2 it is PyPI package:

<https://pypi.org/project/transcrypto/>

- [TransCrypto](#transcrypto)
  - [License](#license)
  - [Design assumptions / Disclaimers](#design-assumptions--disclaimers)
  - [CLI Apps](#cli-apps)
  - [Programming API](#programming-api)
    - [Install](#install)
    - [Base Library](#base-library)
      - [Humanized Sizes (IEC binary)](#humanized-sizes-iec-binary)
      - [Humanized Decimal Quantities (SI)](#humanized-decimal-quantities-si)
      - [Humanized Durations](#humanized-durations)
      - [Execution Timing](#execution-timing)
        - [Context manager](#context-manager)
        - [Decorator](#decorator)
        - [Manual use](#manual-use)
        - [Key points](#key-points)
      - [Serialization Pipeline](#serialization-pipeline)
        - [Serialize](#serialize)
        - [DeSerialize](#deserialize)
      - [Cryptographically Secure Randomness](#cryptographically-secure-randomness)
        - [Fixed-size random integers](#fixed-size-random-integers)
        - [Uniform random integers in a range](#uniform-random-integers-in-a-range)
        - [In-place secure shuffle](#in-place-secure-shuffle)
        - [Random byte strings](#random-byte-strings)
      - [Computing the Greatest Common Divisor](#computing-the-greatest-common-divisor)
      - [Fast Modular Arithmetic](#fast-modular-arithmetic)
        - [Chinese Remainder Theorem (CRT) – Pair](#chinese-remainder-theorem-crt--pair)
        - [Modular Polynomials \& Lagrange Interpolation](#modular-polynomials--lagrange-interpolation)
      - [Primality testing \& Prime generators, Mersenne primes](#primality-testing--prime-generators-mersenne-primes)
      - [Cryptographic Hashing](#cryptographic-hashing)
        - [SHA-256 hashing](#sha-256-hashing)
        - [SHA-512 hashing](#sha-512-hashing)
        - [File hashing](#file-hashing)
      - [Symmetric Encryption Interface](#symmetric-encryption-interface)
      - [Crypto Objects General Properties (`CryptoKey`)](#crypto-objects-general-properties-cryptokey)
      - [AES-256 Symmetric Encryption](#aes-256-symmetric-encryption)
        - [Key creation](#key-creation)
        - [AES-256 + GCM (default)](#aes-256--gcm-default)
        - [AES-256 + ECB (unsafe, fixed block only)](#aes-256--ecb-unsafe-fixed-block-only)
      - [RSA (Rivest-Shamir-Adleman) Public Cryptography](#rsa-rivest-shamir-adleman-public-cryptography)
      - [El-Gamal Public-Key Cryptography](#el-gamal-public-key-cryptography)
      - [DSA (Digital Signature Algorithm)](#dsa-digital-signature-algorithm)
        - [Security notes](#security-notes)
        - [Advanced: custom primes generator](#advanced-custom-primes-generator)
      - [Public Bidding](#public-bidding)
      - [SSS (Shamir Shared Secret)](#sss-shamir-shared-secret)
  - [Appendix: Development Instructions](#appendix-development-instructions)
    - [Setup](#setup)
    - [Updating Dependencies](#updating-dependencies)
    - [Creating a New Version](#creating-a-new-version)

## License

Copyright 2026 Daniel Balparda <balparda@github.com>

Licensed under the ***Apache License, Version 2.0*** (the "License"); you may not use this file except in compliance with the License. You may obtain a [copy of the License here](http://www.apache.org/licenses/LICENSE-2.0).

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## Design assumptions / Disclaimers

- The library is built to have reference, reliable, simple implementations of math and crypto primitives (e.g. `RawEncrypt()`/`RawSign()` and friends plus all the low-level primality and modular arithmetic). The issue is not that the library is unsafe, it is that the library is full of places that allow you to shoot yourself in the foot if you don't know what you are doing.
- The library also has advanced top-level methods that are cryptographically safe and might be used in real-world scenarios (e.g. `Encrypt()`/`Sign()` and friends).
- All library methods' `int` are tailored to be efficient with arbitrarily large integers.
- Everything **should work**, as the library is **extensively tested**, *but not necessarily the most efficient or safe for real-world cryptographic use.* For real-world crypto you might consider *other optimized/safe libraries* that were built to be resistant to malicious attacks.
- *All operations in this library may be vulnerable to timing attacks.* This may be a problem to your use-case or not depending on the situation.

All that being said, extreme care was taken that this is a good library with a solid safe implementation. *Have fun!*

## CLI Apps

- [TransCrypto/`transcrypto`](transcrypto.md): Does all the operations but allows you to shoot yourself in the foot;
- [Profiler/`profiler`](profiler.md): Measure transcrypto performance.

## Programming API

### Install

To use in your project just do:

```sh
pip3 install transcrypto
```

and then `from transcrypto.core import rsa` (or other parts of the library) for using it.

Known dependencies:

- [zstandard](https://pypi.org/project/zstandard/) ([docs](https://python-zstandard.readthedocs.org/))
- [cryptography](https://pypi.org/project/cryptography/) ([docs](https://cryptography.io/en/latest/))
- [gmpy2](https://pypi.org/project/gmpy2/) ([docs](https://gmpy2.readthedocs.io/en/latest/))

### Base Library

#### Humanized Sizes (IEC binary)

```py
from transcrypto.utils import human

human.HumanizedBytes(512)                  # '512 B'
human.HumanizedBytes(2048)                 # '2.000 KiB'
human.HumanizedBytes(5 * 1024**3)          # '5.000 GiB'
```

Converts raw byte counts to binary-prefixed strings (`B`, `KiB`, `MiB`, `GiB`, `TiB`, `PiB`, `EiB`).

- For integer inputs `<1024`, returns an integer count with `B` (e.g. `'512 B'`).
- For float inputs `<1024`, returns 3 decimals with `B` (e.g. `'51.200 B'`).
- For values `≥1024`, returns 3 decimals.

- standard: 1 KiB = 1024 B, 1 MiB = 1024 KiB, …
- errors: negative inputs raise `base.InputError`

#### Humanized Decimal Quantities (SI)

```py
from transcrypto.utils import human

# Base (unitless)
human.HumanizedDecimal(950)                # '950'
human.HumanizedDecimal(1500)               # '1.500 k'

# With a unit (trimmed and attached)
human.HumanizedDecimal(1500, unit=' Hz ')  # '1.500 kHz'
human.HumanizedDecimal(0.123456, unit='V') # '123.456 mV'

# Large magnitudes
human.HumanizedDecimal(3_200_000)          # '3.200 M'
human.HumanizedDecimal(7.2e12, unit='B/s') # '7.200 TB/s'
```

Scales by powers of 1000 using SI prefixes to keep the displayed value in roughly `[1, 1000)` when possible.

- Supported large prefixes: `k`, `M`, `G`, `T`, `P`, `E`
- Supported small prefixes: `m`, `µ`, `n`, `p`, `f`, `a`
- Formatting uses 3 decimals for non-integer/unscaled values and for scaled values.

- unit handling: `unit` is stripped; `<1000` values include a space before the unit (`'950 Hz'`)
- errors: non-finite inputs raise `base.InputError` (negative values are supported and keep a leading `-`)

#### Humanized Durations

```py
from transcrypto.utils import human

human.HumanizedSeconds(0)                  # '0.000 s'
human.HumanizedSeconds(0.000004)           # '4.000 µs'
human.HumanizedSeconds(0.25)               # '250.000 ms'
human.HumanizedSeconds(42)                 # '42.000 s'
human.HumanizedSeconds(3661)               # '1.017 h'
human.HumanizedSeconds(172800)             # '2.000 d'
```

Chooses an appropriate time unit based on magnitude and formats with fixed precision:

- `< 1 ms`: microseconds with three decimals (`µs`)
- `< 1 s`: milliseconds with three decimals (`ms`)
- `< 60 s`: seconds with three decimals (`s`)
- `< 60 min`: minutes with three decimals (`min`)
- `< 24 h`: hours with three decimals (`h`)
- `≥ 24 h`: days with three decimals (`d`)
- special case: `0 → '0.000 s'`
- errors: negative or non-finite inputs raise `base.InputError`

#### Execution Timing

A flexible timing utility that works as a **context manager**, **decorator**, or **manual timer object**.

```py
from transcrypto.utils import timer
import time
```

##### Context manager

```py
with timer.Timer('Block timing'):
    time.sleep(1.2)
# → logs: "Block timing: 1.200 s" (default via logging.info)
```

Starts timing on entry, stops on exit, and reports elapsed time automatically.

##### Decorator

```py
@timer.Timer('Function timing')
def slow_function():
    time.sleep(0.8)

slow_function()
# → logs: "Function timing: 0.800 s"
```

Wraps a function so that each call is automatically timed.

##### Manual use

```py
tm = timer.Timer('Inline timing', emit_print=True)
tm.Start()
time.sleep(0.1)
tm.Stop()   # prints: "Inline timing: 0.100 s"
```

Manual control over `Start()` and `Stop()` for precise measurement of custom intervals.

##### Key points

- **Label**: optional; if empty, output omits the label prefix
- **Output**:
  - `emit_log=True` → `logging.info()` (default)
  - `emit_print=True` → prints via `rich.console.Console().print()`
  - Both can be enabled
- **Format**: elapsed time is shown using `HumanizedSeconds()`
- **Safety**:
  - Cannot start an already started timer
  - Cannot stop an unstarted or already stopped timer
    (raises `Error`)

#### Serialization Pipeline

These helpers turn arbitrary Python objects into compressed and/or encrypted binary blobs, and back again — with detailed timing and size logging.

```py
from transcrypto.core import key
```

##### Serialize

```py
data = {'x': 42, 'y': 'hello'}

# Basic serialization
blob = key.Serialize(data)

# With compression and encryption
blob = key.Serialize(
    data,
    compress=9,               # compression level (-22..22, default=3)
    encryption_key=my_encryptor  # must implement `key.Encryptor` (e.g., `aes.AESKey`)
)

# Save directly to file
key.Serialize(data, file_path='/tmp/data.blob')
```

Serialization path:

```text
obj → pickle → (compress) → (encrypt) → (save)
```

At each stage:

- Data size is measured using `HumanizedBytes`
- Duration is timed with `Timer`
- Results are logged once at the end

Compression levels:

`compress` uses `zstandard`; see table below for speed/ratio trade-offs:

| Level    | Speed       | Compression ratio                 | Typical use case                        |
| -------- | ------------| --------------------------------- | --------------------------------------- |
| -5 to -1 | Fastest     | Poor (better than no compression) | Real-time or very latency-sensitive     |
| 0…3      | Very fast   | Good ratio                        | Default CLI choice, safe baseline       |
| 4…6      | Moderate    | Better ratio                      | Good compromise for general persistence |
| 7…10     | Slower      | Marginally better ratio           | Only if storage space is precious       |
| 11…15    | Much slower | Slight gains                      | Large archives, not for runtime use     |
| 16…22    | Very slow   | Tiny gains                        | Archival-only, multi-GB datasets        |

Errors: invalid compression level is clamped to range; other input errors raise `base.InputError`.

##### DeSerialize

```py
# From in-memory blob
obj = key.DeSerialize(data=blob)

# From file
obj = key.DeSerialize(file_path='/tmp/data.blob')

# With decryption
obj = key.DeSerialize(data=blob, decryption_key=my_decryptor)
```

Deserialization path:

```text
data/file → (decrypt) → (decompress if Zstd) → unpickle
```

- Compression is auto-detected via Zstandard magic numbers.
- All steps are timed/logged like in `Serialize`.

**Constraints & errors**:

- Exactly one of `data` or `file_path` must be provided.
- `file_path` must exist; `data` must be at least 4 bytes.
- Wrong key / authentication failure can raise `key.CryptoError`.
- Corrupted compressed blobs typically raise `zstandard.ZstdError` during decompression.

#### Cryptographically Secure Randomness

These helpers live in `saferandom` and wrap Python’s `secrets` with additional checks and guarantees for crypto use-cases.

```py
from transcrypto.core import bid
```

##### Fixed-size random integers

```py
# Generate a 256-bit integer (first bit always set)
r = saferandom.RandBits(256)
assert r.bit_length() == 256
```

Produces a crypto-secure random integer with exactly `n_bits` bits (`≥ 8`). The most significant bit is guaranteed to be `1`, so entropy is \~`n_bits−1` — negligible for large crypto sizes.

- errors: `n_bits < 8` → `base.InputError`

##### Uniform random integers in a range

```py
# Uniform between [10, 20] inclusive
n = saferandom.RandInt(10, 20)
assert 10 <= n <= 20
```

Returns a crypto-secure integer uniformly distributed over the closed interval `[min_int, max_int]`.

- constraints: `min_int ≥ 0` and `< max_int`
- errors: invalid bounds → `base.InputError`

##### In-place secure shuffle

```py
deck = list(range(10))
saferandom.RandShuffle(deck)
print(deck)   # securely shuffled order
```

Performs an in-place Fisher–Yates shuffle using `secrets.randbelow`. Suitable for sensitive data ordering.

- constraints: sequence length ≥ 2
- errors: shorter sequences → `base.InputError`

##### Random byte strings

```py
# 32 random bytes
b = saferandom.RandBytes(32)
assert len(b) == 32
```

Generates `n_bytes` of high-quality crypto-secure random data.

- constraints: `n_bytes ≥ 1`
- errors: smaller values → `base.InputError`

#### Computing the Greatest Common Divisor

```py
>>> from transcrypto.core import modmath
>>> modmath.GCD(462, 1071)
21
>>> modmath.GCD(0, 17)
17
```

The function is `O(log(min(a, b)))` and handles arbitrarily large integers. To find Bézout coefficients `(x, y)` such that `ax + by = gcd(a, b)` do:

```py
>>> modmath.ExtendedGCD(462, 1071)
(21, 7, -3)
>>> 462 * 7 + 1071 * (-3)
21
```

Use-cases:

- modular inverses: `inv = x % m` when `gcd(a, m) == 1`
- solving linear Diophantine equations
- RSA / ECC key generation internals

#### Fast Modular Arithmetic

```py
from transcrypto.core import modmath

m = 2**256 - 189    # a large prime modulus

# Inverse ──────────────────────────────
x = 123456789
x_inv = modmath.ModInv(x, m)
assert (x * x_inv) % m == 1

# Division (x / y) mod m ──────────────
y = 987654321
z = modmath.ModDiv(x, y, m)      # solves z·y ≡ x (mod m)
assert (z * y) % m == x % m

# Exponentiation ──────────────────────
exp = modmath.ModExp(3, 10**20, m)   # ≈ log₂(y) time, handles huge exponents
```

##### Chinese Remainder Theorem (CRT) – Pair

```py
from transcrypto.core import modmath

# Solve:
#   x ≡ 2 (mod 3)
#   x ≡ 3 (mod 5)
x = modmath.CRTPair(2, 3, 3, 5)
print(x)             # 8
assert x % 3 == 2
assert x % 5 == 3
```

Solves a system of two simultaneous congruences with **pairwise co-prime** moduli, returning the **least non-negative solution** `x` such that:

```text
x ≡ a1 (mod m1)
x ≡ a2 (mod m2)
0 ≤ x < m1 * m2
```

- **Requirements**:
  - `m1 ≥ 2`, `m2 ≥ 2`, `m1 != m2`
  - `gcd(m1, m2) == 1` (co-prime)
- **Errors**:
  - invalid modulus values → `base.InputError`
  - non co-prime moduli → `ModularDivideError`

This function is a 2-modulus variant; for multiple moduli, apply it iteratively or use a general CRT solver.

##### Modular Polynomials & Lagrange Interpolation

```py
# f(t) = 7t³ − 3t² + 2t + 5  (coefficients constant-term first)
coefficients = [5, 2, -3, 7]
print(modmath.ModPolynomial(11, coefficients, 97))   # → 19

# Given three points build the degree-≤2 polynomial and evaluate it.
pts = {2: 4, 5: 3, 7: 1}
print(modmath.ModLagrangeInterpolate(9, pts, 11))   # → 2
```

#### Primality testing & Prime generators, Mersenne primes

```py
modmath.IsPrime(2**127 - 1)              # True  (Mersenne prime)
modmath.IsPrime(3825123056546413051)     # False (strong pseudo-prime)

# Direct Miller–Rabin with custom witnesses
modmath.MillerRabinIsPrime(961748941, witnesses={2,7,61})

# Infinite iterator of primes ≥ 10⁶
for p in modmath.PrimeGenerator(1_000_000):
  print(p)
  if p > 1_000_100:
    break

# Secure random 384-bit prime (for RSA/ECC experiments)
p384 = modmath.NBitRandomPrimes(384).pop()

for k, m_p, perfect in modmath.MersennePrimesGenerator(0):
  print(f'p = {k:>8}  M = {m_p}  perfect = {perfect}')
  if k > 10000:          # stop after a few
    break
```

#### Cryptographic Hashing

Simple, fixed-output-size wrappers over Python’s `hashlib` for common digest operations, plus file hashing.

```py
from transcrypto.core import hashes
```

##### SHA-256 hashing

```py
h = hashes.Hash256(b'hello world')
assert len(h) == 32                       # bytes
print(h.hex())                            # 64 hex chars
```

Computes the SHA-256 digest of a byte string, returning exactly 32 bytes (256 bits). Suitable for fingerprints, commitments, or internal crypto primitives.

##### SHA-512 hashing

```py
h = hashes.Hash512(b'hello world')
assert len(h) == 64                       # bytes
print(h.hex())                            # 128 hex chars
```

Computes the SHA-512 digest of a byte string, returning exactly 64 bytes (512 bits). Higher collision resistance and larger output space than SHA-256.

##### File hashing

```py
# Default SHA-256
fh = hashes.FileHash('/path/to/file')
print(fh.hex())

# SHA-512
fh2 = hashes.FileHash('/path/to/file', digest='sha512')
```

Hashes a file from disk in streaming mode. By default uses SHA-256; `digest='sha512'` switches to SHA-512.

- constraints:
  - `digest` must be `'sha256'` or `'sha512'`
  - `full_path` must exist
- errors: invalid digest or missing file → `base.InputError`

#### Symmetric Encryption Interface

`key.Encryptor` and `key.Decryptor` are runtime-checkable protocols that define the **byte-in / byte-out** contract for symmetric ciphers.

- **Metadata handling** — if the algorithm uses a `nonce` or `tag`, the implementation must handle it internally (e.g., append it to ciphertext).
- **AEAD modes** — if supported, `associated_data` must be authenticated; otherwise, a non-`None` value should raise `base.InputError`.

```py
from transcrypto.core import key

class MyAES(key.Encryptor, key.Decryptor):
    def Encrypt(self, plaintext: bytes, *, associated_data=None) -> bytes:
        ...
    def Decrypt(self, ciphertext: bytes, *, associated_data=None) -> bytes:
        ...
```

#### Crypto Objects General Properties (`CryptoKey`)

Cryptographic objects all derive from the `CryptoKey` class and will all have some important characteristics:

- Will be safe to log and print, i.e., implement safe `__str__()` and `__repr__()` methods (in actuality `repr` will be exactly the same as `str`). The `__str__()` should always fully print the public parts of the object and obfuscate the private ones. This obfuscation allows for some debugging, if needed, but if the secrets are "too short" then it can be defeated by brute force. For usual crypto defaults the obfuscation is fine. The obfuscation is the fist 4 bytes of the SHA-512 for the value followed by an ellipsis (e.g. `c9626f16…`).
- It will have a `_DebugDump()` method that **does print secrets** and can be used for **debugging only**.
- Can be easily serialized to `bytes` by the `blob` property and to base-64 encoded `str` by the `encoded` property.
- Can be serialized encrypted to `bytes` by the `Blob(encryption_key=[key.Encryptor])` method and to encrypted base-64 encoded `str` by the `Encoded(encryption_key=[key.Encryptor])` method.
- Can be instantiated back as an object from `str` or `bytes` using the `Load(data, decryption_key=[key.Decryptor] | None)` method. The `Load()` will decide how to build the object and will work universally with all the serialization options discussed above.

Example:

<!-- cspell:disable -->
```py
from transcrypto.core import aes, rsa

priv = rsa.RSAPrivateKey.New(512)  # small key, but good for this example
print(str(priv))                   # safe, no secrets
# ▶ RSAPrivateKey(RSAPublicKey(public_modulus=pQaoxy-QeXSds1k9WsGjJw==, encrypt_exp=AQAB), modulus_p=f18141aa…, modulus_q=67494eb9…, decrypt_exp=c96db24a…)

print(priv._DebugDump())  # UNSAFE: prints secrets
# ▶ RSAPrivateKey(public_modulus=219357196311600536151291741191131996967, encrypt_exp=65537, modulus_p=13221374197986739361, modulus_q=16591104148992527047, decrypt_exp=37805202135275158391322585315542443073, remainder_p=9522084656682089473, remainder_q=8975656462800098363, q_inverse_p=11965562396596149292)

print(priv.blob)
# ▶ b"(\xb5/\xfd \x98\xc1\x04\x00\x80\x04\x95\x8d\x00\x00\x00\x00\x00\x00\x00\x8c\x0ftranscrypto.rsa\x94\x8c\rRSAPrivateKey\x94\x93\x94)\x81\x94]\x94(\x8a\x11'\xa3\xc1Z=Y\xb3\x9dty\x90/\xc7\xa8\x06\xa5\x00J\x01\x00\x01\x00\x8a\t\xa1\xc4\x83\x81\xc8\xc1{\xb7\x00\x8a\t\xc7\x8a5\xf0Qq?\xe6\x00\x8a\x10A$&\x82!\x1cy\x89r\xef\xeb\xa7_\x04q\x1c\x8a\t\x01\xbc\xbb\x8a\x8b=%\x84\x00\x8a\x08;\x94#s\xff\xef\x8f|\x8a\t,\x9c\xe2z\x9a7\x0e\xa6\x00eb."

print(priv.encoded)
# ▶ KLUv_WBwAIELAIAElWUBAAAAAAAAjA90cmFuc2NyeXB0by5yc2GUjA1SU0FQcml2YXRlS2V5lJOUKYGUXZQoikHf1EvsmZedAZve7TrLmobLAwuRIr_77TLG6G_0fsLGThERVJu075be8PLjUQYnLXcacZFQ5Fb1Iy1WtiE985euAEoBAAEAiiFR9ngiXMzkf41o5CRBY3h0D4DJVisDDhLmAWsiaHggzQCKIS_cmQ6MKXCtROtC7c_Mrsi9A-9NM8DksaHaRwvy6uTZAIpB4TVbsLxc41TEc19wIzpxbi9y5dW5gdfTkRQSSiz0ijmb8Xk3pyBfKAv8JbHp8Yv48gNZUfX67qq0J7yhJqeUoACKIbFb2kTNRzSqm3JRtjc2BPS-FnLFdadlFcV4-6IW7eqLAIogFZfzDN39gZLR9uTz4KHSTaqxWrJgP8-YYssjss6FlFKKIIItgCDv7ompNpY8gBs5bibN8XTsr-JOYSntDVT5Fe5vZWIu

aes_key = aes.AESKey(key256=b'x' * 32)
print(aes_key)
# ▶ AESKey(key256=86a86df7…)

encrypted = priv.Blob(encryption_key=aes_key)
print(priv == rsa.RSAPrivateKey.Load(encrypted, decryption_key=aes_key))
# ▶ True
```
<!-- cspell:enable -->

#### AES-256 Symmetric Encryption

Implements AES-256 in **GCM mode** for authenticated encryption and decryption, plus an **ECB mode** helper for fixed-size block encoding.
Also includes a high-iteration PBKDF2-based key derivation from static passwords.

##### Key creation

```py
from transcrypto.core import aes

# From raw bytes (must be exactly 32 bytes)
aes_key = aes.AESKey(key256=b'\x00' * 32)

# From a static password (slow, high-iteration PBKDF2-SHA256)
aes_key = aes.AESKey.FromStaticPassword('correct horse battery staple')
print(aes_key.encoded)  # URL-safe Base64
```

- **Length**: `key256` must be exactly 32 bytes
- `FromStaticPassword()`:
  - Uses PBKDF2-HMAC-SHA256 with **fixed** salt and \~2 million iterations
  - Designed for **interactive** password entry, **not** for password databases

##### AES-256 + GCM (default)

```py
data = b'secret message'
aad  = b'metadata'

# Encrypt (returns IV + ciphertext + tag)
ct = aes_key.Encrypt(data, associated_data=aad)

# Decrypt
pt = aes_key.Decrypt(ct, associated_data=aad)
assert pt == data
```

- **Security**:
  - Random 128-bit IV (`iv`) per encryption
  - Authenticated tag (128-bit) ensures integrity
  - Optional `associated_data` is authenticated but not encrypted
- **Errors**:
  - Tag mismatch or wrong key → `key.CryptoError`

##### AES-256 + ECB (unsafe, fixed block only)

```py
# ECB mode is for 16-byte block encoding ONLY
ecb = aes_key.ECBEncoder()

block = b'16-byte string!!'
ct_block = ecb.Encrypt(block)
pt_block = ecb.Decrypt(ct_block)
assert pt_block == block

# Hex helpers
hex_ct = ecb.EncryptHex('00112233445566778899aabbccddeeff')  # 128 bits (1 block)
hex_pt = ecb.DecryptHex(hex_ct)
assert hex_pt == '00112233445566778899aabbccddeeff'
hex_ct2 = ecb.EncryptHex256('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')
hex_pt2 = ecb.DecryptHex256(hex_ct2)
assert hex_pt2 == '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
```

- **ECB mode**:
  - 16-byte plaintext ↔ 16-byte ciphertext
  - No padding, no IV, no integrity — **do not use for general encryption**
  - `associated_data` not supported

Key points:

- **GCM mode** is secure for general use; ECB mode is for special low-level operations
- **Static password derivation** is intentionally slow to resist brute force
- All sizes and parameters are validated with `base.InputError` on misuse

#### RSA (Rivest-Shamir-Adleman) Public Cryptography

<https://en.wikipedia.org/wiki/RSA_cryptosystem>

This implementation is raw RSA, no OAEP or PSS! It works on the actual integers. For real uses you should look for higher-level implementations.

By default and deliberate choice the *encryption exponent* will be either 7 or 65537, depending on the size of `phi=(p-1)*(q-1)`. If `phi` allows it the larger one will be chosen to avoid Coppersmith attacks.

```py
from transcrypto.core import rsa

# Generate a key pair
priv = rsa.RSAPrivateKey.New(2048)        # 2048-bit modulus
pub  = rsa.RSAPublicKey.Copy(priv)        # public half
print(priv.public_modulus.bit_length())   # 2048

# Safe Encrypt & decrypt
msg = b'xyz'
cipher = pub.Encrypt(msg, associated_data=b'aad')
plain  = priv.Decrypt(cipher, associated_data=b'aad')
assert plain == msg

# Safe Sign & verify
signature = priv.Sign(msg)  # can also have associated_data, optionally
assert pub.Verify(msg, signature)

# Raw Encrypt & decrypt
msg = 123456789  # (Zero is forbidden by design; smallest valid message is 1.)
cipher = pub.RawEncrypt(msg)
plain  = priv.RawDecrypt(cipher)
assert plain == msg

# Raw Sign & verify
signature = priv.RawSign(msg)
assert pub.RawVerify(msg, signature)

# Blind signatures (obfuscation pair) - only works on raw RSA
pair = rsa.RSAObfuscationPair.New(pub)

blind_msg = pair.ObfuscateMessage(msg)            # what you send to signer
blind_sig = priv.RawSign(blind_msg)               # signer’s output

sig = pair.RevealOriginalSignature(msg, blind_sig)
assert pub.RawVerify(msg, sig)
```

#### El-Gamal Public-Key Cryptography

[https://en.wikipedia.org/wiki/ElGamal\_encryption](https://en.wikipedia.org/wiki/ElGamal_encryption)

This is **raw El-Gamal** over a prime field — no padding, no hashing — and is **not** DSA.
For real-world deployments, use a high-level library with authenticated encryption and proper encoding.

```py
from transcrypto.core import elgamal

# Shared parameters (prime modulus, group base) for a group
shared = elgamal.ElGamalSharedPublicKey.NewShared(256)
print(shared.prime_modulus)
print(shared.group_base)

# Public key from private
priv = elgamal.ElGamalPrivateKey.New(shared)
pub  = elgamal.ElGamalPublicKey.Copy(priv)

# Safe Encrypt & decrypt
msg = b'xyz'
cipher = pub.Encrypt(msg, associated_data=b'aad')
plain  = priv.Decrypt(cipher, associated_data=b'aad')
assert plain == msg

# Safe Sign & verify
signature = priv.Sign(msg)  # can also have associated_data, optionally
assert pub.Verify(msg, signature)

# Raw Encryption
msg = 42
cipher = pub.RawEncrypt(msg)
plain = priv.RawDecrypt(cipher)
assert plain == msg

# Raw Signature verify
sig = priv.RawSign(msg)
assert pub.RawVerify(msg, sig)
```

Key points:

- **Security parameters**:
  - Recommended `prime_modulus` bit length ≥ 2048 for real security
  - Random values from `saferandom.RandBits`
- **Ephemeral keys**:
  - Fresh per encryption/signature
  - Must satisfy `gcd(k, p-1) == 1`
- **Errors**:
  - Bad ranges → `base.InputError`
  - Invalid math relationships → `key.CryptoError`
- **Group sharing**:
  - Multiple parties can share `(p, g)` but have different `(individual_base, decrypt_exp)`

#### DSA (Digital Signature Algorithm)

[https://en.wikipedia.org/wiki/Digital\_Signature\_Algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)

This is **raw DSA** over a prime field — **no hashing or padding**. You sign/verify **integers** modulo `q` (`prime_seed`). For real use, hash the message first (e.g., SHA-256) and then map to an integer `< q`.

```py
from transcrypto.core import dsa

# Shared parameters (p, q, g) - Safe Sign/Verify requires q > 512 bits
shared = dsa.DSASharedPublicKey.NewShared(2048, 520)
print(shared.prime_modulus)  # p
print(shared.prime_seed)     # q  (q | p-1)
print(shared.group_base)     # g

# Individual key pair
priv = dsa.DSAPrivateKey.New(shared)
pub  = dsa.DSAPublicKey.Copy(priv)

# Safe Sign & verify
msg = b'xyz'
signature = priv.Sign(msg)  # can also have associated_data, optionally
assert pub.Verify(msg, signature)

# Raw Sign & verify (message must be 1 ≤ m < q)
msg = 123456789 % shared.prime_seed
sig = priv.RawSign(msg)
assert pub.RawVerify(msg, sig)
```

- ranges:
  - `1 ≤ message < q`
  - signatures: `(s1, s2)` with `2 ≤ s1, s2 < q`
- errors:
  - invalid ranges → `base.InputError`
  - inconsistent parameters → `key.CryptoError`

##### Security notes

- Choose **large** parameters (e.g., `p ≥ 2048 bits`, `q ≥ 224 bits`) for non-toy settings.
- In practice, compute `m = int.from_bytes(Hash(message), 'big') % q` before calling `Sign(m)`.

##### Advanced: custom primes generator

```py
# Generate primes (p, q) with q | (p-1); also returns m = (p-1)//q
p, q, m = dsa.NBitRandomDSAPrimes(1024, 160)
assert (p - 1) % q == 0
```

Used internally by `DSASharedPublicKey.NewShared()`.
Search breadth and retry caps are bounded; repeated failures raise `key.CryptoError`.

#### Public Bidding

This is a way of bidding on some commitment (the `secret`) that can be cryptographically proved later to not have been changed. To do that the secret is combined with 2 nonces (random values, `n1` & `n2`) and a hash of it is taken (`H=SHA-512(n1||n2||secret)`). The hash `H` and one nonce `n1` are public and divulged. The other nonce `n2` and the `secret` are kept private and will be used to show `secret` was not changed since the beginning of the process. The nonces guarantee the `secret` cannot be brute-forced or changed after-the-fact. The whole process is as strong as SHA-512 collisions.

```py
from transcrypto.core import bid

# Generate the private and public bids
bid_priv = bid.PrivateBid512.New(secret)    # this one you keep private
bid_pub = bid.PublicBid512.Copy(bid_priv)   # this one you publish

# Checking that a bid is genuine requires the public bid and knowing the nonce and the secret:
print(bid_pub.VerifyBid(private_key, secret_bid))  # these come from a divulged private bid
# of course, you want to also make sure the provided private data matches your version of it, e.g.:
bid_pub_expected = bid.PublicBid512.Copy(bid_priv)
print(bid_pub == bid_pub_expected)
```

#### SSS (Shamir Shared Secret)

<https://en.wikipedia.org/wiki/Shamir's_secret_sharing>

This is the information-theoretic SSS but with no authentication or binding between share and secret. Malicious share injection is possible! Add MAC or digital signature in hostile settings. Use at least 128-bit modulus for non-toy deployments; `MakeDataShares()` requires > 256 bits.

```py
from transcrypto.core import sss

# Generate parameters: at least 3 of 5 shares needed,
# coefficients & modulus are 264-bit primes (> 256 bits required for MakeDataShares)
priv = sss.ShamirSharedSecretPrivate.New(3, 264)
pub  = sss.ShamirSharedSecretPublic.Copy(priv)   # what you publish

print(f'threshold        : {pub.minimum}')
print(f'prime mod        : {pub.modulus}')
print(f'poly coefficients: {priv.polynomial}')         # keep these private!

# Safe Issuing shares

secret = b'xyz'
# Generate 5 shares, each has a copy of the encrypted secret
five_shares = priv.MakeDataShares(secret, 5)
for sh in five_shares:
  print(sh)

# Raw Issuing shares

secret = 0xC0FFEE
# Generate an unlimited stream; here we take 5
five_shares = list(priv.RawShares(secret, max_shares=5))
for sh in five_shares:
  print(f'share {sh.share_key} → {sh.share_value}')
```

A single share object looks like `sss.ShamirSharePrivate(minimum=3, modulus=..., share_key=42, share_value=123456789)`.

```py
# Safe Re-constructing the secret
secret = b'xyz'
five_shares = priv.MakeDataShares(secret, 5)
subset = five_shares[:3]                        # any 3 distinct shares
recovered = subset[0].RecoverData(subset[1:])   # each share has the encrypted data, pass other shares
assert recovered == secret

# Raw Re-constructing the secret
secret = 0xC0FFEE
five_shares = list(priv.RawShares(secret, max_shares=5))
subset = five_shares[:3]          # any 3 distinct shares
recovered = pub.RawRecoverSecret(subset)
assert recovered == secret
```

If you supply fewer than minimum shares you get a `key.CryptoError`, unless you explicitly override:

```py
try:
  pub.RawRecoverSecret(five_shares[:2])        # raises
except Exception as e:
  print(e)                                  # "unrecoverable secret …"

# Force the interpolation even with 2 points (gives a wrong secret, of course)
print(pub.RawRecoverSecret(five_shares[:2], force_recover=True))

# Checking that a share is genuine

share = five_shares[0]
ok = priv.RawVerifyShare(secret, share)       # ▶ True
tampered = sss.ShamirSharePrivate(
    minimum=share.minimum,
    modulus=share.modulus,
    share_key=share.share_key,
    share_value=(share.share_value + 1) % share.modulus)
print(priv.RawVerifyShare(secret, tampered))  # ▶ False
```

## Appendix: Development Instructions

### Setup

If you want to develop for this project, first install python 3.12 and [Poetry](https://python-poetry.org/docs/cli/), but to get the versions you will need, we suggest you do it like this (*Linux*):

```sh
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install git python3 python3-pip pipx python3-dev python3-venv build-essential software-properties-common

sudo add-apt-repository ppa:deadsnakes/ppa  # install arbitrary python version
sudo apt-get update
sudo apt-get install python3.12

sudo apt-get remove python3-poetry
python3.12 -m pipx ensurepath
# re-open terminal
pipx install poetry
poetry --version  # should be >=2.1

poetry config virtualenvs.in-project true  # creates .venv inside project directory
poetry config pypi-token.pypi <TOKEN>      # add your personal PyPI project token, if any
```

or this (*Mac*):

```sh
brew update
brew upgrade
brew cleanup -s

brew install git python@3.12  # install arbitrary python version

brew uninstall poetry
python3.12 -m pip install --user pipx
python3.12 -m pipx ensurepath
# re-open terminal
pipx install poetry
poetry --version  # should be >=2.1

poetry config virtualenvs.in-project true  # creates .venv inside project directory
poetry config pypi-token.pypi <TOKEN>      # add your personal PyPI project token, if any
```

Now install the project:

```sh
git clone https://github.com/balparda/transcrypto.git transcrypto
cd transcrypto

poetry env use python3.12  # creates the venv
poetry sync                # sync env to project's poetry.lock file
poetry env info            # no-op: just to check

poetry run pytest -vvv
# or any command as:
poetry run <any-command>
```

To activate like a regular environment do:

```sh
poetry env activate
# will print activation command which you next execute, or you can do:
source .venv/bin/activate                        # if .venv is local to the project
source "$(poetry env info --path)/bin/activate"  # for other paths

pytest  # or other commands

deactivate
```

### Updating Dependencies

To update `poetry.lock` file to more current versions do `poetry update`, it will ignore the current lock, update, and rewrite the `poetry.lock` file. If you have cache problems `poetry cache clear PyPI --all` will clean it.

To add a new dependency you should do:

```sh
poetry add "pkg>=1.2.3"  # regenerates lock, updates env (adds dep to prod code)
poetry add -G dev "pkg>=1.2.3"  # adds dep to dev code ("group" dev)
# also remember: "pkg@^1.2.3" = latest 1.* ; "pkg@~1.2.3" = latest 1.2.* ; "pkg@1.2.3" exact
```

If you manually added a dependency to `pyproject.toml` you should ***very carefully*** recreate the environment and files:

```sh
rm -rf .venv .poetry poetry.lock
poetry env use python3.12
poetry install
```

Remember to check your diffs before submitting (especially `poetry.lock`) to avoid surprises!

When dependencies change, always regenerate `requirements.txt` by running:

```sh
make req  # or: poetry export --format requirements.txt --without-hashes --output requirements.txt
```

### Creating a New Version

```sh
# bump the version!
poetry version minor  # updates 1.6 to 1.7, for example
# or:
poetry version patch  # updates 1.6 to 1.6.1
# or:
poetry version <version-number>
# (also updates `pyproject.toml` and `poetry.lock`)

# publish to GIT, including a TAG
git commit -a -m "release version 1.0.2"
git tag 1.0.2
git push
git push --tags

# prepare package for PyPI
poetry build
poetry publish
```

If you changed the CLI interface at all, in any tool, run `make docs` or even better `make ci`.

You can find the 10 top slowest tests by running:

```sh
poetry run pytest -vvv -q --durations=30

poetry run pytest -vvv -q --durations=30 -m "not slow"      # find slow > 0.1s
poetry run pytest -vvv -q --durations=30 -m "not veryslow"  # find veryslow > 1s

poetry run pytest -vvv -q --durations=30 -m slow      # check
poetry run pytest -vvv -q --durations=30 -m veryslow  # check
```

You can search for flaky tests by running all tests 100 times, or more:

```sh
poetry run pytest --flake-finder --flake-runs=100
poetry run pytest --flake-finder --flake-runs=500 -m "not veryslow"
poetry run pytest --flake-finder --flake-runs=10000 -m "not slow"
```

You can instrument your code to find bottlenecks:

```sh
$ source .venv/bin/activate
$ which transcrypto
/path/to/.venv/bin/transcrypto  # place this in the command below:
$ pyinstrument -r html -o dsa_shared.html -- /path/to/.venv/bin/transcrypto -p rsa-key rsa new
$ deactivate
```

Hint: 85%+ is inside `MillerRabinIsPrime()`/`gmpy2.powmod()`...
