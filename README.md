# TransCrypto

Basic cryptography primitives implementation, a companion to *"Criptografia, Métodos e Algoritmos"*.

Started in July/2025, by Daniel Balparda. Since version 1.0.2 it is PyPI package:

<https://pypi.org/project/transcrypto/>

- [TransCrypto](#transcrypto)
  - [License](#license)
  - [Design assumptions / Disclaimers](#design-assumptions--disclaimers)
  - [Install](#install)
  - [Command-Line Interface](#command-line-interface)
    - [Global Options](#global-options)
    - [Top-Level Commands](#top-level-commands)
    - [`random`](#random)
      - [`random bits`](#random-bits)
      - [`random int`](#random-int)
      - [`random bytes`](#random-bytes)
      - [`random prime`](#random-prime)
    - [`isprime`](#isprime)
    - [`primegen`](#primegen)
    - [`mersenne`](#mersenne)
    - [`gcd`](#gcd)
    - [`xgcd`](#xgcd)
    - [`mod`](#mod)
      - [`mod inv`](#mod-inv)
      - [`mod div`](#mod-div)
      - [`mod exp`](#mod-exp)
      - [`mod poly`](#mod-poly)
      - [`mod lagrange`](#mod-lagrange)
      - [`mod crt`](#mod-crt)
    - [`hash`](#hash)
      - [`hash sha256`](#hash-sha256)
      - [`hash sha512`](#hash-sha512)
      - [`hash file`](#hash-file)
    - [`aes`](#aes)
      - [`aes key`](#aes-key)
      - [`aes encrypt`](#aes-encrypt)
      - [`aes decrypt`](#aes-decrypt)
      - [`aes ecb`](#aes-ecb)
      - [`aes ecb encrypt`](#aes-ecb-encrypt)
      - [`aes ecb decrypt`](#aes-ecb-decrypt)
    - [`rsa`](#rsa)
      - [`rsa new`](#rsa-new)
      - [`rsa rawencrypt`](#rsa-rawencrypt)
      - [`rsa rawdecrypt`](#rsa-rawdecrypt)
      - [`rsa rawsign`](#rsa-rawsign)
      - [`rsa rawverify`](#rsa-rawverify)
    - [`elgamal`](#elgamal)
      - [`elgamal shared`](#elgamal-shared)
      - [`elgamal new`](#elgamal-new)
      - [`elgamal rawencrypt`](#elgamal-rawencrypt)
      - [`elgamal rawdecrypt`](#elgamal-rawdecrypt)
      - [`elgamal rawsign`](#elgamal-rawsign)
      - [`elgamal rawverify`](#elgamal-rawverify)
    - [`dsa`](#dsa)
      - [`dsa shared`](#dsa-shared)
      - [`dsa new`](#dsa-new)
      - [`dsa rawsign`](#dsa-rawsign)
      - [`dsa rawverify`](#dsa-rawverify)
    - [`bid`](#bid)
      - [`bid new`](#bid-new)
      - [`bid verify`](#bid-verify)
    - [`sss`](#sss)
      - [`sss new`](#sss-new)
      - [`sss rawshares`](#sss-rawshares)
      - [`sss rawrecover`](#sss-rawrecover)
      - [`sss rawverify`](#sss-rawverify)
    - [`doc`](#doc)
      - [`doc md`](#doc-md)
    - [Base Library](#base-library)
      - [Humanized Sizes (IEC binary)](#humanized-sizes-iec-binary)
      - [Humanized Decimal Quantities (SI)](#humanized-decimal-quantities-si)
      - [Humanized Durations](#humanized-durations)
      - [Cryptographically Secure Randomness](#cryptographically-secure-randomness)
        - [Fixed-size random integers](#fixed-size-random-integers)
        - [Uniform random integers in a range](#uniform-random-integers-in-a-range)
        - [In-place secure shuffle](#in-place-secure-shuffle)
        - [Random byte strings](#random-byte-strings)
      - [Computing the Greatest Common Divisor](#computing-the-greatest-common-divisor)
      - [Cryptographic Hashing](#cryptographic-hashing)
        - [SHA-256 hashing](#sha-256-hashing)
        - [SHA-512 hashing](#sha-512-hashing)
        - [File hashing](#file-hashing)
      - [Execution Timing](#execution-timing)
        - [Context manager](#context-manager)
        - [Decorator](#decorator)
        - [Manual use](#manual-use)
        - [Key points](#key-points)
      - [Symmetric Encryption Interface](#symmetric-encryption-interface)
      - [Serialization Pipeline](#serialization-pipeline)
        - [Serialize](#serialize)
        - [DeSerialize](#deserialize)
      - [Crypto Objects General Properties (`CryptoKey`)](#crypto-objects-general-properties-cryptokey)
      - [AES-256 Symmetric Encryption](#aes-256-symmetric-encryption)
        - [Key creation](#key-creation)
        - [AES-256 + GCM (default)](#aes-256--gcm-default)
        - [AES-256 + ECB (unsafe, fixed block only)](#aes-256--ecb-unsafe-fixed-block-only)
      - [Fast Modular Arithmetic](#fast-modular-arithmetic)
      - [Chinese Remainder Theorem (CRT) – Pair](#chinese-remainder-theorem-crt--pair)
      - [Modular Polynomials \& Lagrange Interpolation](#modular-polynomials--lagrange-interpolation)
      - [Primality testing \& Prime generators, Mersenne primes](#primality-testing--prime-generators-mersenne-primes)
      - [RSA (Rivest-Shamir-Adleman) Public Cryptography](#rsa-rivest-shamir-adleman-public-cryptography)
      - [El-Gamal Public-Key Cryptography](#el-gamal-public-key-cryptography)
        - [Shared Public Key](#shared-public-key)
        - [Public Key](#public-key)
        - [Private Key](#private-key)
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

Copyright 2025 Daniel Balparda <balparda@github.com>

Licensed under the ***Apache License, Version 2.0*** (the "License"); you may not use this file except in compliance with the License. You may obtain a [copy of the License here](http://www.apache.org/licenses/LICENSE-2.0).

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## Design assumptions / Disclaimers

- The library is built to have reference, reliable, simple implementations of math and crypto primitives.
- All library methods' `int` are tailored to be efficient with arbitrarily large integers.
- Everything **should work**, as the library is **extensively tested**, *but not necessarily the most efficient or safe for real-world cryptographic use.* For real-world crypto use *other optimized/safe libraries* that were built to be resistant to malicious attacks.
- *All operations in this library may be vulnerable to timing attacks.*
- There is some logging and error messages that were written to be clear but in real-life security applications could leak private secrets. Again, this library is not build to be crypto safe. It was built as a simple tested reference implementation.

That being said, all care was taken that this is a good library with a solid implementation. *Have fun!*

## Install

To use in your project just do:

```sh
pip3 install transcrypto
```

and then `from transcrypto import rsa` (or other parts of the library) for using it.

Known dependencies:

- [zstandard](https://pypi.org/project/zstandard/) ([docs](https://python-zstandard.readthedocs.org/))
- [cryptography](https://pypi.org/project/cryptography/) ([docs](https://cryptography.io/en/latest/))

<!-- cspell:disable -->

<!-- (auto-generated; do not edit between START/END) -->
<!-- INCLUDE:CLI.md START -->

## Command-Line Interface

`transcrypto` is a command-line utility that provides access to all core functionality described in this documentation. It serves as a convenient wrapper over the Python APIs, enabling **cryptographic operations**, **number theory functions**, **secure randomness generation**, **hashing**, **AES**, **RSA**, **El-Gamal**, **DSA**, **bidding**, **SSS**, and other utilities without writing code.

Invoke with:

```bash
poetry run transcrypto <command> [sub-command] [options...]
```

### Global Options

| Option/Arg | Description |
|---|---|
| `-v, --verbose` | Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG) |
| `--hex` | Treat inputs as hex string (default) |
| `--b64` | Treat inputs as base64url |
| `--bin` | Treat inputs as binary (bytes) |
| `--out-hex` | Outputs as hex (default) |
| `--out-b64` | Outputs as base64url |
| `--out-bin` | Outputs as binary (bytes) |
| `-p, --key-path` | File path to serialized key object, if key is needed for operation [type: str] |
| `--protect` | Password to encrypt/decrypt key file if using the `-p`/`--key-path` option [type: str] |

### Top-Level Commands

- **`random`** — `poetry run transcrypto random [-h] {bits,int,bytes,prime} ...`
- **`isprime`** — `poetry run transcrypto isprime [-h] n`
- **`primegen`** — `poetry run transcrypto primegen [-h] [-c COUNT] start`
- **`mersenne`** — `poetry run transcrypto mersenne [-h] [-k MIN_K] [-C CUTOFF_K]`
- **`gcd`** — `poetry run transcrypto gcd [-h] a b`
- **`xgcd`** — `poetry run transcrypto xgcd [-h] a b`
- **`mod`** — `poetry run transcrypto mod [-h] {inv,div,exp,poly,lagrange,crt} ...`
- **`hash`** — `poetry run transcrypto hash [-h] {sha256,sha512,file} ...`
- **`aes`** — `poetry run transcrypto aes [-h] {key,encrypt,decrypt,ecb} ...`
- **`rsa`** — `poetry run transcrypto rsa [-h] {new,rawencrypt,rawdecrypt,rawsign,rawverify} ...`
- **`elgamal`** — `poetry run transcrypto elgamal [-h] {shared,new,rawencrypt,rawdecrypt,rawsign,rawverify} ...`
- **`dsa`** — `poetry run transcrypto dsa [-h] {shared,new,rawsign,rawverify} ...`
- **`bid`** — `poetry run transcrypto bid [-h] {new,verify} ...`
- **`sss`** — `poetry run transcrypto sss [-h] {new,rawshares,rawrecover,rawverify} ...`
- **`doc`** — `poetry run transcrypto doc [-h] {md} ...`

```bash
Examples:

  # --- Randomness ---
  poetry run transcrypto random bits 16
  poetry run transcrypto random int 1000 2000
  poetry run transcrypto random bytes 32
  poetry run transcrypto random prime 64

  # --- Primes ---
  poetry run transcrypto isprime 428568761
  poetry run transcrypto primegen 100 -c 3
  poetry run transcrypto mersenne -k 2 -C 17

  # --- Integer / Modular Math ---
  poetry run transcrypto gcd 462 1071
  poetry run transcrypto xgcd 127 13
  poetry run transcrypto mod inv 17 97
  poetry run transcrypto mod div 6 127 13
  poetry run transcrypto mod exp 438 234 127
  poetry run transcrypto mod poly 12 17 10 20 30
  poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1
  poetry run transcrypto mod crt 6 7 127 13

  # --- Hashing ---
  poetry run transcrypto hash sha256 xyz
  poetry run transcrypto --b64 hash sha512 eHl6
  poetry run transcrypto hash file /etc/passwd --digest sha512

  # --- AES ---
  poetry run transcrypto --out-b64 aes key "correct horse battery staple"
  poetry run transcrypto --b64 --out-b64 aes encrypt -k "<b64key>" "secret"
  poetry run transcrypto --b64 --out-b64 aes decrypt -k "<b64key>" "<ciphertext>"
  poetry run transcrypto aes ecb -k "<b64key>" encrypt "<128bithexblock>"
  poetry run transcrypto aes ecb -k "<b64key>" decrypt "<128bithexblock>"

  # --- RSA ---
  poetry run transcrypto -p rsa-key rsa new --bits 2048
  poetry run transcrypto -p rsa-key.pub rsa rawencrypt <plaintext>
  poetry run transcrypto -p rsa-key.priv rsa rawdecrypt <ciphertext>
  poetry run transcrypto -p rsa-key.priv rsa rawsign <message>
  poetry run transcrypto -p rsa-key.pub rsa rawverify <message> <signature>

  # --- ElGamal ---
  poetry run transcrypto -p eg-key elgamal shared --bits 2048
  poetry run transcrypto -p eg-key elgamal new
  poetry run transcrypto -p eg-key.pub elgamal rawencrypt <plaintext>
  poetry run transcrypto -p eg-key.priv elgamal rawdecrypt <c1:c2>
  poetry run transcrypto -p eg-key.priv elgamal rawsign <message>
  poetry run transcrypto-p eg-key.pub elgamal rawverify <message> <s1:s2>

  # --- DSA ---
  poetry run transcrypto -p dsa-key dsa shared --p-bits 2048 --q-bits 256
  poetry run transcrypto -p dsa-key dsa new
  poetry run transcrypto -p dsa-key.priv dsa rawsign <message>
  poetry run transcrypto -p dsa-key.pub dsa rawverify <message> <s1:s2>

  # --- Public Bid ---
  poetry run transcrypto --bin bid new "tomorrow it will rain"
  poetry run transcrypto --out-bin bid verify

  # --- Shamir Secret Sharing (SSS) ---
  poetry run transcrypto -p sss-key sss new 3 --bits 1024
  poetry run transcrypto -p sss-key sss rawshares <secret> 5
  poetry run transcrypto -p sss-key sss rawrecover
  poetry run transcrypto -p sss-key sss rawverify <secret>
```

---

### `random`

Cryptographically secure randomness, from the OS CSPRNG.

```bash
poetry run transcrypto random [-h] {bits,int,bytes,prime} ...
```

#### `random bits`

Random integer with exact bit length = `bits` (MSB will be 1).

```bash
poetry run transcrypto random bits [-h] bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Number of bits, ≥ 8 [type: int] |

**Example:**

```bash
$ poetry run transcrypto random bits 16
36650
```

#### `random int`

Uniform random integer in `[min, max]` range, inclusive.

```bash
poetry run transcrypto random int [-h] min max
```

| Option/Arg | Description |
|---|---|
| `min` | Minimum, ≥ 0 [type: str] |
| `max` | Maximum, > `min` [type: str] |

**Example:**

```bash
$ poetry run transcrypto random int 1000 2000
1628
```

#### `random bytes`

Generates `n` cryptographically secure random bytes.

```bash
poetry run transcrypto random bytes [-h] n
```

| Option/Arg | Description |
|---|---|
| `n` | Number of bytes, ≥ 1 [type: int] |

**Example:**

```bash
$ poetry run transcrypto random bytes 32
6c6f1f88cb93c4323285a2224373d6e59c72a9c2b82e20d1c376df4ffbe9507f
```

#### `random prime`

Generate a random prime with exact bit length = `bits` (MSB will be 1).

```bash
poetry run transcrypto random prime [-h] bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Bit length, ≥ 11 [type: int] |

**Example:**

```bash
$ poetry run transcrypto random prime 32
2365910551
```

---

### `isprime`

Primality test with safe defaults, useful for any integer size.

```bash
poetry run transcrypto isprime [-h] n
```

| Option/Arg | Description |
|---|---|
| `n` | Integer to test, ≥ 1 [type: str] |

**Example:**

```bash
$ poetry run transcrypto isprime 2305843009213693951
True
$ poetry run transcrypto isprime 2305843009213693953
False
```

---

### `primegen`

Generate (stream) primes ≥ `start` (prints a limited `count` by default).

```bash
poetry run transcrypto primegen [-h] [-c COUNT] start
```

| Option/Arg | Description |
|---|---|
| `start` | Starting integer (inclusive) [type: str] |
| `-c, --count` | How many to print (0 = unlimited) [type: int (default: 10)] |

**Example:**

```bash
$ poetry run transcrypto primegen 100 -c 3
101
103
107
```

---

### `mersenne`

Generate (stream) Mersenne prime exponents `k`, also outputting `2^k-1` (the Mersenne prime, `M`) and `M×2^(k-1)` (the associated perfect number), starting at `min-k` and stopping once `k` > `cutoff-k`.

```bash
poetry run transcrypto mersenne [-h] [-k MIN_K] [-C CUTOFF_K]
```

| Option/Arg | Description |
|---|---|
| `-k, --min-k` | Starting exponent `k`, ≥ 1 [type: int (default: 1)] |
| `-C, --cutoff-k` | Stop once `k` > `cutoff-k` [type: int (default: 10000)] |

**Example:**

```bash
$ poetry run transcrypto mersenne -k 0 -C 15
k=2  M=3  perfect=6
k=3  M=7  perfect=28
k=5  M=31  perfect=496
k=7  M=127  perfect=8128
k=13  M=8191  perfect=33550336
k=17  M=131071  perfect=8589869056
```

---

### `gcd`

Greatest Common Divisor (GCD) of integers `a` and `b`.

```bash
poetry run transcrypto gcd [-h] a b
```

| Option/Arg | Description |
|---|---|
| `a` | Integer, ≥ 0 [type: str] |
| `b` | Integer, ≥ 0 (can't be both zero) [type: str] |

**Example:**

```bash
$ poetry run transcrypto gcd 462 1071
21
$ poetry run transcrypto gcd 0 5
5
$ poetry run transcrypto gcd 127 13
1
```

---

### `xgcd`

Extended Greatest Common Divisor (x-GCD) of integers `a` and `b`, will return `(g, x, y)` where `a×x+b×y==g`.

```bash
poetry run transcrypto xgcd [-h] a b
```

| Option/Arg | Description |
|---|---|
| `a` | Integer, ≥ 0 [type: str] |
| `b` | Integer, ≥ 0 (can't be both zero) [type: str] |

**Example:**

```bash
$ poetry run transcrypto xgcd 462 1071
(21, 7, -3)
$ poetry run transcrypto xgcd 0 5
(5, 0, 1)
$ poetry run transcrypto xgcd 127 13
(1, 4, -39)
```

---

### `mod`

Modular arithmetic helpers.

```bash
poetry run transcrypto mod [-h] {inv,div,exp,poly,lagrange,crt} ...
```

#### `mod inv`

Modular inverse: find integer 0≤`i`<`m` such that `a×i ≡ 1 (mod m)`. Will only work if `gcd(a,m)==1`, else will fail with a message.

```bash
poetry run transcrypto mod inv [-h] a m
```

| Option/Arg | Description |
|---|---|
| `a` | Integer to invert [type: str] |
| `m` | Modulus `m`, ≥ 2 [type: str] |

**Example:**

```bash
$ poetry run transcrypto mod inv 127 13
4
$ poetry run transcrypto mod inv 17 3120
2753
$ poetry run transcrypto mod inv 462 1071
<<INVALID>> no modular inverse exists (ModularDivideError)
```

#### `mod div`

Modular division: find integer 0≤`z`<`m` such that `z×y ≡ x (mod m)`. Will only work if `gcd(y,m)==1` and `y!=0`, else will fail with a message.

```bash
poetry run transcrypto mod div [-h] x y m
```

| Option/Arg | Description |
|---|---|
| `x` | Integer [type: str] |
| `y` | Integer, cannot be zero [type: str] |
| `m` | Modulus `m`, ≥ 2 [type: str] |

**Example:**

```bash
$ poetry run transcrypto mod div 6 127 13
11
$ poetry run transcrypto mod div 6 0 13
<<INVALID>> no modular inverse exists (ModularDivideError)
```

#### `mod exp`

Modular exponentiation: `a^e mod m`. Efficient, can handle huge values.

```bash
poetry run transcrypto mod exp [-h] a e m
```

| Option/Arg | Description |
|---|---|
| `a` | Integer [type: str] |
| `e` | Integer, ≥ 0 [type: str] |
| `m` | Modulus `m`, ≥ 2 [type: str] |

**Example:**

```bash
$ poetry run transcrypto mod exp 438 234 127
32
$ poetry run transcrypto mod exp 438 234 89854
60622
```

#### `mod poly`

Efficiently evaluate polynomial with `coeff` coefficients at point `x` modulo `m` (`c₀+c₁×x+c₂×x²+…+cₙ×xⁿ mod m`).

```bash
poetry run transcrypto mod poly [-h] x m coeff [coeff ...]
```

| Option/Arg | Description |
|---|---|
| `x` | Evaluation point `x` [type: str] |
| `m` | Modulus `m`, ≥ 2 [type: str] |
| `coeff` | Coefficients (constant-term first: `c₀+c₁×x+c₂×x²+…+cₙ×xⁿ`) [nargs: +] |

**Example:**

```bash
$ poetry run transcrypto mod poly 12 17 10 20 30
14  # (10+20×12+30×12² ≡ 14 (mod 17))
$ poetry run transcrypto mod poly 10 97 3 0 0 1 1
42  # (3+1×10³+1×10⁴ ≡ 42 (mod 97))
```

#### `mod lagrange`

Lagrange interpolation over modulus `m`: find the `f(x)` solution for the given `x` and `zₙ:f(zₙ)` points `pt`. The modulus `m` must be a prime.

```bash
poetry run transcrypto mod lagrange [-h] x m pt [pt ...]
```

| Option/Arg | Description |
|---|---|
| `x` | Evaluation point `x` [type: str] |
| `m` | Modulus `m`, ≥ 2 [type: str] |
| `pt` | Points `zₙ:f(zₙ)` as `key:value` pairs (e.g., `2:4 5:3 7:1`) [nargs: +] |

**Example:**

```bash
$ poetry run transcrypto mod lagrange 5 13 2:4 6:3 7:1
3  # passes through (2,4), (6,3), (7,1)
$ poetry run transcrypto mod lagrange 11 97 1:1 2:4 3:9 4:16 5:25
24  # passes through (1,1), (2,4), (3,9), (4,16), (5,25)
```

#### `mod crt`

Solves Chinese Remainder Theorem (CRT) Pair: finds the unique integer 0≤`x`<`(m1×m2)` satisfying both `x ≡ a1 (mod m1)` and `x ≡ a2 (mod m2)`, if `gcd(m1,m2)==1`.

```bash
poetry run transcrypto mod crt [-h] a1 m1 a2 m2
```

| Option/Arg | Description |
|---|---|
| `a1` | Integer residue for first congruence [type: str] |
| `m1` | Modulus `m1`, ≥ 2 and `gcd(m1,m2)==1` [type: str] |
| `a2` | Integer residue for second congruence [type: str] |
| `m2` | Modulus `m2`, ≥ 2 and `gcd(m1,m2)==1` [type: str] |

**Example:**

```bash
$ poetry run transcrypto mod crt 6 7 127 13
62
$ poetry run transcrypto mod crt 12 56 17 19
796
$ poetry run transcrypto mod crt 6 7 462 1071
<<INVALID>> moduli m1/m2 not co-prime (ModularDivideError)
```

---

### `hash`

Cryptographic Hashing (SHA-256 / SHA-512 / file).

```bash
poetry run transcrypto hash [-h] {sha256,sha512,file} ...
```

#### `hash sha256`

SHA-256 of input `data`.

```bash
poetry run transcrypto hash sha256 [-h] data
```

| Option/Arg | Description |
|---|---|
| `data` | Input data (raw text; or use --hex/--b64/--bin) [type: str] |

**Example:**

```bash
$ poetry run transcrypto --bin hash sha256 xyz
3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282
$ poetry run transcrypto --b64 hash sha256 eHl6  # "xyz" in base-64
3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282
```

#### `hash sha512`

SHA-512 of input `data`.

```bash
poetry run transcrypto hash sha512 [-h] data
```

| Option/Arg | Description |
|---|---|
| `data` | Input data (raw text; or use --hex/--b64/--bin) [type: str] |

**Example:**

```bash
$ poetry run transcrypto --bin hash sha512 xyz
4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a58e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728
$ poetry run transcrypto --b64 hash sha512 eHl6  # "xyz" in base-64
4a3ed8147e37876adc8f76328e5abcc1b470e6acfc18efea0135f983604953a58e183c1a6086e91ba3e821d926f5fdeb37761c7ca0328a963f5e92870675b728
```

#### `hash file`

SHA-256/512 hash of file contents, defaulting to SHA-256.

```bash
poetry run transcrypto hash file [-h] [--digest {sha256,sha512}] path
```

| Option/Arg | Description |
|---|---|
| `path` | Path to existing file [type: str] |
| `--digest` | Digest type, SHA-256 ("sha256") or SHA-512 ("sha512") [choices: ['sha256', 'sha512'] (default: sha256)] |

**Example:**

```bash
$ poetry run transcrypto hash file /etc/passwd --digest sha512
8966f5953e79f55dfe34d3dc5b160ac4a4a3f9cbd1c36695a54e28d77c7874dff8595502f8a420608911b87d336d9e83c890f0e7ec11a76cb10b03e757f78aea
```

---

### `aes`

AES-256 operations (GCM/ECB) and key derivation. No measures are taken here to prevent timing attacks.

```bash
poetry run transcrypto aes [-h] {key,encrypt,decrypt,ecb} ...
```

#### `aes key`

Derive key from a password (PBKDF2-HMAC-SHA256) with custom expensive salt and iterations. Very good/safe for simple password-to-key but not for passwords databases (because of constant salt).

```bash
poetry run transcrypto aes key [-h] password
```

| Option/Arg | Description |
|---|---|
| `password` | Password (leading/trailing spaces ignored) [type: str] |

**Example:**

```bash
$ poetry run transcrypto --out-b64 aes key "correct horse battery staple"
DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es=
$ poetry run transcrypto -p keyfile.out --protect hunter aes key "correct horse battery staple"
AES key saved to 'keyfile.out'
```

#### `aes encrypt`

AES-256-GCM: safely encrypt `plaintext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use `--bin`/`--hex`/`--b64` flags. Attention: if you provide `-a`/`--aad` (associated data, AAD), you will need to provide the same AAD when decrypting and it is NOT included in the `ciphertext`/CT returned by this method!

```bash
poetry run transcrypto aes encrypt [-h] [-k KEY] [-a AAD] plaintext
```

| Option/Arg | Description |
|---|---|
| `plaintext` | Input data to encrypt (PT) [type: str] |
| `-k, --key` | Key if `-p`/`--key-path` wasn't used (32 bytes) [type: str] |
| `-a, --aad` | Associated data (optional; has to be separately sent to receiver/stored) [type: str] |

**Example:**

```bash
$ poetry run transcrypto --b64 --out-b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= AAAAAAB4eXo=
F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==
$ poetry run transcrypto --b64 --out-b64 aes encrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 AAAAAAB4eXo=
xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==
```

#### `aes decrypt`

AES-256-GCM: safely decrypt `ciphertext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. All inputs are raw, or you can use `--bin`/`--hex`/`--b64` flags. Attention: if you provided `-a`/`--aad` (associated data, AAD) during encryption, you will need to provide the same AAD now!

```bash
poetry run transcrypto aes decrypt [-h] [-k KEY] [-a AAD] ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Input data to decrypt (CT) [type: str] |
| `-k, --key` | Key if `-p`/`--key-path` wasn't used (32 bytes) [type: str] |
| `-a, --aad` | Associated data (optional; has to be exactly the same as used during encryption) [type: str] |

**Example:**

```bash
$ poetry run transcrypto --b64 --out-b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= F2_ZLrUw5Y8oDnbTP5t5xCUWX8WtVILLD0teyUi_37_4KHeV-YowVA==
AAAAAAB4eXo=
$ poetry run transcrypto --b64 --out-b64 aes decrypt -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= -a eHl6 xOlAHPUPpeyZHId-f3VQ_QKKMxjIW0_FBo9WOfIBrzjn0VkVV6xTRA==
AAAAAAB4eXo=
```

#### `aes ecb`

AES-256-ECB: encrypt/decrypt 128 bit (16 bytes) hexadecimal blocks. UNSAFE, except for specifically encrypting hash blocks which are very much expected to look random. ECB mode will have the same output for the same input (no IV/nonce is used).

```bash
poetry run transcrypto aes ecb [-h] [-k KEY] {encrypt,decrypt} ...
```

| Option/Arg | Description |
|---|---|
| `-k, --key` | Key if `-p`/`--key-path` wasn't used (32 bytes; raw, or you can use `--bin`/`--hex`/`--b64` flags) [type: str] |

#### `aes ecb encrypt`

AES-256-ECB: encrypt 16-bytes hex `plaintext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash blocks.

```bash
poetry run transcrypto aes ecb encrypt [-h] plaintext
```

| Option/Arg | Description |
|---|---|
| `plaintext` | Plaintext block as 32 hex chars (16-bytes) [type: str] |

**Example:**

```bash
$ poetry run transcrypto --b64 aes ecb -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= encrypt 00112233445566778899aabbccddeeff
54ec742ca3da7b752e527b74e3a798d7
```

#### `aes ecb decrypt`

AES-256-ECB: decrypt 16-bytes hex `ciphertext` with `-k`/`--key` or with `-p`/`--key-path` keyfile. UNSAFE, except for specifically encrypting hash blocks.

```bash
poetry run transcrypto aes ecb decrypt [-h] ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Ciphertext block as 32 hex chars (16-bytes) [type: str] |

**Example:**

```bash
$ poetry run transcrypto --b64 aes ecb -k DbWJ_ZrknLEEIoq_NpoCQwHYfjskGokpueN2O_eY0es= decrypt 54ec742ca3da7b752e527b74e3a798d7
00112233445566778899aabbccddeeff
```

---

### `rsa`

Raw RSA (Rivest-Shamir-Adleman) asymmetric cryptography over *integers* (BEWARE: no OAEP/PSS padding or validation). These are pedagogical/raw primitives; do not use for new protocols. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` (see provided examples).

```bash
poetry run transcrypto rsa [-h]
                                  {new,rawencrypt,rawdecrypt,rawsign,rawverify} ...
```

#### `rsa new`

Generate RSA private/public key pair with `bits` modulus size (prime sizes will be `bits`/2). Requires `-p`/`--key-path` to set the basename for output files.

```bash
poetry run transcrypto rsa new [-h] [--bits BITS]
```

| Option/Arg | Description |
|---|---|
| `--bits` | Modulus size in bits; the default is a safe size [type: int (default: 3332)] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key rsa new --bits 64  # NEVER use such a small key: example only!
RSA private/public keys saved to 'rsa-key.priv/.pub'
```

#### `rsa rawencrypt`

Encrypt integer `message` with public key.

```bash
poetry run transcrypto rsa rawencrypt [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to encrypt, 1≤`message`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key.pub rsa rawencrypt 999
6354905961171348600
```

#### `rsa rawdecrypt`

Decrypt integer `ciphertext` with private key.

```bash
poetry run transcrypto rsa rawdecrypt [-h] ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Integer ciphertext to decrypt, 1≤`ciphertext`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key.priv rsa rawdecrypt 6354905961171348600
999
```

#### `rsa rawsign`

Sign integer `message` with private key.

```bash
poetry run transcrypto rsa rawsign [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to sign, 1≤`message`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key.priv rsa rawsign 999
7632909108672871784
```

#### `rsa rawverify`

Verify integer `signature` for integer `message` with public key.

```bash
poetry run transcrypto rsa rawverify [-h] message signature
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message that was signed earlier, 1≤`message`<*modulus* [type: str] |
| `signature` | Integer putative signature for `message`, 1≤`signature`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key.pub rsa rawverify 999 7632909108672871784
RSA signature: OK
$ poetry run transcrypto -p rsa-key.pub rsa rawverify 999 7632909108672871785
RSA signature: INVALID
```

---

### `elgamal`

Raw El-Gamal asymmetric cryptography over *integers* (BEWARE: no ECIES-style KEM/DEM padding or validation). These are pedagogical/raw primitives; do not use for new protocols. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` (see provided examples).

```bash
poetry run transcrypto elgamal [-h]
                                      {shared,new,rawencrypt,rawdecrypt,rawsign,rawverify} ...
```

#### `elgamal shared`

Generate a shared El-Gamal key with `bits` prime modulus size, which is the first step in key generation. The shared key can safely be used by any number of users to generate their private/public key pairs (with the `new` command). The shared keys are "public". Requires `-p`/`--key-path` to set the basename for output files.

```bash
poetry run transcrypto elgamal shared [-h] [--bits BITS]
```

| Option/Arg | Description |
|---|---|
| `--bits` | Prime modulus (`p`) size in bits; the default is a safe size [type: int (default: 3332)] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key elgamal shared --bits 64  # NEVER use such a small key: example only!
El-Gamal shared key saved to 'eg-key.shared'
```

#### `elgamal new`

Generate an individual El-Gamal private/public key pair from a shared key.

```bash
poetry run transcrypto elgamal new [-h]
```

**Example:**

```bash
$ poetry run transcrypto -p eg-key elgamal new
El-Gamal private/public keys saved to 'eg-key.priv/.pub'
```

#### `elgamal rawencrypt`

Encrypt integer `message` with public key.

```bash
poetry run transcrypto elgamal rawencrypt [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to encrypt, 1≤`message`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key.pub elgamal rawencrypt 999
2948854810728206041:15945988196340032688
```

#### `elgamal rawdecrypt`

Decrypt integer `ciphertext` with private key.

```bash
poetry run transcrypto elgamal rawdecrypt [-h] ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Integer ciphertext to decrypt; expects `c1:c2` format with 2 integers,  2≤`c1`,`c2`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key.priv elgamal rawdecrypt 2948854810728206041:15945988196340032688
999
```

#### `elgamal rawsign`

Sign integer message with private key. Output will 2 integers in a `s1:s2` format.

```bash
poetry run transcrypto elgamal rawsign [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to sign, 1≤`message`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key.priv elgamal rawsign 999
4674885853217269088:14532144906178302633
```

#### `elgamal rawverify`

Verify integer `signature` for integer `message` with public key.

```bash
poetry run transcrypto elgamal rawverify [-h] message signature
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message that was signed earlier, 1≤`message`<*modulus* [type: str] |
| `signature` | Integer putative signature for `message`; expects `s1:s2` format with 2 integers,  2≤`s1`,`s2`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key.pub elgamal rawverify 999 4674885853217269088:14532144906178302633
El-Gamal signature: OK
$ poetry run transcrypto -p eg-key.pub elgamal rawverify 999 4674885853217269088:14532144906178302632
El-Gamal signature: INVALID
```

---

### `dsa`

Raw DSA (Digital Signature Algorithm) asymmetric signing over *integers* (BEWARE: no ECDSA/EdDSA padding or validation). These are pedagogical/raw primitives; do not use for new protocols. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` (see provided examples).

```bash
poetry run transcrypto dsa [-h] {shared,new,rawsign,rawverify} ...
```

#### `dsa shared`

Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is the first step in key generation. `q-bits` should be larger than the secrets that will be protected and `p-bits` should be much larger than `q-bits` (e.g. 4096/544). The shared key can safely be used by any number of users to generate their private/public key pairs (with the `new` command). The shared keys are "public". Requires `-p`/`--key-path` to set the basename for output files.

```bash
poetry run transcrypto dsa shared [-h] [--p-bits P_BITS]
                                         [--q-bits Q_BITS]
```

| Option/Arg | Description |
|---|---|
| `--p-bits` | Prime modulus (`p`) size in bits; the default is a safe size [type: int (default: 4096)] |
| `--q-bits` | Prime modulus (`q`) size in bits; the default is a safe size ***IFF*** you are protecting symmetric keys or regular hashes [type: int (default: 544)] |

**Example:**

```bash
$ poetry run transcrypto -p dsa-key dsa shared --p-bits 128 --q-bits 32  # NEVER use such a small key: example only!
DSA shared key saved to 'dsa-key.shared'
```

#### `dsa new`

Generate an individual DSA private/public key pair from a shared key.

```bash
poetry run transcrypto dsa new [-h]
```

**Example:**

```bash
$ poetry run transcrypto -p dsa-key dsa new
DSA private/public keys saved to 'dsa-key.priv/.pub'
```

#### `dsa rawsign`

Sign integer message with private key. Output will 2 integers in a `s1:s2` format.

```bash
poetry run transcrypto dsa rawsign [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to sign, 1≤`message`<`q` [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p dsa-key.priv dsa rawsign 999
2395961484:3435572290
```

#### `dsa rawverify`

Verify integer `signature` for integer `message` with public key.

```bash
poetry run transcrypto dsa rawverify [-h] message signature
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message that was signed earlier, 1≤`message`<`q` [type: str] |
| `signature` | Integer putative signature for `message`; expects `s1:s2` format with 2 integers,  2≤`s1`,`s2`<`q` [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p dsa-key.pub dsa rawverify 999 2395961484:3435572290
DSA signature: OK
$ poetry run transcrypto -p dsa-key.pub dsa rawverify 999 2395961484:3435572291
DSA signature: INVALID
```

---

### `bid`

Bidding on a `secret` so that you can cryptographically convince a neutral party that the `secret` that was committed to previously was not changed. All methods require file key(s) as `-p`/`--key-path` (see provided examples).

```bash
poetry run transcrypto bid [-h] {new,verify} ...
```

#### `bid new`

Generate the bid files for `secret`. Requires `-p`/`--key-path` to set the basename for output files.

```bash
poetry run transcrypto bid new [-h] secret
```

| Option/Arg | Description |
|---|---|
| `secret` | Input data to bid to, the protected "secret" [type: str] |

**Example:**

```bash
$ poetry run transcrypto --bin -p my-bid bid new "tomorrow it will rain"
Bid private/public commitments saved to 'my-bid.priv/.pub'
```

#### `bid verify`

Verify the bid files for correctness and reveal the `secret`. Requires `-p`/`--key-path` to set the basename for output files.

```bash
poetry run transcrypto bid verify [-h]
```

**Example:**

```bash
$ poetry run transcrypto --out-bin -p my-bid bid verify
Bid commitment: OK
Bid secret:
tomorrow it will rain
```

---

### `sss`

Raw SSS (Shamir Shared Secret) secret sharing crypto scheme over *integers* (BEWARE: no modern message wrapping, padding or validation). These are pedagogical/raw primitives; do not use for new protocols. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` (see provided examples).

```bash
poetry run transcrypto sss [-h]
                                  {new,rawshares,rawrecover,rawverify} ...
```

#### `sss new`

Generate the private keys with `bits` prime modulus size and so that at least a `minimum` number of shares are needed to recover the secret. This key will be used to generate the shares later (with the `shares` command). Requires `-p`/`--key-path` to set the basename for output files.

```bash
poetry run transcrypto sss new [-h] [--bits BITS] minimum
```

| Option/Arg | Description |
|---|---|
| `minimum` | Minimum number of shares required to recover secret, ≥ 2 [type: int] |
| `--bits` | Prime modulus (`p`) size in bits; the default is a safe size ***IFF*** you are protecting symmetric keys; the number of bits should be comfortably larger than the size of the secret you want to protect with this scheme [type: int (default: 1024)] |

**Example:**

```bash
$ poetry run transcrypto -p sss-key sss new 3 --bits 64  # NEVER use such a small key: example only!
SSS private/public keys saved to 'sss-key.priv/.pub'
```

#### `sss rawshares`

Issue `count` private shares for an integer `secret`.

```bash
poetry run transcrypto sss rawshares [-h] secret count
```

| Option/Arg | Description |
|---|---|
| `secret` | Integer secret to be protected, 1≤`secret`<*modulus* [type: str] |
| `count` | How many shares to produce; must be ≥ `minimum` used in `new` command or else the `secret` would become unrecoverable [type: int] |

**Example:**

```bash
$ poetry run transcrypto -p sss-key sss rawshares 999 5
SSS 5 individual (private) shares saved to 'sss-key.share.1…5'
$ rm sss-key.share.2 sss-key.share.4  # this is to simulate only having shares 1,3,5
```

#### `sss rawrecover`

Recover secret from shares; will use any available shares that were found.

```bash
poetry run transcrypto sss rawrecover [-h]
```

**Example:**

```bash
$ poetry run transcrypto -p sss-key sss rawrecover
Loaded SSS share: 'sss-key.share.3'
Loaded SSS share: 'sss-key.share.5'
Loaded SSS share: 'sss-key.share.1'  # using only 3 shares: number 2/4 are missing
Secret:
999
```

#### `sss rawverify`

Verify shares against a secret (private params).

```bash
poetry run transcrypto sss rawverify [-h] secret
```

| Option/Arg | Description |
|---|---|
| `secret` | Integer secret used to generate the shares, 1≤`secret`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p sss-key sss rawverify 999
SSS share 'sss-key.share.3' verification: OK
SSS share 'sss-key.share.5' verification: OK
SSS share 'sss-key.share.1' verification: OK
$ poetry run transcrypto -p sss-key sss rawverify 998
SSS share 'sss-key.share.3' verification: INVALID
SSS share 'sss-key.share.5' verification: INVALID
SSS share 'sss-key.share.1' verification: INVALID
```

---

### `doc`

Documentation utilities. (Not for regular use: these are developer utils.)

```bash
poetry run transcrypto doc [-h] {md} ...
```

#### `doc md`

Emit Markdown docs for the CLI (see README.md section "Creating a New Version").

```bash
poetry run transcrypto doc md [-h]
```

**Example:**

```bash
$ poetry run transcrypto doc md > CLI.md
$ ./tools/inject_md_includes.py
inject: README.md updated with included content
```
<!-- INCLUDE:CLI.md END -->
<!-- (auto-generated; do not edit between START/END) -->

<!-- cspell:enable -->

### Base Library

#### Humanized Sizes (IEC binary)

```py
from transcrypto import utils

utils.HumanizedBytes(512)                 # '512 B'
utils.HumanizedBytes(2048)                # '2.00 KiB'
utils.HumanizedBytes(5 * 1024**3)         # '5.00 GiB'
```

Converts raw byte counts to binary-prefixed strings (`B`, `KiB`, `MiB`, `GiB`, `TiB`, `PiB`, `EiB`). Values under 1024 bytes are returned as integers with `B`; larger values use two decimals.

- standard: 1 KiB = 1024 B, 1 MiB = 1024 KiB, …
- errors: negative inputs raise `InputError`

#### Humanized Decimal Quantities (SI)

```py
# Base (unitless)
utils.HumanizedDecimal(950)               # '950'
utils.HumanizedDecimal(1500)              # '1.50 k'

# With a unit (trimmed and attached)
utils.HumanizedDecimal(1500, ' Hz ')      # '1.50 kHz'
utils.HumanizedDecimal(0.123456, 'V')     # '0.1235 V'

# Large magnitudes
utils.HumanizedDecimal(3_200_000)         # '3.20 M'
utils.HumanizedDecimal(7.2e12, 'B/s')     # '7.20 TB/s'
```

Scales by powers of 1000 using SI prefixes (`k`, `M`, `G`, `T`, `P`, `E`). For values `<1000`, integers are shown as-is; small floats show four decimals. For scaled values, two decimals are used and the unit (if provided) is attached without a space (e.g., `kHz`).

- unit handling: `unit` is stripped; `<1000` values include a space before the unit (`'950 Hz'`)
- errors: negative or non-finite inputs raise `InputError`

#### Humanized Durations

```py
utils.HumanizedSeconds(0)                 # '0.00 s'
utils.HumanizedSeconds(0.000004)          # '4.000 µs'
utils.HumanizedSeconds(0.25)              # '250.000 ms'
utils.HumanizedSeconds(42)                # '42.00 s'
utils.HumanizedSeconds(3661)              # '1.02 h'
utils.HumanizedSeconds(172800)            # '2.00 d'
```

Chooses an appropriate time unit based on magnitude and formats with fixed precision:

- `< 1 ms`: microseconds with three decimals (`µs`)
- `< 1 s`: milliseconds with three decimals (`ms`)
- `< 60 s`: seconds with two decimals (`s`)
- `< 60 min`: minutes with two decimals (`min`)
- `< 24 h`: hours with two decimals (`h`)
- `≥ 24 h`: days with two decimals (`d`)
- special case: `0 → '0.00 s'`
- errors: negative or non-finite inputs raise `InputError`

#### Cryptographically Secure Randomness

These helpers live in `base` and wrap Python’s `secrets` with additional checks and guarantees for crypto use-cases.

```py
from transcrypto import base
```

##### Fixed-size random integers

```py
# Generate a 256-bit integer (first bit always set)
r = base.RandBits(256)
assert r.bit_length() == 256
```

Produces a crypto-secure random integer with exactly `n_bits` bits (`≥ 8`). The most significant bit is guaranteed to be `1`, so entropy is \~`n_bits−1` — negligible for large crypto sizes.

- errors: `n_bits < 8` → `InputError`

##### Uniform random integers in a range

```py
# Uniform between [10, 20] inclusive
n = base.RandInt(10, 20)
assert 10 <= n <= 20
```

Returns a crypto-secure integer uniformly distributed over the closed interval `[min_int, max_int]`.

- constraints: `min_int ≥ 0` and `< max_int`
- errors: invalid bounds → `InputError`

##### In-place secure shuffle

```py
deck = list(range(10))
base.RandShuffle(deck)
print(deck)   # securely shuffled order
```

Performs an in-place Fisher–Yates shuffle using `secrets.randbelow`. Suitable for sensitive data ordering.

- constraints: sequence length ≥ 2
- errors: shorter sequences → `InputError`

##### Random byte strings

```py
# 32 random bytes
b = base.RandBytes(32)
assert len(b) == 32
```

Generates `n_bytes` of high-quality crypto-secure random data.

- constraints: `n_bytes ≥ 1`
- errors: smaller values → `InputError`

#### Computing the Greatest Common Divisor

```py
>>> from transcrypto import base
>>> base.GCD(462, 1071)
21
>>> base.GCD(0, 17)
17
```

The function is `O(log(min(a, b)))` and handles arbitrarily large integers. To find Bézout coefficients `(x, y)` such that `ax + by = gcd(a, b)` do:

```py
>>> base.ExtendedGCD(462, 1071)
(21, -2, 1)
>>> 462 * -2 + 1071 * 1
21
```

Use-cases:

- modular inverses: `inv = x % m` when `gcd(a, m) == 1`
- solving linear Diophantine equations
- RSA / ECC key generation internals

#### Cryptographic Hashing

Simple, fixed-output-size wrappers over Python’s `hashlib` for common digest operations, plus file hashing.

```py
from transcrypto import base
```

##### SHA-256 hashing

```py
h = base.Hash256(b'hello world')
assert len(h) == 32                       # bytes
print(h.hex())                            # 64 hex chars
```

Computes the SHA-256 digest of a byte string, returning exactly 32 bytes (256 bits). Suitable for fingerprints, commitments, or internal crypto primitives.

##### SHA-512 hashing

```py
h = base.Hash512(b'hello world')
assert len(h) == 64                       # bytes
print(h.hex())                            # 128 hex chars
```

Computes the SHA-512 digest of a byte string, returning exactly 64 bytes (512 bits). Higher collision resistance and larger output space than SHA-256.

##### File hashing

```py
# Default SHA-256
fh = base.FileHash('/path/to/file')
print(fh.hex())

# SHA-512
fh2 = base.FileHash('/path/to/file', digest='sha512')
```

Hashes a file from disk in streaming mode. By default uses SHA-256; `digest='sha512'` switches to SHA-512.

- constraints:
  - `digest` must be `'sha256'` or `'sha512'`
  - `full_path` must exist
- errors: invalid digest or missing file → `InputError`

#### Execution Timing

A flexible timing utility that works as a **context manager**, **decorator**, or **manual timer object**.

```py
from transcrypto import base
import time
```

##### Context manager

```py
with base.Timer('Block timing'):
    time.sleep(1.2)
# → logs: "Block timing: 1.20 s" (default via logging.info)
```

Starts timing on entry, stops on exit, and reports elapsed time automatically.

##### Decorator

```py
@base.Timer('Function timing')
def slow_function():
    time.sleep(0.8)

slow_function()
# → logs: "Function timing: 0.80 s"
```

Wraps a function so that each call is automatically timed.

##### Manual use

```py
tm = base.Timer('Inline timing', emit_print=True)
tm.Start()
time.sleep(0.1)
tm.Stop()   # prints: "Inline timing: 0.10 s"
```

Manual control over `Start()` and `Stop()` for precise measurement of custom intervals.

##### Key points

- **Label**: required, shown in output; empty labels raise `InputError`
- **Output**:
  - `emit_log=True` → `logging.info()` (default)
  - `emit_print=True` → direct `print()`
  - Both can be enabled
- **Format**: elapsed time is shown using `HumanizedSeconds()`
- **Safety**:
  - Cannot start an already started timer
  - Cannot stop an unstarted or already stopped timer
    (raises `Error`)

#### Symmetric Encryption Interface

`SymmetricCrypto` is an abstract base class that defines the **byte-in / byte-out** contract for symmetric ciphers.

- **Metadata handling** — if the algorithm uses a `nonce` or `tag`, the implementation must handle it internally (e.g., append it to ciphertext).
- **AEAD modes** — if supported, `associated_data` must be authenticated; otherwise, a non-`None` value should raise `InputError`.

```py
class MyAES(base.SymmetricCrypto):
    def Encrypt(self, plaintext: bytes, *, associated_data=None) -> bytes:
        ...
    def Decrypt(self, ciphertext: bytes, *, associated_data=None) -> bytes:
        ...
```

#### Serialization Pipeline

These helpers turn arbitrary Python objects into compressed and/or encrypted binary blobs, and back again — with detailed timing and size logging.

```py
from transcrypto import base
```

##### Serialize

```py
data = {'x': 42, 'y': 'hello'}

# Basic serialization
blob = base.Serialize(data)

# With compression and encryption
blob = base.Serialize(
    data,
    compress=9,               # compression level (-22..22, default=3)
    key=my_symmetric_key      # must implement SymmetricCrypto
)

# Save directly to file
base.Serialize(data, file_path='/tmp/data.blob')
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

Errors: invalid compression level is clamped to range; other input errors raise `InputError`.

##### DeSerialize

```py
# From in-memory blob
obj = base.DeSerialize(data=blob)

# From file
obj = base.DeSerialize(file_path='/tmp/data.blob')

# With decryption
obj = base.DeSerialize(data=blob, key=my_symmetric_key)
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
- Wrong key or corrupted data can raise `CryptoError`.

#### Crypto Objects General Properties (`CryptoKey`)

Cryptographic objects all derive from the `CryptoKey` class and will all have some important characteristics:

- Will be safe to log and print, i.e., implement safe `__str__()` and `__repr__()` methods (in actuality `repr` will be exactly the same as `str`). The `__str__()` should always fully print the public parts of the object and obfuscate the private ones. This obfuscation allows for some debugging, if needed, but if the secrets are "too short" then it can be defeated by brute force. For usual crypto defaults the obfuscation is fine. The obfuscation is the fist 4 bytes of the SHA-512 for the value followed by an ellipsis (e.g. `c9626f16…`).
- It will have a `_DebugDump()` method that **does print secrets** and can be used for **debugging only**.
- Can be easily serialized to `bytes` by the `blob` property and to base-64 encoded `str` by the `encoded` property.
- Can be serialized encrypted to `bytes` by the `Blob(key=[SymmetricCrypto])` method and to encrypted base-64 encoded `str` by the `Encoded(key=[SymmetricCrypto])` method.
- Can be instantiated back as an object from `str` or `bytes` using the `Load(data, key=[SymmetricCrypto] | None)` method. The `Load()` will decide how to build the object and will work universally with all the serialization options discussed above.

Example:

<!-- cspell:disable -->
```py
from transcrypto import base, rsa, aes

priv = rsa.RSAPrivateKey.New(512)  # small key, but good for this example
print(str(priv))                   # safe, no secrets
# ▶ RSAPrivateKey(RSAPublicKey(public_modulus=pQaoxy-QeXSds1k9WsGjJw==, encrypt_exp=AQAB), modulus_p=f18141aa…, modulus_q=67494eb9…, decrypt_exp=c96db24a…)

print(priv._DebugDump())  # UNSAFE: prints secrets
# ▶ RSAPrivateKey(public_modulus=219357196311600536151291741191131996967, encrypt_exp=65537, modulus_p=13221374197986739361, modulus_q=16591104148992527047, decrypt_exp=37805202135275158391322585315542443073, remainder_p=9522084656682089473, remainder_q=8975656462800098363, q_inverse_p=11965562396596149292)

print(priv.blob)
# ▶ b"(\xb5/\xfd \x98\xc1\x04\x00\x80\x04\x95\x8d\x00\x00\x00\x00\x00\x00\x00\x8c\x0ftranscrypto.rsa\x94\x8c\rRSAPrivateKey\x94\x93\x94)\x81\x94]\x94(\x8a\x11'\xa3\xc1Z=Y\xb3\x9dty\x90/\xc7\xa8\x06\xa5\x00J\x01\x00\x01\x00\x8a\t\xa1\xc4\x83\x81\xc8\xc1{\xb7\x00\x8a\t\xc7\x8a5\xf0Qq?\xe6\x00\x8a\x10A$&\x82!\x1cy\x89r\xef\xeb\xa7_\x04q\x1c\x8a\t\x01\xbc\xbb\x8a\x8b=%\x84\x00\x8a\x08;\x94#s\xff\xef\x8f|\x8a\t,\x9c\xe2z\x9a7\x0e\xa6\x00eb."

print(priv.encoded)
# ▶ KLUv_WBwAIELAIAElWUBAAAAAAAAjA90cmFuc2NyeXB0by5yc2GUjA1SU0FQcml2YXRlS2V5lJOUKYGUXZQoikHf1EvsmZedAZve7TrLmobLAwuRIr_77TLG6G_0fsLGThERVJu075be8PLjUQYnLXcacZFQ5Fb1Iy1WtiE985euAEoBAAEAiiFR9ngiXMzkf41o5CRBY3h0D4DJVisDDhLmAWsiaHggzQCKIS_cmQ6MKXCtROtC7c_Mrsi9A-9NM8DksaHaRwvy6uTZAIpB4TVbsLxc41TEc19wIzpxbi9y5dW5gdfTkRQSSiz0ijmb8Xk3pyBfKAv8JbHp8Yv48gNZUfX67qq0J7yhJqeUoACKIbFb2kTNRzSqm3JRtjc2BPS-FnLFdadlFcV4-6IW7eqLAIogFZfzDN39gZLR9uTz4KHSTaqxWrJgP8-YYssjss6FlFKKIIItgCDv7ompNpY8gBs5bibN8XTsr-JOYSntDVT5Fe5vZWIu

key = aes.AESKey(key256=b'x' * 32)
print(key)
# ▶ AESKey(key256=86a86df7…)

encrypted = priv.Blob(key=key)
print(priv == rsa.RSAPrivateKey.Load(encrypted, key=key))
# ▶ True
```
<!-- cspell:enable -->

#### AES-256 Symmetric Encryption

Implements AES-256 in **GCM mode** for authenticated encryption and decryption, plus an **ECB mode** helper for fixed-size block encoding.
Also includes a high-iteration PBKDF2-based key derivation from static passwords.

##### Key creation

```py
from transcrypto import aes

# From raw bytes (must be exactly 32 bytes)
key = aes.AESKey(key256=b'\x00' * 32)

# From a static password (slow, high-iteration PBKDF2-SHA256)
key = aes.AESKey.FromStaticPassword('correct horse battery staple')
print(key.encoded)  # URL-safe Base64
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
ct = key.Encrypt(data, associated_data=aad)

# Decrypt
pt = key.Decrypt(ct, associated_data=aad)
assert pt == data
```

- **Security**:
  - Random 128-bit IV (`iv`) per encryption
  - Authenticated tag (128-bit) ensures integrity
  - Optional `associated_data` is authenticated but not encrypted
- **Errors**:
  - Tag mismatch or wrong key → `CryptoError`

##### AES-256 + ECB (unsafe, fixed block only)

```py
# ECB mode is for 16-byte block encoding ONLY
ecb = key.ECBEncoder()

block = b'16-byte string!!'
ct_block = ecb.Encrypt(block)
pt_block = ecb.Decrypt(ct_block)
assert pt_block == block

# Hex helpers
hex_ct = ecb.EncryptHex('00112233445566778899aabbccddeeff')
```

- **ECB mode**:
  - 16-byte plaintext ↔ 16-byte ciphertext
  - No padding, no IV, no integrity — **do not use for general encryption**
  - `associated_data` not supported

Key points:

- **GCM mode** is secure for general use; ECB mode is for special low-level operations
- **Static password derivation** is intentionally slow to resist brute force
- All sizes and parameters are validated with `InputError` on misuse

#### Fast Modular Arithmetic

```py
from transcrypto import modmath

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

#### Chinese Remainder Theorem (CRT) – Pair

```py
from transcrypto import modmath

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
  - invalid modulus values → `InputError`
  - non co-prime moduli → `ModularDivideError`

This function is a 2-modulus variant; for multiple moduli, apply it iteratively or use a general CRT solver.

#### Modular Polynomials & Lagrange Interpolation

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
p384 = modmath.NBitRandomPrime(384)

for k, m_p, perfect in modmath.MersennePrimesGenerator(0):
  print(f'p = {k:>8}  M = {m_p}  perfect = {perfect}')
  if k > 10000:          # stop after a few
    break
```

#### RSA (Rivest-Shamir-Adleman) Public Cryptography

<https://en.wikipedia.org/wiki/RSA_cryptosystem>

This implementation is raw RSA, no OAEP or PSS! It works on the actual integers. For real uses you should look for higher-level implementations.

By default and deliberate choice the *encryption exponent* will be either 7 or 65537, depending on the size of `phi=(p-1)*(q-1)`. If `phi` allows it the larger one will be chosen to avoid Coppersmith attacks.

```py
from transcrypto import rsa

# Generate a key pair
priv = rsa.RSAPrivateKey.New(2048)     # 2048-bit modulus
pub  = rsa.RSAPublicKey.Copy(priv)     # public half
print(priv.public_modulus.bit_length())   # 2048

# Encrypt & decrypt
msg = 123456789  # (Zero is forbidden by design; smallest valid message is 1.)
cipher = pub.Encrypt(msg)
plain  = priv.Decrypt(cipher)
assert plain == msg

# Sign & verify
signature = priv.Sign(msg)
assert pub.VerifySignature(msg, signature)

# Blind signatures (obfuscation pair) - only works on raw RSA
pair = rsa.RSAObfuscationPair.New(pub)

blind_msg = pair.ObfuscateMessage(msg)            # what you send to signer
blind_sig = priv.Sign(blind_msg)                  # signer’s output

sig = pair.RevealOriginalSignature(msg, blind_sig)
assert pub.VerifySignature(msg, sig)
```

#### El-Gamal Public-Key Cryptography

[https://en.wikipedia.org/wiki/ElGamal\_encryption](https://en.wikipedia.org/wiki/ElGamal_encryption)

This is **raw El-Gamal** over a prime field — no padding, no hashing — and is **not** DSA.
For real-world deployments, use a high-level library with authenticated encryption and proper encoding.

##### Shared Public Key

```py
from transcrypto import elgamal

# ➊ Shared parameters (prime modulus, group base) for a group
shared = elgamal.ElGamalSharedPublicKey.New(256)
print(shared.prime_modulus)
print(shared.group_base)
```

- `prime_modulus`: large prime `p ≥ 7`
- `group_base`: integer `3 ≤ g < p`
- Used to derive individual public/private keys.

##### Public Key

```py
# ➋ Public key from private
priv = elgamal.ElGamalPrivateKey.New(shared)
pub  = elgamal.ElGamalPublicKey.Copy(priv)

# Encryption
msg = 42
cipher = pub.Encrypt(msg)
plain = priv.Decrypt(cipher)
assert plain == msg

# Signature verify
sig = priv.Sign(msg)
assert pub.VerifySignature(msg, sig)
```

- `Encrypt(message)` → `(c1, c2)`, both in `[2, p-1]`
- `VerifySignature(message, signature)` → `True` or `False`
- `Copy()` extracts public portion from a private key

##### Private Key

```py
# ➌ Private key generation
priv = elgamal.ElGamalPrivateKey.New(shared)

# Decryption
plain = priv.Decrypt(cipher)

# Signing
sig = priv.Sign(msg)
assert pub.VerifySignature(msg, sig)
```

- `decrypt_exp`: secret exponent `3 ≤ e < p`
- `Decrypt((c1, c2))` recovers `m`
- `Sign(m)` returns `(s1, s2)`; both satisfy the modulus constraints

Key points:

- **Security parameters**:
  - Recommended `prime_modulus` bit length ≥ 2048 for real security
  - Random values from `base.RandBits`
- **Ephemeral keys**:
  - Fresh per encryption/signature
  - Must satisfy `gcd(k, p-1) == 1`
- **Errors**:
  - Bad ranges → `InputError`
  - Invalid math relationships → `CryptoError`
- **Group sharing**:
  - Multiple parties can share `(p, g)` but have different `(individual_base, decrypt_exp)`

#### DSA (Digital Signature Algorithm)

[https://en.wikipedia.org/wiki/Digital\_Signature\_Algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)

This is **raw DSA** over a prime field — **no hashing or padding**. You sign/verify **integers** modulo `q` (`prime_seed`). For real use, hash the message first (e.g., SHA-256) and then map to an integer `< q`.

```py
from transcrypto import dsa

# ➊ Shared parameters (p, q, g)
shared = dsa.DSASharedPublicKey.New(p_bits=1024, q_bits=160)
print(shared.prime_modulus)  # p
print(shared.prime_seed)     # q  (q | p-1)
print(shared.group_base)     # g

# ➋ Individual key pair
priv = dsa.DSAPrivateKey.New(shared)
pub  = dsa.DSAPublicKey.Copy(priv)

# ➌ Sign & verify (message must be 1 ≤ m < q)
msg = 123456789 % shared.prime_seed
sig = priv.Sign(msg)
assert pub.VerifySignature(msg, sig)
```

- ranges:
  - `1 ≤ message < q`
  - signatures: `(s1, s2)` with `2 ≤ s1, s2 < q`
- errors:
  - invalid ranges → `InputError`
  - inconsistent parameters → `CryptoError`

##### Security notes

- Choose **large** parameters (e.g., `p ≥ 2048 bits`, `q ≥ 224 bits`) for non-toy settings.
- In practice, compute `m = int.from_bytes(Hash(message), 'big') % q` before calling `Sign(m)`.

##### Advanced: custom primes generator

```py
# Generate primes (p, q) with q | (p-1); also returns m = (p-1)//q
p, q, m = dsa.NBitRandomDSAPrimes(p_bits=1024, q_bits=160)
assert (p - 1) % q == 0
```

Used internally by `DSASharedPublicKey.New()`.
Search breadth and retry caps are bounded; repeated failures raise `CryptoError`.

#### Public Bidding

This is a way of bidding on some commitment (the `secret`) that can be cryptographically proved later to not have been changed. To do that the secret is combined with 2 nonces (random values, `n1` & `n2`) and a hash of it is taken (`H=SHA-512(n1||n2||secret)`). The hash `H` and one nonce `n1` are public and divulged. The other nonce `n2` and the `secret` are kept private and will be used to show `secret` was not changed since the beginning of the process. The nonces guarantee the `secret` cannot be brute-forced or changed after-the-fact. The whole process is as strong as SHA-512 collisions.

```py
from transcrypto import base

# Generate the private and public bids
bid_priv = base.PrivateBid512.New(secret)    # this one you keep private
bid_pub = base.PublicBid512.Copy(bid_priv)   # this one you publish

# Checking that a bid is genuine requires the public bid and knowing the nonce and the secret:
print(bid_pub.VerifyBid(private_key, secret_bid))  # these come from a divulged private bid
# of course, you want to also make sure the provided private data matches your version of it, e.g.:
bid_pub_expected = base.PublicBid512.Copy(bid_priv)
print(bid_pub == bid_pub_expected)
```

#### SSS (Shamir Shared Secret)

<https://en.wikipedia.org/wiki/Shamir's_secret_sharing>

This is the information-theoretic SSS but with no authentication or binding between share and secret. Malicious share injection is possible! Add MAC or digital signature in hostile settings. Use at least 128-bit modulus for non-toy deployments.

```py
from transcrypto import sss

# ➊  Generate parameters: at least 3 of 5 shares needed,
#     coefficients & modulus are 128-bit primes
priv = sss.ShamirSharedSecretPrivate.New(minimum_shares=3, bit_length=128)
pub  = sss.ShamirSharedSecretPublic.Copy(priv)   # what you publish

print(f'threshold        : {pub.minimum}')
print(f'prime mod        : {pub.modulus}')
print(f'poly coefficients: {priv.polynomial}')         # keep these private!

# Issuing shares

secret = 0xC0FFEE
# Generate an unlimited stream; here we take 5
five_shares = list(priv.Shares(secret, max_shares=5))
for sh in five_shares:
  print(f'share {sh.share_key} → {sh.share_value}')
```

A single share object looks like `sss.ShamirSharePrivate(minimum=3, modulus=..., share_key=42, share_value=123456789)`.

```py
# Re-constructing the secret

subset = five_shares[:3]          # any 3 distinct shares
recovered = pub.RecoverSecret(subset)
assert recovered == secret
```

If you supply fewer than minimum shares you get a `CryptoError`, unless you explicitly override:

```py
try:
  pub.RecoverSecret(five_shares[:2])        # raises
except Exception as e:
  print(e)                                  # "unrecoverable secret …"

# Force the interpolation even with 2 points (gives a wrong secret, of course)
print(pub.RecoverSecret(five_shares[:2], force_recover=True))

# Checking that a share is genuine

share = five_shares[0]
ok = priv.VerifyShare(secret, share)       # ▶ True
tampered = sss.ShamirSharePrivate(
    minimum=share.minimum,
    modulus=share.modulus,
    share_key=share.share_key,
    share_value=(share.share_value + 1) % share.modulus)
print(priv.VerifyShare(secret, tampered))  # ▶ False
```

## Appendix: Development Instructions

### Setup

If you want to develop for this project, first install python 3.13 and [Poetry](https://python-poetry.org/docs/cli/), but to get the versions you will need, we suggest you do it like this (*Linux*):

```sh
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install git python3 python3-pip pipx python3-dev python3-venv build-essential software-properties-common

sudo add-apt-repository ppa:deadsnakes/ppa  # install arbitrary python version
sudo apt-get update
sudo apt-get install python3.13

sudo apt-get remove python3-poetry
python3.13 -m pipx ensurepath
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

brew install git python@3.13  # install arbitrary python version

brew uninstall poetry
python3.13 -m pip install --user pipx
python3.13 -m pipx ensurepath
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

poetry env use python3.13  # creates the venv
poetry install --sync      # HONOR the project's poetry.lock file, uninstalls stray packages
poetry env info            # no-op: just to check

poetry run pytest -vvv
# or any command as:
poetry run <any-command>
```

To activate like a regular environment do:

```sh
poetry env activate
# will print activation command which you next execute, or you can do:
source .env/bin/activate                         # if .env is local to the project
source "$(poetry env info --path)/bin/activate"  # for other paths

pytest  # or other commands

deactivate
```

### Updating Dependencies

To update `poetry.lock` file to more current versions do `poetry update`, it will ignore the current lock, update, and rewrite the `poetry.lock` file.

To add a new dependency you should do:

```sh
poetry add "pkg>=1.2.3"  # regenerates lock, updates env (adds dep to prod code)
poetry add -G dev "pkg>=1.2.3"  # adds dep to dev code ("group" dev)
# also remember: "pkg@^1.2.3" = latest 1.* ; "pkg@~1.2.3" = latest 1.2.* ; "pkg@1.2.3" exact
```

If you manually added a dependency to `pyproject.toml` you should ***very carefully*** recreate the environment and files:

```sh
rm -rf .venv .poetry poetry.lock
poetry env use python3.13
poetry install
```

Remember to check your diffs before submitting (especially `poetry.lock`) to avoid surprises!

When dependencies change, always regenerate `requirements.txt` by running:

```sh
poetry export --format requirements.txt --without-hashes --output requirements.txt
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

If you changed the CLI interface at all run:

```sh
poetry run transcrypto doc md > CLI.md
./tools/inject_md_includes.py
```

You can find the 10 top slowest tests by running:

```sh
poetry run pytest -vvv -q --durations=10
```

You can search for flaky tests by running all tests 100 times:

```sh
poetry run pytest --flake-finder --flake-runs=100
```
