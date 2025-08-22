# TransCrypto

Basic crypto primitives, not intended for actual use, but as a companion to "Criptografia, Métodos e Algoritmos".

Started in July/2025, by Daniel Balparda. Since version 1.0.2 it is PyPI package:

<https://pypi.org/project/transcrypto/>

- [TransCrypto](#transcrypto)
  - [License](#license)
  - [Use](#use)
  - [Install](#install)
  - [Command-Line Interface](#command-line-interface)
  - [Command-Line Interface](#command-line-interface-1)
    - [Global Options](#global-options)
    - [Commands](#commands)
      - [`isprime`](#isprime)
      - [`mr`](#mr)
      - [`randomprime`](#randomprime)
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
      - [`rand`](#rand)
      - [`rand bits`](#rand-bits)
      - [`rand int`](#rand-int)
      - [`rand bytes`](#rand-bytes)
      - [`hash`](#hash)
      - [`hash sha256`](#hash-sha256)
      - [`hash sha512`](#hash-sha512)
      - [`hash file`](#hash-file)
      - [`aes`](#aes)
      - [`aes key`](#aes-key)
      - [`aes key frompass`](#aes-key-frompass)
      - [`aes encrypt`](#aes-encrypt)
      - [`aes decrypt`](#aes-decrypt)
      - [`aes ecb`](#aes-ecb)
      - [`aes ecb encrypthex`](#aes-ecb-encrypthex)
      - [`aes ecb decrypthex`](#aes-ecb-decrypthex)
      - [`rsa`](#rsa)
      - [`rsa new`](#rsa-new)
      - [`rsa encrypt`](#rsa-encrypt)
      - [`rsa decrypt`](#rsa-decrypt)
      - [`rsa sign`](#rsa-sign)
      - [`rsa verify`](#rsa-verify)
      - [`elgamal`](#elgamal)
      - [`elgamal shared`](#elgamal-shared)
      - [`elgamal new`](#elgamal-new)
      - [`elgamal encrypt`](#elgamal-encrypt)
      - [`elgamal decrypt`](#elgamal-decrypt)
      - [`elgamal sign`](#elgamal-sign)
      - [`elgamal verify`](#elgamal-verify)
      - [`dsa`](#dsa)
      - [`dsa shared`](#dsa-shared)
      - [`dsa new`](#dsa-new)
      - [`dsa sign`](#dsa-sign)
      - [`dsa verify`](#dsa-verify)
      - [`sss`](#sss)
      - [`sss new`](#sss-new)
      - [`sss shares`](#sss-shares)
      - [`sss recover`](#sss-recover)
      - [`sss verify`](#sss-verify)
      - [`doc`](#doc)
      - [`doc md`](#doc-md)
    - [1. Cryptographically Secure Randomness](#1-cryptographically-secure-randomness)
      - [`random bytes`](#random-bytes)
      - [`random int`](#random-int)
    - [2. Primality and Modular Math](#2-primality-and-modular-math)
      - [`isprime`](#isprime-1)
      - [`crt`](#crt)
    - [3. RSA Cryptography](#3-rsa-cryptography)
      - [`rsa new`](#rsa-new-1)
      - [`rsa encrypt`](#rsa-encrypt-1)
      - [`rsa decrypt`](#rsa-decrypt-1)
    - [4. AES Cryptography](#4-aes-cryptography)
      - [`aes genkey`](#aes-genkey)
      - [`aes encrypt`](#aes-encrypt-1)
      - [`aes decrypt`](#aes-decrypt-1)
      - [`aes ecb-encrypt`](#aes-ecb-encrypt)
      - [`aes ecb-decrypt`](#aes-ecb-decrypt)
    - [5. Hashing](#5-hashing)
      - [`hash sha256`](#hash-sha256-1)
      - [`hash sha512`](#hash-sha512-1)
      - [`hash file`](#hash-file-1)
    - [6. Shamir’s Secret Sharing](#6-shamirs-secret-sharing)
      - [`sss split`](#sss-split)
      - [`sss combine`](#sss-combine)
    - [7. Timer Utility](#7-timer-utility)
    - [Base Library](#base-library)
      - [Humanized Sizes (IEC binary)](#humanized-sizes-iec-binary)
      - [Humanized Decimal Quantities (SI)](#humanized-decimal-quantities-si)
      - [Humanized Durations](#humanized-durations)
      - [Cryptographically Secure Randomness](#cryptographically-secure-randomness)
      - [Computing the Greatest Common Divisor](#computing-the-greatest-common-divisor)
      - [Cryptographic Hashing](#cryptographic-hashing)
      - [Execution Timing](#execution-timing)
      - [Symmetric Encryption Interface](#symmetric-encryption-interface)
      - [Serialization Pipeline](#serialization-pipeline)
      - [AES-256 Symmetric Encryption](#aes-256-symmetric-encryption)
      - [Fast Modular Arithmetic](#fast-modular-arithmetic)
      - [Chinese Remainder Theorem (CRT) – Pair](#chinese-remainder-theorem-crt--pair)
      - [Modular Polynomials \& Lagrange Interpolation](#modular-polynomials--lagrange-interpolation)
      - [Primality testing \& Prime generators, Mersenne primes](#primality-testing--prime-generators-mersenne-primes)
      - [RSA (Rivest-Shamir-Adleman) Public Cryptography](#rsa-rivest-shamir-adleman-public-cryptography)
      - [El-Gamal Public-Key Cryptography](#el-gamal-public-key-cryptography)
      - [DSA (Digital Signature Algorithm)](#dsa-digital-signature-algorithm)
      - [SSS (Shamir Shared Secret)](#sss-shamir-shared-secret)
  - [Appendix: Development Instructions](#appendix-development-instructions)
    - [Setup](#setup)
    - [Updating Dependencies](#updating-dependencies)
    - [Creating a New Version](#creating-a-new-version)

## License

Copyright 2025 Daniel Balparda <balparda@github.com>

Licensed under the ***Apache License, Version 2.0*** (the "License"); you may not use this file except in compliance with the License. You may obtain a [copy of the License here](http://www.apache.org/licenses/LICENSE-2.0).

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## Use

Design assumptions:

- The library is built to have reference, reliable, simple implementations of math and crypto primitives.
- All library methods' `int` are tailored to be efficient with arbitrarily large integers.
- Everything **should work**, as the library is **extensively tested**, *but not necessarily the most efficient or safe for real-world cryptographic use.* For real-world crypto use *other optimized/safe libraries* that were built to be resistant to malicious attacks.
- *All operations in this library may be vulnerable to timing attacks.*
- There is some logging and error messages that were written to be clear but in real-life security applications could leak private secrets. Again, this library is not build to be crypto safe. It was built as a simple tested reference implementation.

That being said, all care was taken that this is a good library with a solid implementation. Have fun!

## Install

To use in your project just do:

```sh
pip3 install transcrypto
```

and then `from transcrypto import rsa` (or other parts of the library) for using it.

Known dependencies:

<https://pypi.org/project/zstandard/> (<https://python-zstandard.readthedocs.org/>)

<https://pypi.org/project/cryptography/> (<https://cryptography.io/en/latest/>)

## Command-Line Interface



The `transcrypto.py` module is a command-line utility that provides access to all core functionality described in this documentation. It serves as a convenient wrapper over the Python APIs, enabling **cryptographic operations**, **number theory functions**, **secure randomness generation**, **hashing**, and other utilities without writing code.

Run via:

```bash
poetry run transcrypto <command> [sub-command] [options...]
```

<!-- (auto-generated; do not edit between START/END) -->
<!-- INCLUDE:CLI.md START -->

## Command-Line Interface

`transcrypto.py` exposes cryptographic primitives, number theory tools, key management, and utilities.

Invoke with:

```bash
poetry run transcrypto.py <command> [sub-command] [options...]
```

### Global Options

| Option/Arg | Description |
|---|---|
| `-v, --verbose` | Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG) |

### Commands

- `isprime` — usage: transcrypto.py isprime [-h] n
- `mr` — usage: transcrypto.py mr [-h] [-w WITNESS] n
- `randomprime` — usage: transcrypto.py randomprime [-h] bits
- `primegen` — usage: transcrypto.py primegen [-h] [-c COUNT] start
- `mersenne` — usage: transcrypto.py mersenne [-h] [-k MIN_K] [-C CUTOFF_K]
- `gcd` — usage: transcrypto.py gcd [-h] a b
- `xgcd` — usage: transcrypto.py xgcd [-h] a b
- `mod` — usage: transcrypto.py mod [-h] {inv,div,exp,poly,lagrange,crt} ...
- `rand` — usage: transcrypto.py rand [-h] {bits,int,bytes} ...
- `hash` — usage: transcrypto.py hash [-h] {sha256,sha512,file} ...
- `aes` — usage: transcrypto.py aes [-h] {key,encrypt,decrypt,ecb} ...
- `rsa` — usage: transcrypto.py rsa [-h] {new,encrypt,decrypt,sign,verify} ...
- `elgamal` — usage: transcrypto.py elgamal [-h]
- `dsa` — usage: transcrypto.py dsa [-h] {shared,new,sign,verify} ...
- `sss` — usage: transcrypto.py sss [-h] {new,shares,recover,verify} ...
- `doc` — usage: transcrypto.py doc [-h] {md} ...

#### `isprime`

```bash
poetry run transcrypto.py transcrypto.py isprime [-h] n
```

usage: transcrypto.py isprime [-h] n

| Option/Arg | Description |
|---|---|
| `n` | Integer to test (supports 0x.., 0b.., 0o.., underscores). [type: str] |

#### `mr`

```bash
poetry run transcrypto.py transcrypto.py mr [-h] [-w WITNESS] n
```

usage: transcrypto.py mr [-h] [-w WITNESS] n

| Option/Arg | Description |
|---|---|
| `n` | Integer to test. [type: str] |
| `-w, --witness` | Add a witness (repeatable). Example: -w 2 -w 7 -w 61 [(default: [])] |

#### `randomprime`

```bash
poetry run transcrypto.py transcrypto.py randomprime [-h] bits
```

usage: transcrypto.py randomprime [-h] bits

| Option/Arg | Description |
|---|---|
| `bits` | Bit length (≥ 11). [type: int] |

#### `primegen`

```bash
poetry run transcrypto.py transcrypto.py primegen [-h] [-c COUNT] start
```

usage: transcrypto.py primegen [-h] [-c COUNT] start

| Option/Arg | Description |
|---|---|
| `start` | Starting integer (inclusive). [type: str] |
| `-c, --count` | How many to print (default: 10; 0 = unlimited). [type: int (default: 10)] |

#### `mersenne`

```bash
poetry run transcrypto.py transcrypto.py mersenne [-h] [-k MIN_K] [-C CUTOFF_K]
```

usage: transcrypto.py mersenne [-h] [-k MIN_K] [-C CUTOFF_K]

| Option/Arg | Description |
|---|---|
| `-k, --min-k` | Starting exponent k (default 0). [type: int] |
| `-C, --cutoff-k` | Stop once k > cutoff (default 10000). [type: int (default: 10000)] |

#### `gcd`

```bash
poetry run transcrypto.py transcrypto.py gcd [-h] a b
```

usage: transcrypto.py gcd [-h] a b

| Option/Arg | Description |
|---|---|
| `a` | [type: str] |
| `b` | [type: str] |

#### `xgcd`

```bash
poetry run transcrypto.py transcrypto.py xgcd [-h] a b
```

usage: transcrypto.py xgcd [-h] a b

| Option/Arg | Description |
|---|---|
| `a` | [type: str] |
| `b` | [type: str] |

#### `mod`

```bash
poetry run transcrypto.py transcrypto.py mod [-h] {inv,div,exp,poly,lagrange,crt} ...
```

usage: transcrypto.py mod [-h] {inv,div,exp,poly,lagrange,crt} ...

#### `mod inv`

```bash
poetry run transcrypto.py transcrypto.py mod inv [-h] a m
```

usage: transcrypto.py mod inv [-h] a m

| Option/Arg | Description |
|---|---|
| `a` | [type: str] |
| `m` | [type: str] |

#### `mod div`

```bash
poetry run transcrypto.py transcrypto.py mod div [-h] x y m
```

usage: transcrypto.py mod div [-h] x y m

| Option/Arg | Description |
|---|---|
| `x` | [type: str] |
| `y` | [type: str] |
| `m` | [type: str] |

#### `mod exp`

```bash
poetry run transcrypto.py transcrypto.py mod exp [-h] a e m
```

usage: transcrypto.py mod exp [-h] a e m

| Option/Arg | Description |
|---|---|
| `a` | [type: str] |
| `e` | [type: str] |
| `m` | [type: str] |

#### `mod poly`

```bash
poetry run transcrypto.py transcrypto.py mod poly [-h] t m coeff [coeff ...]
```

usage: transcrypto.py mod poly [-h] t m coeff [coeff ...]

| Option/Arg | Description |
|---|---|
| `t` | Evaluation point t. [type: str] |
| `m` | Modulus m. [type: str] |
| `coeff` | Coefficients (constant-term first). [nargs: +] |

#### `mod lagrange`

```bash
poetry run transcrypto.py transcrypto.py mod lagrange [-h] x m pt [pt ...]
```

usage: transcrypto.py mod lagrange [-h] x m pt [pt ...]

| Option/Arg | Description |
|---|---|
| `x` | Point to evaluate at. [type: str] |
| `m` | Modulus m. [type: str] |
| `pt` | Points as k:v (e.g., 2:4 5:3 7:1). [nargs: +] |

#### `mod crt`

```bash
poetry run transcrypto.py transcrypto.py mod crt [-h] a1 m1 a2 m2
```

usage: transcrypto.py mod crt [-h] a1 m1 a2 m2

| Option/Arg | Description |
|---|---|
| `a1` | [type: str] |
| `m1` | [type: str] |
| `a2` | [type: str] |
| `m2` | [type: str] |

#### `rand`

```bash
poetry run transcrypto.py transcrypto.py rand [-h] {bits,int,bytes} ...
```

usage: transcrypto.py rand [-h] {bits,int,bytes} ...

#### `rand bits`

```bash
poetry run transcrypto.py transcrypto.py rand bits [-h] bits
```

usage: transcrypto.py rand bits [-h] bits

| Option/Arg | Description |
|---|---|
| `bits` | Number of bits ≥ 8 for base.RandBits. [type: int] |

#### `rand int`

```bash
poetry run transcrypto.py transcrypto.py rand int [-h] min max
```

usage: transcrypto.py rand int [-h] min max

| Option/Arg | Description |
|---|---|
| `min` | Minimum (≥ 0). [type: str] |
| `max` | Maximum (> min). [type: str] |

#### `rand bytes`

```bash
poetry run transcrypto.py transcrypto.py rand bytes [-h] n
```

usage: transcrypto.py rand bytes [-h] n

| Option/Arg | Description |
|---|---|
| `n` | Number of bytes ≥ 1. [type: int] |

#### `hash`

```bash
poetry run transcrypto.py transcrypto.py hash [-h] {sha256,sha512,file} ...
```

usage: transcrypto.py hash [-h] {sha256,sha512,file} ...

#### `hash sha256`

```bash
poetry run transcrypto.py transcrypto.py hash sha256 [-h] [--hex] [--b64] [--out-hex] [--out-b64]
                                  data
```

usage: transcrypto.py hash sha256 [-h] [--hex] [--b64] [--out-hex] [--out-b64]

| Option/Arg | Description |
|---|---|
| `data` | Input text (raw; or use --hex/--b64). [type: str] |
| `--hex` | Treat input as hex string. |
| `--b64` | Treat input as base64url. |
| `--out-hex` | Output digest as hex (default). |
| `--out-b64` | Output digest as base64url. |

#### `hash sha512`

```bash
poetry run transcrypto.py transcrypto.py hash sha512 [-h] [--hex] [--b64] [--out-hex] [--out-b64]
                                  data
```

usage: transcrypto.py hash sha512 [-h] [--hex] [--b64] [--out-hex] [--out-b64]

| Option/Arg | Description |
|---|---|
| `data` | Input text (raw; or use --hex/--b64). [type: str] |
| `--hex` | Treat input as hex string. |
| `--b64` | Treat input as base64url. |
| `--out-hex` | Output digest as hex (default). |
| `--out-b64` | Output digest as base64url. |

#### `hash file`

```bash
poetry run transcrypto.py transcrypto.py hash file [-h] [--digest {sha256,sha512}] [--out-hex]
                                [--out-b64]
                                path
```

usage: transcrypto.py hash file [-h] [--digest {sha256,sha512}] [--out-hex]

| Option/Arg | Description |
|---|---|
| `path` | Path to file. [type: str] |
| `--digest` | Digest (default: sha256). [choices: ['sha256', 'sha512'] (default: sha256)] |
| `--out-hex` | Output digest as hex (default). |
| `--out-b64` | Output digest as base64url. |

#### `aes`

```bash
poetry run transcrypto.py transcrypto.py aes [-h] {key,encrypt,decrypt,ecb} ...
```

usage: transcrypto.py aes [-h] {key,encrypt,decrypt,ecb} ...

#### `aes key`

```bash
poetry run transcrypto.py transcrypto.py aes key [-h] {frompass} ...
```

usage: transcrypto.py aes key [-h] {frompass} ...

#### `aes key frompass`

```bash
poetry run transcrypto.py transcrypto.py aes key frompass [-h] [--print-b64] [--out OUT]
                                       [--protect PROTECT]
                                       password
```

usage: transcrypto.py aes key frompass [-h] [--print-b64] [--out OUT]

| Option/Arg | Description |
|---|---|
| `password` | Password (leading/trailing spaces ignored). [type: str] |
| `--print-b64` | Print derived key (base64url). |
| `--out` | Save serialized AESKey to path. [type: str] |
| `--protect` | Password to encrypt the saved key file (Serialize). [type: str] |

#### `aes encrypt`

```bash
poetry run transcrypto.py transcrypto.py aes encrypt [-h] [-k KEY_B64] [-p KEY_PATH] [-a AAD]
                                  [--in-hex] [--in-b64] [--out-hex]
                                  [--out-b64] [--protect PROTECT]
                                  plaintext
```

usage: transcrypto.py aes encrypt [-h] [-k KEY_B64] [-p KEY_PATH] [-a AAD]

| Option/Arg | Description |
|---|---|
| `plaintext` | Input data (raw; or use --in-hex/--in-b64). [type: str] |
| `-k, --key-b64` | Key as base64url (32 bytes). [type: str] |
| `-p, --key-path` | Path to serialized AESKey. [type: str] |
| `-a, --aad` | Associated data (optional). [type: str] |
| `--in-hex` | Treat plaintext as hex. |
| `--in-b64` | Treat plaintext as base64url. |
| `--out-hex` | Output ciphertext as hex (default). |
| `--out-b64` | Output ciphertext as base64url. |
| `--protect` | Password to decrypt key file if using --key-path. [type: str] |

#### `aes decrypt`

```bash
poetry run transcrypto.py transcrypto.py aes decrypt [-h] [-k KEY_B64] [-p KEY_PATH] [-a AAD]
                                  [--in-hex] [--in-b64] [--out-hex]
                                  [--out-b64] [--protect PROTECT]
                                  ciphertext
```

usage: transcrypto.py aes decrypt [-h] [-k KEY_B64] [-p KEY_PATH] [-a AAD]

| Option/Arg | Description |
|---|---|
| `ciphertext` | Input blob (use --in-hex/--in-b64). [type: str] |
| `-k, --key-b64` | Key as base64url (32 bytes). [type: str] |
| `-p, --key-path` | Path to serialized AESKey. [type: str] |
| `-a, --aad` | Associated data (must match). [type: str] |
| `--in-hex` | Treat ciphertext as hex. |
| `--in-b64` | Treat ciphertext as base64url. |
| `--out-hex` | Output plaintext as hex. |
| `--out-b64` | Output plaintext as base64url. |
| `--protect` | Password to decrypt key file if using --key-path. [type: str] |

#### `aes ecb`

```bash
poetry run transcrypto.py transcrypto.py aes ecb [-h] {encrypthex,decrypthex} ...
```

usage: transcrypto.py aes ecb [-h] {encrypthex,decrypthex} ...

#### `aes ecb encrypthex`

```bash
poetry run transcrypto.py transcrypto.py aes ecb encrypthex [-h] key_b64 block_hex
```

usage: transcrypto.py aes ecb encrypthex [-h] key_b64 block_hex

| Option/Arg | Description |
|---|---|
| `key_b64` | Key as base64url (32 bytes). [type: str] |
| `block_hex` | Plaintext block as 32 hex chars. [type: str] |

#### `aes ecb decrypthex`

```bash
poetry run transcrypto.py transcrypto.py aes ecb decrypthex [-h] key_b64 block_hex
```

usage: transcrypto.py aes ecb decrypthex [-h] key_b64 block_hex

| Option/Arg | Description |
|---|---|
| `key_b64` | Key as base64url (32 bytes). [type: str] |
| `block_hex` | Ciphertext block as 32 hex chars. [type: str] |

#### `rsa`

```bash
poetry run transcrypto.py transcrypto.py rsa [-h] {new,encrypt,decrypt,sign,verify} ...
```

usage: transcrypto.py rsa [-h] {new,encrypt,decrypt,sign,verify} ...

#### `rsa new`

```bash
poetry run transcrypto.py transcrypto.py rsa new [-h] [--out OUT] [--protect PROTECT] bits
```

usage: transcrypto.py rsa new [-h] [--out OUT] [--protect PROTECT] bits

| Option/Arg | Description |
|---|---|
| `bits` | Modulus size in bits (e.g., 2048). [type: int] |
| `--out` | Save private key to path (Serialize). [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `rsa encrypt`

```bash
poetry run transcrypto.py transcrypto.py rsa encrypt [-h] --key KEY [--protect PROTECT] message
```

usage: transcrypto.py rsa encrypt [-h] --key KEY [--protect PROTECT] message

| Option/Arg | Description |
|---|---|
| `message` | Integer message (e.g., "12345" or "0x..."). [type: str] |
| `--key` | Path to private/public key (Serialize). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `rsa decrypt`

```bash
poetry run transcrypto.py transcrypto.py rsa decrypt [-h] --key KEY [--protect PROTECT]
                                  ciphertext
```

usage: transcrypto.py rsa decrypt [-h] --key KEY [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `ciphertext` | Integer ciphertext. [type: str] |
| `--key` | Path to private key (Serialize). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `rsa sign`

```bash
poetry run transcrypto.py transcrypto.py rsa sign [-h] --key KEY [--protect PROTECT] message
```

usage: transcrypto.py rsa sign [-h] --key KEY [--protect PROTECT] message

| Option/Arg | Description |
|---|---|
| `message` | Integer message. [type: str] |
| `--key` | Path to private key (Serialize). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `rsa verify`

```bash
poetry run transcrypto.py transcrypto.py rsa verify [-h] --key KEY [--protect PROTECT]
                                 message signature
```

usage: transcrypto.py rsa verify [-h] --key KEY [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `message` | Integer message. [type: str] |
| `signature` | Integer signature. [type: str] |
| `--key` | Path to private/public key (Serialize). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `elgamal`

```bash
poetry run transcrypto.py transcrypto.py elgamal [-h]
                              {shared,new,encrypt,decrypt,sign,verify} ...
```

usage: transcrypto.py elgamal [-h]

#### `elgamal shared`

```bash
poetry run transcrypto.py transcrypto.py elgamal shared [-h] --out OUT [--protect PROTECT] bits
```

usage: transcrypto.py elgamal shared [-h] --out OUT [--protect PROTECT] bits

| Option/Arg | Description |
|---|---|
| `bits` | Bit length for prime modulus p. [type: int] |
| `--out` | Save shared key to path. [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `elgamal new`

```bash
poetry run transcrypto.py transcrypto.py elgamal new [-h] --shared SHARED --out OUT
                                  [--protect PROTECT]
```

usage: transcrypto.py elgamal new [-h] --shared SHARED --out OUT

| Option/Arg | Description |
|---|---|
| `--shared` | Path to shared (p,g). [type: str] |
| `--out` | Save private key to path. [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `elgamal encrypt`

```bash
poetry run transcrypto.py transcrypto.py elgamal encrypt [-h] --key KEY [--protect PROTECT]
                                      message
```

usage: transcrypto.py elgamal encrypt [-h] --key KEY [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `message` | Integer message 1 ≤ m < p. [type: str] |
| `--key` | Path to private/public key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `elgamal decrypt`

```bash
poetry run transcrypto.py transcrypto.py elgamal decrypt [-h] --key KEY [--protect PROTECT] c1 c2
```

usage: transcrypto.py elgamal decrypt [-h] --key KEY [--protect PROTECT] c1 c2

| Option/Arg | Description |
|---|---|
| `c1` | [type: str] |
| `c2` | [type: str] |
| `--key` | Path to private key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `elgamal sign`

```bash
poetry run transcrypto.py transcrypto.py elgamal sign [-h] --key KEY [--protect PROTECT] message
```

usage: transcrypto.py elgamal sign [-h] --key KEY [--protect PROTECT] message

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `--key` | Path to private key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `elgamal verify`

```bash
poetry run transcrypto.py transcrypto.py elgamal verify [-h] --key KEY [--protect PROTECT]
                                     message s1 s2
```

usage: transcrypto.py elgamal verify [-h] --key KEY [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `s1` | [type: str] |
| `s2` | [type: str] |
| `--key` | Path to private/public key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `dsa`

```bash
poetry run transcrypto.py transcrypto.py dsa [-h] {shared,new,sign,verify} ...
```

usage: transcrypto.py dsa [-h] {shared,new,sign,verify} ...

#### `dsa shared`

```bash
poetry run transcrypto.py transcrypto.py dsa shared [-h] --out OUT [--protect PROTECT]
                                 p_bits q_bits
```

usage: transcrypto.py dsa shared [-h] --out OUT [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `p_bits` | Bit length of p (≥ q_bits + 11). [type: int] |
| `q_bits` | Bit length of q (≥ 11). [type: int] |
| `--out` | Save shared params to path. [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `dsa new`

```bash
poetry run transcrypto.py transcrypto.py dsa new [-h] --shared SHARED --out OUT
                              [--protect PROTECT]
```

usage: transcrypto.py dsa new [-h] --shared SHARED --out OUT

| Option/Arg | Description |
|---|---|
| `--shared` | Path to shared (p,q,g). [type: str] |
| `--out` | Save private key to path. [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `dsa sign`

```bash
poetry run transcrypto.py transcrypto.py dsa sign [-h] --key KEY [--protect PROTECT] message
```

usage: transcrypto.py dsa sign [-h] --key KEY [--protect PROTECT] message

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `--key` | Path to private key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `dsa verify`

```bash
poetry run transcrypto.py transcrypto.py dsa verify [-h] --key KEY [--protect PROTECT]
                                 message s1 s2
```

usage: transcrypto.py dsa verify [-h] --key KEY [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `s1` | [type: str] |
| `s2` | [type: str] |
| `--key` | Path to private/public key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `sss`

```bash
poetry run transcrypto.py transcrypto.py sss [-h] {new,shares,recover,verify} ...
```

usage: transcrypto.py sss [-h] {new,shares,recover,verify} ...

#### `sss new`

```bash
poetry run transcrypto.py transcrypto.py sss new [-h] --out OUT [--protect PROTECT] minimum bits
```

usage: transcrypto.py sss new [-h] --out OUT [--protect PROTECT] minimum bits

| Option/Arg | Description |
|---|---|
| `minimum` | Threshold t (≥ 2). [type: int] |
| `bits` | Prime modulus bit length (≥ 128 for non-toy). [type: int] |
| `--out` | Base path; will save ".priv" and ".pub". [type: str] |
| `--protect` | Password to encrypt saved files. [type: str] |

#### `sss shares`

```bash
poetry run transcrypto.py transcrypto.py sss shares [-h] --key KEY [--protect PROTECT]
                                 secret count
```

usage: transcrypto.py sss shares [-h] --key KEY [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `secret` | Secret as integer (supports 0x..). [type: str] |
| `count` | How many shares to produce. [type: int] |
| `--key` | Path to private SSS key (.priv). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `sss recover`

```bash
poetry run transcrypto.py transcrypto.py sss recover [-h] --key KEY [--protect PROTECT]
                                  shares [shares ...]
```

usage: transcrypto.py sss recover [-h] --key KEY [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `shares` | Shares as k:v (e.g., 2:123 5:456 ...). [nargs: +] |
| `--key` | Path to public SSS key (.pub). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `sss verify`

```bash
poetry run transcrypto.py transcrypto.py sss verify [-h] --key KEY [--protect PROTECT]
                                 secret share
```

usage: transcrypto.py sss verify [-h] --key KEY [--protect PROTECT]

| Option/Arg | Description |
|---|---|
| `secret` | Secret as integer (supports 0x..). [type: str] |
| `share` | One share as k:v (e.g., 7:9999). [type: str] |
| `--key` | Path to private SSS key (.priv). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `doc`

```bash
poetry run transcrypto.py transcrypto.py doc [-h] {md} ...
```

usage: transcrypto.py doc [-h] {md} ...

#### `doc md`

```bash
poetry run transcrypto.py transcrypto.py doc md [-h]
```
<!-- INCLUDE:CLI.md END -->
<!-- (auto-generated; do not edit between START/END) -->




### 1. Cryptographically Secure Randomness

#### `random bytes`

```bash
poetry run transcrypto.py random bytes N
```

Generates `N` cryptographically secure random bytes from `base.RandBytes()`.

**Arguments**:

- `N` (`int`): Number of bytes to generate, `N ≥ 1`.

**Output**:

- Hexadecimal string representing the random bytes (2·`N` hex characters).

**Example**:

```bash
poetry run transcrypto.py random bytes 16
# → "e3c4b0d1f7..."
```

---

#### `random int`

```bash
poetry run transcrypto.py random int BITS
```

Generates a cryptographically secure random integer from `base.RandInt()`.

**Arguments**:

- `BITS` (`int`): Bit length of integer to generate, `BITS ≥ 1`.

**Output**:

- Decimal integer in `[0, 2**BITS)`.

**Example**:

```bash
poetry run transcrypto.py random int 256
# → 9732561093957239581...
```

---

### 2. Primality and Modular Math

#### `isprime`

```bash
poetry run transcrypto.py isprime N
```

Checks primality using `modmath.IsPrime()`.

**Arguments**:

- `N` (`int`): Number to test, `N ≥ 0`.

**Output**:

- `"prime"` if `N` is prime, `"composite"` otherwise.

**Example**:

```bash
poetry run transcrypto.py isprime 17
# → "prime"
```

---

#### `crt`

```bash
poetry run transcrypto.py crt A1 M1 A2 M2
```

Solves a **Chinese Remainder Theorem** pair using `modmath.CRTPair()`.

**Arguments**:

- `A1` (`int`): Residue for first congruence.
- `M1` (`int`): Modulus 1, `M1 ≥ 2`.
- `A2` (`int`): Residue for second congruence.
- `M2` (`int`): Modulus 2, `M2 ≥ 2`, `gcd(M1, M2) == 1`.

**Output**:

- The unique solution `x` in `[0, M1*M2)`.

**Example**:

```bash
poetry run transcrypto.py crt 2 3 3 5
# → 8
```

---

### 3. RSA Cryptography

#### `rsa new`

```bash
poetry run transcrypto.py rsa new BITS
```

Generates an RSA key pair with given bit length using `rsa.RSAKey()`.

**Arguments**:

- `BITS` (`int`): Key size in bits, typically 2048 or 4096.

**Output**:

- PEM-encoded private key.
- PEM-encoded public key.

**Example**:

```bash
poetry run transcrypto.py rsa new 2048
# → <PEM output>
```

---

#### `rsa encrypt`

```bash
poetry run transcrypto.py rsa encrypt PUBKEY PLAINTEXT
```

Encrypts data with RSA public key using OAEP padding.

**Arguments**:

- `PUBKEY` (`str`): PEM-encoded public key string or file path.
- `PLAINTEXT` (`str`): Plaintext string to encrypt.

**Output**:

- Hexadecimal ciphertext.

---

#### `rsa decrypt`

```bash
poetry run transcrypto.py rsa decrypt PRIVKEY CIPHERTEXT_HEX
```

Decrypts RSA ciphertext with private key.

**Arguments**:

- `PRIVKEY` (`str`): PEM-encoded private key string or file path.
- `CIPHERTEXT_HEX` (`str`): Hexadecimal-encoded ciphertext.

**Output**:

- Original plaintext string.

---

### 4. AES Cryptography

#### `aes genkey`

```bash
poetry run transcrypto.py aes genkey PASSWORD
```

Derives a 256-bit AES key from a static password using `AESKey.FromStaticPassword()`.

**Arguments**:

- `PASSWORD` (`str`): Non-empty password string (leading/trailing spaces ignored).

**Output**:

- URL-safe Base64-encoded AES key.

---

#### `aes encrypt`

```bash
poetry run transcrypto.py aes encrypt KEY PLAINTEXT [-a AAD]
```

Encrypts data using AES-256-GCM.

**Arguments**:

- `KEY` (`str`): URL-safe Base64-encoded AES key.
- `PLAINTEXT` (`str`): Plaintext to encrypt.
- `-a`, `--aad` (`str`, optional): Additional authenticated data.

**Output**:

- Hexadecimal ciphertext including IV and tag.

---

#### `aes decrypt`

```bash
poetry run transcrypto.py aes decrypt KEY CIPHERTEXT_HEX [-a AAD]
```

Decrypts AES-256-GCM ciphertext.

**Arguments**:

- `KEY` (`str`): URL-safe Base64-encoded AES key.
- `CIPHERTEXT_HEX` (`str`): Hexadecimal ciphertext including IV and tag.
- `-a`, `--aad` (`str`, optional): Additional authenticated data.

**Output**:

- Original plaintext string.

---

#### `aes ecb-encrypt`

```bash
poetry run transcrypto.py aes ecb-encrypt KEY PLAINTEXT_HEX
```

Encrypts a single 16-byte block using AES-256-ECB.

**Arguments**:

- `KEY` (`str`): URL-safe Base64-encoded AES key.
- `PLAINTEXT_HEX` (`str`): 32 hex characters (16 bytes).

**Output**:

- 32-character hex ciphertext.

---

#### `aes ecb-decrypt`

```bash
poetry run transcrypto.py aes ecb-decrypt KEY CIPHERTEXT_HEX
```

Decrypts a single 16-byte block using AES-256-ECB.

**Arguments**:

- `KEY` (`str`): URL-safe Base64-encoded AES key.
- `CIPHERTEXT_HEX` (`str`): 32 hex characters (16 bytes).

**Output**:

- 32-character hex plaintext.

---

### 5. Hashing

#### `hash sha256`

```bash
poetry run transcrypto.py hash sha256 DATA
```

SHA-256 digest of given data.

**Arguments**:

- `DATA` (`str`): Input string; if starts with `0x` or matches hex length, treated as hex.

**Output**:

- 64-character hex digest.

---

#### `hash sha512`

```bash
poetry run transcrypto.py hash sha512 DATA
```

SHA-512 digest of given data.

**Arguments**:

- `DATA` (`str`): As above.

**Output**:

- 128-character hex digest.

---

#### `hash file`

```bash
poetry run transcrypto.py hash file PATH [-d DIGEST]
```

Computes file digest.

**Arguments**:

- `PATH` (`str`): Path to existing file.
- `-d`, `--digest` (`str`): `sha256` (default) or `sha512`.

**Output**:

- Hex digest of file contents.

---

### 6. Shamir’s Secret Sharing

#### `sss split`

```bash
poetry run transcrypto.py sss split SECRET_HEX K N
```

Splits a secret into N shares with threshold K.

**Arguments**:

- `SECRET_HEX` (`str`): Hex-encoded secret.
- `K` (`int`): Threshold, `2 ≤ K ≤ N`.
- `N` (`int`): Total number of shares.

**Output**:

- List of share strings.

---

#### `sss combine`

```bash
poetry run transcrypto.py sss combine SHARE1 SHARE2 [...]
```

Reconstructs the secret from K shares.

**Arguments**:

- `SHAREn` (`str`): Share strings.

**Output**:

- Original secret in hex.

---

### 7. Timer Utility

```bash
poetry run transcrypto.py timer SECONDS
```

Sleeps for the given number of seconds, measuring elapsed time using `base.Timer`.

**Arguments**:

- `SECONDS` (`float`): Duration to wait.

**Output**:

- Elapsed time in seconds.

---

If you want, I can now generate **matching `argparse` parser definitions** from this doc so the CLI’s help text will always match exactly. That way, your documentation and runtime usage stay perfectly synchronized. Would you like me to do that?







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

**Fixed-size random integers**

```py
# Generate a 256-bit integer (first bit always set)
r = base.RandBits(256)
assert r.bit_length() == 256
```

Produces a crypto-secure random integer with exactly `n_bits` bits (`≥ 8`). The most significant bit is guaranteed to be `1`, so entropy is \~`n_bits−1` — negligible for large crypto sizes.

- errors: `n_bits < 8` → `InputError`

---

**Uniform random integers in a range**

```py
# Uniform between [10, 20] inclusive
n = base.RandInt(10, 20)
assert 10 <= n <= 20
```

Returns a crypto-secure integer uniformly distributed over the closed interval `[min_int, max_int]`.

- constraints: `min_int ≥ 0` and `< max_int`
- errors: invalid bounds → `InputError`

---

**In-place secure shuffle**

```py
deck = list(range(10))
base.RandShuffle(deck)
print(deck)   # securely shuffled order
```

Performs an in-place Fisher–Yates shuffle using `secrets.randbelow`. Suitable for sensitive data ordering.

- constraints: sequence length ≥ 2
- errors: shorter sequences → `InputError`

---

**Random byte strings**

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

**SHA-256 hashing**

```py
h = base.Hash256(b'hello world')
assert len(h) == 32                       # bytes
print(h.hex())                            # 64 hex chars
```

Computes the SHA-256 digest of a byte string, returning exactly 32 bytes (256 bits). Suitable for fingerprints, commitments, or internal crypto primitives.

---

**SHA-512 hashing**

```py
h = base.Hash512(b'hello world')
assert len(h) == 64                       # bytes
print(h.hex())                            # 128 hex chars
```

Computes the SHA-512 digest of a byte string, returning exactly 64 bytes (512 bits). Higher collision resistance and larger output space than SHA-256.

---

**File hashing**

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

**Context manager**

```py
with base.Timer('Block timing'):
    time.sleep(1.2)
# → logs: "Block timing: 1.20 s" (default via logging.info)
```

Starts timing on entry, stops on exit, and reports elapsed time automatically.

---

**Decorator**

```py
@base.Timer('Function timing')
def slow_function():
    time.sleep(0.8)

slow_function()
# → logs: "Function timing: 0.80 s"
```

Wraps a function so that each call is automatically timed.

---

**Manual use**

```py
tm = base.Timer('Inline timing', emit_print=True)
tm.Start()
time.sleep(0.1)
tm.Stop()   # prints: "Inline timing: 0.10 s"
```

Manual control over `Start()` and `Stop()` for precise measurement of custom intervals.

---

**Key points**

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

---

#### Serialization Pipeline

These helpers turn arbitrary Python objects into compressed and/or encrypted binary blobs, and back again — with detailed timing and size logging.

```py
from transcrypto import base
```

**Serialize**

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

```
obj → pickle → (compress) → (encrypt) → (save)
```

At each stage:

- Data size is measured using `HumanizedBytes`
- Duration is timed with `Timer`
- Results are logged once at the end

**Compression levels**
`compress` uses `zstandard`; see table in docstring for speed/ratio trade-offs.

**Errors** — invalid compression level is clamped to range; other input errors raise `InputError`.

---

**DeSerialize**

```py
# From in-memory blob
obj = base.DeSerialize(data=blob)

# From file
obj = base.DeSerialize(file_path='/tmp/data.blob')

# With decryption
obj = base.DeSerialize(data=blob, key=my_symmetric_key)
```

Deserialization path:

```
data/file → (decrypt) → (decompress if Zstd) → unpickle
```

- Compression is auto-detected via Zstandard magic numbers.
- All steps are timed/logged like in `Serialize`.

**Constraints & errors**:

- Exactly one of `data` or `file_path` must be provided.
- `file_path` must exist; `data` must be at least 4 bytes.
- Wrong key or corrupted data can raise `CryptoError`.






#### AES-256 Symmetric Encryption

Implements AES-256 in **GCM mode** for authenticated encryption and decryption, plus an **ECB mode** helper for fixed-size block encoding.
Also includes a high-iteration PBKDF2-based key derivation from static passwords.

---

**Key creation**

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

---

**AES-256 + GCM (default)**

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

---

**AES-256 + ECB (unsafe, fixed block only)**

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

---

**Key points**

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

```
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

---

**Example – Larger moduli**

```py
#   x ≡ 4 (mod 7)
#   x ≡ 11 (mod 13)
x = modmath.CRTPair(4, 7, 11, 13)
assert 0 <= x < 91
assert x % 7 == 4
assert x % 13 == 11
```

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

---

**Shared Public Key**

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

---

**Public Key**

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

---

**Private Key**

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

---

**Key Points**

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

**Security notes**

- Choose **large** parameters (e.g., `p ≥ 2048 bits`, `q ≥ 224 bits`) for non-toy settings.
- In practice, compute `m = int.from_bytes(Hash(message), 'big') % q` before calling `Sign(m)`.

---

**Advanced: custom primes generator**

```py
# Generate primes (p, q) with q | (p-1); also returns m = (p-1)//q
p, q, m = dsa.NBitRandomDSAPrimes(p_bits=1024, q_bits=160)
assert (p - 1) % q == 0
```

Used internally by `DSASharedPublicKey.New()`.
Search breadth and retry caps are bounded; repeated failures raise `CryptoError`.







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
