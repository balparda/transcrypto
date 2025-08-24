
## Command-Line Interface

`transcrypto` is a command-line utility that provides access to all core functionality described in this documentation. It serves as a convenient wrapper over the Python APIs, enabling **cryptographic operations**, **number theory functions**, **secure randomness generation**, **hashing**, and other utilities without writing code.

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
- **`rsa`** — `poetry run transcrypto rsa [-h] {new,encrypt,decrypt,sign,verify} ...`
- **`elgamal`** — `poetry run transcrypto elgamal [-h]`
- **`dsa`** — `poetry run transcrypto dsa [-h] {shared,new,sign,verify} ...`
- **`sss`** — `poetry run transcrypto sss [-h] {new,shares,recover,verify} ...`
- **`doc`** — `poetry run transcrypto doc [-h] {md} ...`

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
$ poetry run transcrypto gcd 0 5
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

Hashing (SHA-256 / SHA-512 / file).

```bash
poetry run transcrypto hash [-h] {sha256,sha512,file} ...
```

#### `hash sha256`

SHA-256 of input data.

```bash
poetry run transcrypto hash sha256 [-h] data
```

| Option/Arg | Description |
|---|---|
| `data` | Input text (raw; or use --hex/--b64) [type: str] |

#### `hash sha512`

SHA-512 of input data.

```bash
poetry run transcrypto hash sha512 [-h] data
```

| Option/Arg | Description |
|---|---|
| `data` | Input text (raw; or use --hex/--b64) [type: str] |

#### `hash file`

Hash file contents (streamed).

```bash
poetry run transcrypto hash file [-h] [--digest {sha256,sha512}] path
```

| Option/Arg | Description |
|---|---|
| `path` | Path to file [type: str] |
| `--digest` | Digest (default: sha256) [choices: ['sha256', 'sha512'] (default: sha256)] |

---

### `aes`

AES-256 operations (GCM/ECB) and key derivation.

```bash
poetry run transcrypto aes [-h] {key,encrypt,decrypt,ecb} ...
```

#### `aes key`

Create/derive/store AES keys.

```bash
poetry run transcrypto aes key [-h] {frompass} ...
```

#### `aes key frompass`

Derive key from a password (PBKDF2-HMAC-SHA256).

```bash
poetry run transcrypto aes key frompass [-h] [--print-b64] [--out OUT]
                                               [--protect PROTECT]
                                               password
```

| Option/Arg | Description |
|---|---|
| `password` | Password (leading/trailing spaces ignored) [type: str] |
| `--print-b64` | Print derived key (base64url) |
| `--out` | Save serialized AESKey to path [type: str] |
| `--protect` | Password to encrypt the saved key file (Serialize) [type: str] |

#### `aes encrypt`

AES-256-GCM: encrypt (outputs IV||ct||tag).

```bash
poetry run transcrypto aes encrypt [-h] [-k KEY_B64] [-p KEY_PATH]
                                          [-a AAD] [--protect PROTECT]
                                          plaintext
```

| Option/Arg | Description |
|---|---|
| `plaintext` | Input data (raw; or use --in-hex/--in-b64) [type: str] |
| `-k, --key-b64` | Key as base64url (32 bytes) [type: str] |
| `-p, --key-path` | Path to serialized AESKey [type: str] |
| `-a, --aad` | Associated data (optional) [type: str] |
| `--protect` | Password to decrypt key file if using --key-path [type: str] |

#### `aes decrypt`

AES-256-GCM: decrypt IV||ct||tag.

```bash
poetry run transcrypto aes decrypt [-h] [-k KEY_B64] [-p KEY_PATH]
                                          [-a AAD] [--protect PROTECT]
                                          ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Input blob (use --in-hex/--in-b64) [type: str] |
| `-k, --key-b64` | Key as base64url (32 bytes) [type: str] |
| `-p, --key-path` | Path to serialized AESKey [type: str] |
| `-a, --aad` | Associated data (must match) [type: str] |
| `--protect` | Password to decrypt key file if using --key-path [type: str] |

#### `aes ecb`

AES-ECB (unsafe; fixed 16-byte blocks only).

```bash
poetry run transcrypto aes ecb [-h] [-k KEY_B64] [-p KEY_PATH]
                                      [--protect PROTECT]
                                      {encrypthex,decrypthex} ...
```

| Option/Arg | Description |
|---|---|
| `-k, --key-b64` | Key as base64url (32 bytes) [type: str] |
| `-p, --key-path` | Path to serialized AESKey [type: str] |
| `--protect` | Password to decrypt key file if using --key-path [type: str] |

#### `aes ecb encrypthex`

Encrypt 16-byte hex block with AES-ECB.

```bash
poetry run transcrypto aes ecb encrypthex [-h] block_hex
```

| Option/Arg | Description |
|---|---|
| `block_hex` | Plaintext block as 32 hex chars [type: str] |

#### `aes ecb decrypthex`

Decrypt 16-byte hex block with AES-ECB.

```bash
poetry run transcrypto aes ecb decrypthex [-h] block_hex
```

| Option/Arg | Description |
|---|---|
| `block_hex` | Ciphertext block as 32 hex chars [type: str] |

---

### `rsa`

Raw RSA over integers (no OAEP/PSS).

```bash
poetry run transcrypto rsa [-h] {new,encrypt,decrypt,sign,verify} ...
```

#### `rsa new`

Generate RSA private key.

```bash
poetry run transcrypto rsa new [-h] [--out OUT] [--protect PROTECT]
                                      bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Modulus size in bits (e.g., 2048) [type: int] |
| `--out` | Save private key to path (Serialize) [type: str] |
| `--protect` | Password to encrypt saved key file [type: str] |

#### `rsa encrypt`

Encrypt integer with public key.

```bash
poetry run transcrypto rsa encrypt [-h] --key KEY [--protect PROTECT]
                                          message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message (e.g., "12345" or "0x...") [type: str] |
| `--key` | Path to private/public key (Serialize) [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `rsa decrypt`

Decrypt integer ciphertext with private key.

```bash
poetry run transcrypto rsa decrypt [-h] --key KEY [--protect PROTECT]
                                          ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Integer ciphertext [type: str] |
| `--key` | Path to private key (Serialize) [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `rsa sign`

Sign integer message with private key.

```bash
poetry run transcrypto rsa sign [-h] --key KEY [--protect PROTECT]
                                       message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message [type: str] |
| `--key` | Path to private key (Serialize) [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `rsa verify`

Verify integer signature with public key.

```bash
poetry run transcrypto rsa verify [-h] --key KEY [--protect PROTECT]
                                         message signature
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message [type: str] |
| `signature` | Integer signature [type: str] |
| `--key` | Path to private/public key (Serialize) [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

---

### `elgamal`

Raw El-Gamal (no padding).

```bash
poetry run transcrypto elgamal [-h]
                                      {shared,new,encrypt,decrypt,sign,verify} ...
```

#### `elgamal shared`

Generate shared parameters (p, g).

```bash
poetry run transcrypto elgamal shared [-h] --out OUT
                                             [--protect PROTECT]
                                             bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Bit length for prime modulus p [type: int] |
| `--out` | Save shared key to path [type: str] |
| `--protect` | Password to encrypt saved key file [type: str] |

#### `elgamal new`

Generate individual private key from shared.

```bash
poetry run transcrypto elgamal new [-h] --shared SHARED --out OUT
                                          [--protect PROTECT]
```

| Option/Arg | Description |
|---|---|
| `--shared` | Path to shared (p,g) [type: str] |
| `--out` | Save private key to path [type: str] |
| `--protect` | Password to encrypt saved key file [type: str] |

#### `elgamal encrypt`

Encrypt integer with public key.

```bash
poetry run transcrypto elgamal encrypt [-h] --key KEY
                                              [--protect PROTECT]
                                              message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message 1 ≤ m < p [type: str] |
| `--key` | Path to private/public key [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `elgamal decrypt`

Decrypt El-Gamal ciphertext tuple (c1,c2).

```bash
poetry run transcrypto elgamal decrypt [-h] --key KEY
                                              [--protect PROTECT]
                                              c1 c2
```

| Option/Arg | Description |
|---|---|
| `c1` | [type: str] |
| `c2` | [type: str] |
| `--key` | Path to private key [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `elgamal sign`

Sign integer message with private key.

```bash
poetry run transcrypto elgamal sign [-h] --key KEY [--protect PROTECT]
                                           message
```

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `--key` | Path to private key [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `elgamal verify`

Verify El-Gamal signature (s1,s2).

```bash
poetry run transcrypto elgamal verify [-h] --key KEY
                                             [--protect PROTECT]
                                             message s1 s2
```

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `s1` | [type: str] |
| `s2` | [type: str] |
| `--key` | Path to private/public key [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

---

### `dsa`

Raw DSA (no hash, integer messages < q).

```bash
poetry run transcrypto dsa [-h] {shared,new,sign,verify} ...
```

#### `dsa shared`

Generate (p,q,g) with q | p-1.

```bash
poetry run transcrypto dsa shared [-h] --out OUT [--protect PROTECT]
                                         p_bits q_bits
```

| Option/Arg | Description |
|---|---|
| `p_bits` | Bit length of p (≥ q_bits + 11) [type: int] |
| `q_bits` | Bit length of q (≥ 11) [type: int] |
| `--out` | Save shared params to path [type: str] |
| `--protect` | Password to encrypt saved key file [type: str] |

#### `dsa new`

Generate DSA private key from shared.

```bash
poetry run transcrypto dsa new [-h] --shared SHARED --out OUT
                                      [--protect PROTECT]
```

| Option/Arg | Description |
|---|---|
| `--shared` | Path to shared (p,q,g) [type: str] |
| `--out` | Save private key to path [type: str] |
| `--protect` | Password to encrypt saved key file [type: str] |

#### `dsa sign`

Sign integer m (1 ≤ m < q).

```bash
poetry run transcrypto dsa sign [-h] --key KEY [--protect PROTECT]
                                       message
```

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `--key` | Path to private key [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `dsa verify`

Verify DSA signature (s1,s2).

```bash
poetry run transcrypto dsa verify [-h] --key KEY [--protect PROTECT]
                                         message s1 s2
```

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `s1` | [type: str] |
| `s2` | [type: str] |
| `--key` | Path to private/public key [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

---

### `sss`

Shamir Shared Secret (unauthenticated).

```bash
poetry run transcrypto sss [-h] {new,shares,recover,verify} ...
```

#### `sss new`

Generate SSS params (minimum, prime, coefficients).

```bash
poetry run transcrypto sss new [-h] --out OUT [--protect PROTECT]
                                      minimum bits
```

| Option/Arg | Description |
|---|---|
| `minimum` | Threshold t (≥ 2) [type: int] |
| `bits` | Prime modulus bit length (≥ 128 for non-toy) [type: int] |
| `--out` | Base path; will save ".priv" and ".pub" [type: str] |
| `--protect` | Password to encrypt saved files [type: str] |

#### `sss shares`

Issue N shares for a secret (private params).

```bash
poetry run transcrypto sss shares [-h] --key KEY [--protect PROTECT]
                                         secret count
```

| Option/Arg | Description |
|---|---|
| `secret` | Secret as integer (supports 0x..) [type: str] |
| `count` | How many shares to produce [type: int] |
| `--key` | Path to private SSS key (.priv) [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `sss recover`

Recover secret from shares (public params).

```bash
poetry run transcrypto sss recover [-h] --key KEY [--protect PROTECT]
                                          shares [shares ...]
```

| Option/Arg | Description |
|---|---|
| `shares` | Shares as k:v (e.g., 2:123 5:456 ...) [nargs: +] |
| `--key` | Path to public SSS key (.pub) [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

#### `sss verify`

Verify a share against a secret (private params).

```bash
poetry run transcrypto sss verify [-h] --key KEY [--protect PROTECT]
                                         secret share
```

| Option/Arg | Description |
|---|---|
| `secret` | Secret as integer (supports 0x..) [type: str] |
| `share` | One share as k:v (e.g., 7:9999) [type: str] |
| `--key` | Path to private SSS key (.priv) [type: str] |
| `--protect` | Password to decrypt key file if needed [type: str] |

---

### `doc`

Documentation utilities.

```bash
poetry run transcrypto doc [-h] {md} ...
```

#### `doc md`

Emit Markdown for the CLI (see README.md section "Creating a New Version").

```bash
poetry run transcrypto doc md [-h]
```

