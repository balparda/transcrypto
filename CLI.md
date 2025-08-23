
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
| `--hex` | Treat inputs as hex string (default). |
| `--b64` | Treat inputs as base64url. |
| `--bin` | Treat inputs as binary (bytes). |
| `--out-hex` | Outputs as hex (default). |
| `--out-b64` | Outputs as base64url. |
| `--out-bin` | Outputs as binary (bytes). |

### Commands

- **`isprime`** — `poetry run transcrypto isprime [-h] n`
- **`mr`** — `poetry run transcrypto mr [-h] [-w WITNESS] n`
- **`randomprime`** — `poetry run transcrypto randomprime [-h] bits`
- **`primegen`** — `poetry run transcrypto primegen [-h] [-c COUNT] start`
- **`mersenne`** — `poetry run transcrypto mersenne [-h] [-k MIN_K] [-C CUTOFF_K]`
- **`gcd`** — `poetry run transcrypto gcd [-h] a b`
- **`xgcd`** — `poetry run transcrypto xgcd [-h] a b`
- **`mod`** — `poetry run transcrypto mod [-h] {inv,div,exp,poly,lagrange,crt} ...`
- **`rand`** — `poetry run transcrypto rand [-h] {bits,int,bytes} ...`
- **`hash`** — `poetry run transcrypto hash [-h] {sha256,sha512,file} ...`
- **`aes`** — `poetry run transcrypto aes [-h] {key,encrypt,decrypt,ecb} ...`
- **`rsa`** — `poetry run transcrypto rsa [-h] {new,encrypt,decrypt,sign,verify} ...`
- **`elgamal`** — `poetry run transcrypto elgamal [-h]`
- **`dsa`** — `poetry run transcrypto dsa [-h] {shared,new,sign,verify} ...`
- **`sss`** — `poetry run transcrypto sss [-h] {new,shares,recover,verify} ...`
- **`doc`** — `poetry run transcrypto doc [-h] {md} ...`

#### `isprime`

Primality test with safe defaults (modmath.IsPrime)

```bash
poetry run transcrypto isprime [-h] n
```

| Option/Arg | Description |
|---|---|
| `n` | Integer to test (supports 0x.., 0b.., 0o.., underscores). [type: str] |

#### `mr`

Miller-Rabin primality with optional custom witnesses

```bash
poetry run transcrypto mr [-h] [-w WITNESS] n
```

| Option/Arg | Description |
|---|---|
| `n` | Integer to test. [type: str] |
| `-w, --witness` | Add a witness (repeatable). Example: -w 2 -w 7 -w 61 [(default: [])] |

#### `randomprime`

Generate a random prime with given bit length

```bash
poetry run transcrypto randomprime [-h] bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Bit length (≥ 11). [type: int] |

#### `primegen`

Stream primes ≥ start (prints a limited count by default)

```bash
poetry run transcrypto primegen [-h] [-c COUNT] start
```

| Option/Arg | Description |
|---|---|
| `start` | Starting integer (inclusive). [type: str] |
| `-c, --count` | How many to print (default: 10; 0 = unlimited). [type: int (default: 10)] |

#### `mersenne`

Iterate Mersenne primes (k, M=2^k-1, perfect?)

```bash
poetry run transcrypto mersenne [-h] [-k MIN_K] [-C CUTOFF_K]
```

| Option/Arg | Description |
|---|---|
| `-k, --min-k` | Starting exponent k (default 0). [type: int] |
| `-C, --cutoff-k` | Stop once k > cutoff (default 10000). [type: int (default: 10000)] |

#### `gcd`

Greatest Common Divisor

```bash
poetry run transcrypto gcd [-h] a b
```

| Option/Arg | Description |
|---|---|
| `a` | [type: str] |
| `b` | [type: str] |

#### `xgcd`

Extended GCD → (g, x, y) where ax + by = g

```bash
poetry run transcrypto xgcd [-h] a b
```

| Option/Arg | Description |
|---|---|
| `a` | [type: str] |
| `b` | [type: str] |

#### `mod`

Modular arithmetic helpers

```bash
poetry run transcrypto mod [-h] {inv,div,exp,poly,lagrange,crt} ...
```

#### `mod inv`

Modular inverse: a^(-1) mod m

```bash
poetry run transcrypto mod inv [-h] a m
```

| Option/Arg | Description |
|---|---|
| `a` | [type: str] |
| `m` | [type: str] |

#### `mod div`

Modular division: find z s.t. z·y ≡ x (mod m)

```bash
poetry run transcrypto mod div [-h] x y m
```

| Option/Arg | Description |
|---|---|
| `x` | [type: str] |
| `y` | [type: str] |
| `m` | [type: str] |

#### `mod exp`

Modular exponentiation: a^e mod m

```bash
poetry run transcrypto mod exp [-h] a e m
```

| Option/Arg | Description |
|---|---|
| `a` | [type: str] |
| `e` | [type: str] |
| `m` | [type: str] |

#### `mod poly`

Evaluate polynomial modulo m (c0 c1 c2 ... at t)

```bash
poetry run transcrypto mod poly [-h] t m coeff [coeff ...]
```

| Option/Arg | Description |
|---|---|
| `t` | Evaluation point t. [type: str] |
| `m` | Modulus m. [type: str] |
| `coeff` | Coefficients (constant-term first). [nargs: +] |

#### `mod lagrange`

Lagrange interpolation over modulus

```bash
poetry run transcrypto mod lagrange [-h] x m pt [pt ...]
```

| Option/Arg | Description |
|---|---|
| `x` | Point to evaluate at. [type: str] |
| `m` | Modulus m. [type: str] |
| `pt` | Points as k:v (e.g., 2:4 5:3 7:1). [nargs: +] |

#### `mod crt`

CRT pair: solve x ≡ a1 (mod m1), x ≡ a2 (mod m2)

```bash
poetry run transcrypto mod crt [-h] a1 m1 a2 m2
```

| Option/Arg | Description |
|---|---|
| `a1` | [type: str] |
| `m1` | [type: str] |
| `a2` | [type: str] |
| `m2` | [type: str] |

#### `rand`

Cryptographically secure randomness

```bash
poetry run transcrypto rand [-h] {bits,int,bytes} ...
```

#### `rand bits`

Random integer with exact bit length (MSB may be 1)

```bash
poetry run transcrypto rand bits [-h] bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Number of bits ≥ 8 for base.RandBits. [type: int] |

#### `rand int`

Uniform random integer in [min, max], inclusive

```bash
poetry run transcrypto rand int [-h] min max
```

| Option/Arg | Description |
|---|---|
| `min` | Minimum (≥ 0). [type: str] |
| `max` | Maximum (> min). [type: str] |

#### `rand bytes`

Random bytes from the OS CSPRNG

```bash
poetry run transcrypto rand bytes [-h] n
```

| Option/Arg | Description |
|---|---|
| `n` | Number of bytes ≥ 1. [type: int] |

#### `hash`

Hashing (SHA-256 / SHA-512 / file)

```bash
poetry run transcrypto hash [-h] {sha256,sha512,file} ...
```

#### `hash sha256`

SHA-256 of input data

```bash
poetry run transcrypto hash sha256 [-h] data
```

| Option/Arg | Description |
|---|---|
| `data` | Input text (raw; or use --hex/--b64). [type: str] |

#### `hash sha512`

SHA-512 of input data

```bash
poetry run transcrypto hash sha512 [-h] data
```

| Option/Arg | Description |
|---|---|
| `data` | Input text (raw; or use --hex/--b64). [type: str] |

#### `hash file`

Hash file contents (streamed)

```bash
poetry run transcrypto hash file [-h] [--digest {sha256,sha512}] path
```

| Option/Arg | Description |
|---|---|
| `path` | Path to file. [type: str] |
| `--digest` | Digest (default: sha256). [choices: ['sha256', 'sha512'] (default: sha256)] |

#### `aes`

AES-256 operations (GCM/ECB) and key derivation

```bash
poetry run transcrypto aes [-h] {key,encrypt,decrypt,ecb} ...
```

#### `aes key`

Create/derive/store AES keys

```bash
poetry run transcrypto aes key [-h] {frompass} ...
```

#### `aes key frompass`

Derive key from a password (PBKDF2-HMAC-SHA256)

```bash
poetry run transcrypto aes key frompass [-h] [--print-b64] [--out OUT]
                                       [--protect PROTECT]
                                       password
```

| Option/Arg | Description |
|---|---|
| `password` | Password (leading/trailing spaces ignored). [type: str] |
| `--print-b64` | Print derived key (base64url). |
| `--out` | Save serialized AESKey to path. [type: str] |
| `--protect` | Password to encrypt the saved key file (Serialize). [type: str] |

#### `aes encrypt`

AES-256-GCM: encrypt (outputs IV||ct||tag)

```bash
poetry run transcrypto aes encrypt [-h] [-k KEY_B64] [-p KEY_PATH] [-a AAD]
                                  [--protect PROTECT]
                                  plaintext
```

| Option/Arg | Description |
|---|---|
| `plaintext` | Input data (raw; or use --in-hex/--in-b64). [type: str] |
| `-k, --key-b64` | Key as base64url (32 bytes). [type: str] |
| `-p, --key-path` | Path to serialized AESKey. [type: str] |
| `-a, --aad` | Associated data (optional). [type: str] |
| `--protect` | Password to decrypt key file if using --key-path. [type: str] |

#### `aes decrypt`

AES-256-GCM: decrypt IV||ct||tag

```bash
poetry run transcrypto aes decrypt [-h] [-k KEY_B64] [-p KEY_PATH] [-a AAD]
                                  [--protect PROTECT]
                                  ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Input blob (use --in-hex/--in-b64). [type: str] |
| `-k, --key-b64` | Key as base64url (32 bytes). [type: str] |
| `-p, --key-path` | Path to serialized AESKey. [type: str] |
| `-a, --aad` | Associated data (must match). [type: str] |
| `--protect` | Password to decrypt key file if using --key-path. [type: str] |

#### `aes ecb`

AES-ECB (unsafe; fixed 16-byte blocks only)

```bash
poetry run transcrypto aes ecb [-h] [-k KEY_B64] [-p KEY_PATH]
                              [--protect PROTECT]
                              {encrypthex,decrypthex} ...
```

| Option/Arg | Description |
|---|---|
| `-k, --key-b64` | Key as base64url (32 bytes). [type: str] |
| `-p, --key-path` | Path to serialized AESKey. [type: str] |
| `--protect` | Password to decrypt key file if using --key-path. [type: str] |

#### `aes ecb encrypthex`

Encrypt 16-byte hex block with AES-ECB

```bash
poetry run transcrypto aes ecb encrypthex [-h] block_hex
```

| Option/Arg | Description |
|---|---|
| `block_hex` | Plaintext block as 32 hex chars. [type: str] |

#### `aes ecb decrypthex`

Decrypt 16-byte hex block with AES-ECB

```bash
poetry run transcrypto aes ecb decrypthex [-h] block_hex
```

| Option/Arg | Description |
|---|---|
| `block_hex` | Ciphertext block as 32 hex chars. [type: str] |

#### `rsa`

Raw RSA over integers (no OAEP/PSS)

```bash
poetry run transcrypto rsa [-h] {new,encrypt,decrypt,sign,verify} ...
```

#### `rsa new`

Generate RSA private key

```bash
poetry run transcrypto rsa new [-h] [--out OUT] [--protect PROTECT] bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Modulus size in bits (e.g., 2048). [type: int] |
| `--out` | Save private key to path (Serialize). [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `rsa encrypt`

Encrypt integer with public key

```bash
poetry run transcrypto rsa encrypt [-h] --key KEY [--protect PROTECT] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message (e.g., "12345" or "0x..."). [type: str] |
| `--key` | Path to private/public key (Serialize). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `rsa decrypt`

Decrypt integer ciphertext with private key

```bash
poetry run transcrypto rsa decrypt [-h] --key KEY [--protect PROTECT]
                                  ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Integer ciphertext. [type: str] |
| `--key` | Path to private key (Serialize). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `rsa sign`

Sign integer message with private key

```bash
poetry run transcrypto rsa sign [-h] --key KEY [--protect PROTECT] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message. [type: str] |
| `--key` | Path to private key (Serialize). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `rsa verify`

Verify integer signature with public key

```bash
poetry run transcrypto rsa verify [-h] --key KEY [--protect PROTECT]
                                 message signature
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message. [type: str] |
| `signature` | Integer signature. [type: str] |
| `--key` | Path to private/public key (Serialize). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `elgamal`

Raw El-Gamal (no padding)

```bash
poetry run transcrypto elgamal [-h]
                              {shared,new,encrypt,decrypt,sign,verify} ...
```

#### `elgamal shared`

Generate shared parameters (p, g)

```bash
poetry run transcrypto elgamal shared [-h] --out OUT [--protect PROTECT] bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Bit length for prime modulus p. [type: int] |
| `--out` | Save shared key to path. [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `elgamal new`

Generate individual private key from shared

```bash
poetry run transcrypto elgamal new [-h] --shared SHARED --out OUT
                                  [--protect PROTECT]
```

| Option/Arg | Description |
|---|---|
| `--shared` | Path to shared (p,g). [type: str] |
| `--out` | Save private key to path. [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `elgamal encrypt`

Encrypt integer with public key

```bash
poetry run transcrypto elgamal encrypt [-h] --key KEY [--protect PROTECT]
                                      message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message 1 ≤ m < p. [type: str] |
| `--key` | Path to private/public key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `elgamal decrypt`

Decrypt El-Gamal ciphertext tuple (c1,c2)

```bash
poetry run transcrypto elgamal decrypt [-h] --key KEY [--protect PROTECT] c1 c2
```

| Option/Arg | Description |
|---|---|
| `c1` | [type: str] |
| `c2` | [type: str] |
| `--key` | Path to private key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `elgamal sign`

Sign integer message with private key

```bash
poetry run transcrypto elgamal sign [-h] --key KEY [--protect PROTECT] message
```

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `--key` | Path to private key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `elgamal verify`

Verify El-Gamal signature (s1,s2)

```bash
poetry run transcrypto elgamal verify [-h] --key KEY [--protect PROTECT]
                                     message s1 s2
```

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `s1` | [type: str] |
| `s2` | [type: str] |
| `--key` | Path to private/public key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `dsa`

Raw DSA (no hash, integer messages < q)

```bash
poetry run transcrypto dsa [-h] {shared,new,sign,verify} ...
```

#### `dsa shared`

Generate (p,q,g) with q | p-1

```bash
poetry run transcrypto dsa shared [-h] --out OUT [--protect PROTECT]
                                 p_bits q_bits
```

| Option/Arg | Description |
|---|---|
| `p_bits` | Bit length of p (≥ q_bits + 11). [type: int] |
| `q_bits` | Bit length of q (≥ 11). [type: int] |
| `--out` | Save shared params to path. [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `dsa new`

Generate DSA private key from shared

```bash
poetry run transcrypto dsa new [-h] --shared SHARED --out OUT
                              [--protect PROTECT]
```

| Option/Arg | Description |
|---|---|
| `--shared` | Path to shared (p,q,g). [type: str] |
| `--out` | Save private key to path. [type: str] |
| `--protect` | Password to encrypt saved key file. [type: str] |

#### `dsa sign`

Sign integer m (1 ≤ m < q)

```bash
poetry run transcrypto dsa sign [-h] --key KEY [--protect PROTECT] message
```

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `--key` | Path to private key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `dsa verify`

Verify DSA signature (s1,s2)

```bash
poetry run transcrypto dsa verify [-h] --key KEY [--protect PROTECT]
                                 message s1 s2
```

| Option/Arg | Description |
|---|---|
| `message` | [type: str] |
| `s1` | [type: str] |
| `s2` | [type: str] |
| `--key` | Path to private/public key. [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `sss`

Shamir Shared Secret (unauthenticated)

```bash
poetry run transcrypto sss [-h] {new,shares,recover,verify} ...
```

#### `sss new`

Generate SSS params (minimum, prime, coefficients)

```bash
poetry run transcrypto sss new [-h] --out OUT [--protect PROTECT] minimum bits
```

| Option/Arg | Description |
|---|---|
| `minimum` | Threshold t (≥ 2). [type: int] |
| `bits` | Prime modulus bit length (≥ 128 for non-toy). [type: int] |
| `--out` | Base path; will save ".priv" and ".pub". [type: str] |
| `--protect` | Password to encrypt saved files. [type: str] |

#### `sss shares`

Issue N shares for a secret (private params)

```bash
poetry run transcrypto sss shares [-h] --key KEY [--protect PROTECT]
                                 secret count
```

| Option/Arg | Description |
|---|---|
| `secret` | Secret as integer (supports 0x..). [type: str] |
| `count` | How many shares to produce. [type: int] |
| `--key` | Path to private SSS key (.priv). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `sss recover`

Recover secret from shares (public params)

```bash
poetry run transcrypto sss recover [-h] --key KEY [--protect PROTECT]
                                  shares [shares ...]
```

| Option/Arg | Description |
|---|---|
| `shares` | Shares as k:v (e.g., 2:123 5:456 ...). [nargs: +] |
| `--key` | Path to public SSS key (.pub). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `sss verify`

Verify a share against a secret (private params)

```bash
poetry run transcrypto sss verify [-h] --key KEY [--protect PROTECT]
                                 secret share
```

| Option/Arg | Description |
|---|---|
| `secret` | Secret as integer (supports 0x..). [type: str] |
| `share` | One share as k:v (e.g., 7:9999). [type: str] |
| `--key` | Path to private SSS key (.priv). [type: str] |
| `--protect` | Password to decrypt key file if needed. [type: str] |

#### `doc`

Documentation utilities

```bash
poetry run transcrypto doc [-h] {md} ...
```

#### `doc md`

Emit Markdown for the CLI (auto-synced)

```bash
poetry run transcrypto doc md [-h]
```

