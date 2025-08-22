
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
