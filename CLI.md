
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
- **`rsa`** — `poetry run transcrypto rsa [-h] {new,encrypt,decrypt,sign,verify} ...`
- **`elgamal`** — `poetry run transcrypto elgamal [-h]`
- **`dsa`** — `poetry run transcrypto dsa [-h] {shared,new,sign,verify} ...`
- **`sss`** — `poetry run transcrypto sss [-h] {new,shares,recover,verify} ...`
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
  poetry run transcrypto -p rsa-key.pub rsa encrypt <plaintext>
  poetry run transcrypto -p rsa-key.priv rsa decrypt <ciphertext>
  poetry run transcrypto -p rsa-key.priv rsa sign <message>
  poetry run transcrypto -p rsa-key.pub rsa verify <message> <signature>

  # --- ElGamal ---
  poetry run transcrypto -p eg-key elgamal shared --bits 2048
  poetry run transcrypto -p eg-key elgamal new
  poetry run transcrypto -p eg-key.pub elgamal encrypt <plaintext>
  poetry run transcrypto -p eg-key.priv elgamal decrypt <c1:c2>
  poetry run transcrypto -p eg-key.priv elgamal sign <message>
  poetry run transcrypto-p eg-key.pub elgamal verify <message> <s1:s2>

  # --- DSA ---
  poetry run transcrypto -p dsa-key dsa shared --p-bits 2048 --q-bits 256
  poetry run transcrypto -p dsa-key dsa new
  poetry run transcrypto -p dsa-key.priv dsa sign <message>
  poetry run transcrypto -p dsa-key.pub dsa verify <message> <s1:s2>

  # --- Shamir Secret Sharing (SSS) ---
  poetry run transcrypto -p sss-key sss new 3 --bits 1024
  poetry run transcrypto -p sss-key sss shares <secret> 5
  poetry run transcrypto -p sss-key sss recover
  poetry run transcrypto -p sss-key sss verify <secret>
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
poetry run transcrypto rsa [-h] {new,encrypt,decrypt,sign,verify} ...
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

#### `rsa encrypt`

Encrypt integer `message` with public key.

```bash
poetry run transcrypto rsa encrypt [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to encrypt, 1≤`message`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key.pub rsa encrypt 999
6354905961171348600
```

#### `rsa decrypt`

Decrypt integer `ciphertext` with private key.

```bash
poetry run transcrypto rsa decrypt [-h] ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Integer ciphertext to decrypt, 1≤`ciphertext`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key.priv rsa decrypt 6354905961171348600
999
```

#### `rsa sign`

Sign integer `message` with private key.

```bash
poetry run transcrypto rsa sign [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to sign, 1≤`message`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key.priv rsa sign 999
7632909108672871784
```

#### `rsa verify`

Verify integer `signature` for integer `message` with public key.

```bash
poetry run transcrypto rsa verify [-h] message signature
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message that was signed earlier, 1≤`message`<*modulus* [type: str] |
| `signature` | Integer putative signature for `message`, 1≤`signature`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p rsa-key.pub rsa verify 999 7632909108672871784
RSA signature: OK
$ poetry run transcrypto -p rsa-key.pub rsa verify 999 7632909108672871785
RSA signature: INVALID
```

---

### `elgamal`

Raw El-Gamal asymmetric cryptography over *integers* (BEWARE: no ECIES-style KEM/DEM padding or validation). These are pedagogical/raw primitives; do not use for new protocols. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` (see provided examples).

```bash
poetry run transcrypto elgamal [-h]
                                      {shared,new,encrypt,decrypt,sign,verify} ...
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

#### `elgamal encrypt`

Encrypt integer `message` with public key.

```bash
poetry run transcrypto elgamal encrypt [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to encrypt, 1≤`message`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key.pub elgamal encrypt 999
2948854810728206041:15945988196340032688
```

#### `elgamal decrypt`

Decrypt integer `ciphertext` with private key.

```bash
poetry run transcrypto elgamal decrypt [-h] ciphertext
```

| Option/Arg | Description |
|---|---|
| `ciphertext` | Integer ciphertext to decrypt; expects `c1:c2` format with 2 integers,  2≤`c1`,`c2`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key.priv elgamal decrypt 2948854810728206041:15945988196340032688
999
```

#### `elgamal sign`

Sign integer message with private key. Output will 2 integers in a `s1:s2` format.

```bash
poetry run transcrypto elgamal sign [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to sign, 1≤`message`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key.priv elgamal sign 999
4674885853217269088:14532144906178302633
```

#### `elgamal verify`

Verify integer `signature` for integer `message` with public key.

```bash
poetry run transcrypto elgamal verify [-h] message signature
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message that was signed earlier, 1≤`message`<*modulus* [type: str] |
| `signature` | Integer putative signature for `message`; expects `s1:s2` format with 2 integers,  2≤`s1`,`s2`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p eg-key.pub elgamal verify 999 4674885853217269088:14532144906178302633
El-Gamal signature: OK
$ poetry run transcrypto -p eg-key.pub elgamal verify 999 4674885853217269088:14532144906178302632
El-Gamal signature: INVALID
```

---

### `dsa`

Raw DSA (Digital Signature Algorithm) asymmetric signing over *integers* (BEWARE: no ECDSA/EdDSA padding or validation). These are pedagogical/raw primitives; do not use for new protocols. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` (see provided examples).

```bash
poetry run transcrypto dsa [-h] {shared,new,sign,verify} ...
```

#### `dsa shared`

Generate a shared DSA key with `p-bits`/`q-bits` prime modulus sizes, which is the first step in key generation. `q-bits` should be larger than the secrets that will be protected and `p-bits` should be much larger than `q-bits` (e.g. 3584/256). The shared key can safely be used by any number of users to generate their private/public key pairs (with the `new` command). The shared keys are "public". Requires `-p`/`--key-path` to set the basename for output files.

```bash
poetry run transcrypto dsa shared [-h] [--p-bits P_BITS]
                                         [--q-bits Q_BITS]
```

| Option/Arg | Description |
|---|---|
| `--p-bits` | Prime modulus (`p`) size in bits; the default is a safe size [type: int (default: 3584)] |
| `--q-bits` | Prime modulus (`q`) size in bits; the default is a safe size ***IFF*** you are protecting symmetric keys or regular hashes [type: int (default: 256)] |

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

#### `dsa sign`

Sign integer message with private key. Output will 2 integers in a `s1:s2` format.

```bash
poetry run transcrypto dsa sign [-h] message
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message to sign, 1≤`message`<`q` [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p dsa-key.priv dsa sign 999
2395961484:3435572290
```

#### `dsa verify`

Verify integer `signature` for integer `message` with public key.

```bash
poetry run transcrypto dsa verify [-h] message signature
```

| Option/Arg | Description |
|---|---|
| `message` | Integer message that was signed earlier, 1≤`message`<`q` [type: str] |
| `signature` | Integer putative signature for `message`; expects `s1:s2` format with 2 integers,  2≤`s1`,`s2`<`q` [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p dsa-key.pub dsa verify 999 2395961484:3435572290
DSA signature: OK
$ poetry run transcrypto -p dsa-key.pub dsa verify 999 2395961484:3435572291
DSA signature: INVALID
```

---

### `sss`

Raw SSS (Shamir Shared Secret) secret sharing crypto scheme over *integers* (BEWARE: no modern message wrapping, padding or validation). These are pedagogical/raw primitives; do not use for new protocols. No measures are taken here to prevent timing attacks. All methods require file key(s) as `-p`/`--key-path` (see provided examples).

```bash
poetry run transcrypto sss [-h] {new,shares,recover,verify} ...
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

#### `sss shares`

Issue `count` private shares for an integer `secret`.

```bash
poetry run transcrypto sss shares [-h] secret count
```

| Option/Arg | Description |
|---|---|
| `secret` | Integer secret to be protected, 1≤`secret`<*modulus* [type: str] |
| `count` | How many shares to produce; must be ≥ `minimum` used in `new` command or else the `secret` would become unrecoverable [type: int] |

**Example:**

```bash
$ poetry run transcrypto -p sss-key sss shares 999 5
SSS 5 individual (private) shares saved to 'sss-key.share.1…5'
$ rm sss-key.share.2 sss-key.share.4  # this is to simulate only having shares 1,3,5
```

#### `sss recover`

Recover secret from shares; will use any available shares that were found.

```bash
poetry run transcrypto sss recover [-h]
```

**Example:**

```bash
$ poetry run transcrypto -p sss-key sss recover
Loaded SSS share: 'sss-key.share.3'
Loaded SSS share: 'sss-key.share.5'
Loaded SSS share: 'sss-key.share.1'  # using only 3 shares: number 2/4 are missing
Secret:
999
```

#### `sss verify`

Verify shares against a secret (private params).

```bash
poetry run transcrypto sss verify [-h] secret
```

| Option/Arg | Description |
|---|---|
| `secret` | Integer secret used to generate the shares, 1≤`secret`<*modulus* [type: str] |

**Example:**

```bash
$ poetry run transcrypto -p sss-key sss verify 999
SSS share 'sss-key.share.3' verification: OK
SSS share 'sss-key.share.5' verification: OK
SSS share 'sss-key.share.1' verification: OK
$ poetry run transcrypto -p sss-key sss verify 998
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

