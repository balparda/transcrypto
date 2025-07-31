# TransCrypto

- [TransCrypto](#transcrypto)
  - [License](#license)
  - [Use](#use)
    - [Install](#install)
    - [Base Library](#base-library)
      - [Computing the Greatest Common Divisor](#computing-the-greatest-common-divisor)
      - [Fast Modular Arithmetic](#fast-modular-arithmetic)
      - [Modular Polynomials \& Lagrange Interpolation](#modular-polynomials--lagrange-interpolation)
      - [Primality testing \& Prime generators, Mersenne primes](#primality-testing--prime-generators-mersenne-primes)
      - [RSA (Rivest-Shamir-Adleman) Public Cryptography](#rsa-rivest-shamir-adleman-public-cryptography)
      - [SSS (Shamir Shared Secret)](#sss-shamir-shared-secret)
  - [Development Instructions](#development-instructions)
    - [Setup](#setup)
    - [Updating Dependencies](#updating-dependencies)
    - [Creating a New Version](#creating-a-new-version)

Basic crypto primitives, not intended for actual use, but as a companion to "Criptografia, Métodos e Algoritmos".

Started in July/2025, by Daniel Balparda. Since version 1.0.2 it is PyPI package:

<https://pypi.org/project/transcrypto/>

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

### Install

To use in your project just do:

```sh
pip3 install transcrypto
```

and then `from transcrypto import rsa` (or other parts of the library) for using it.

### Base Library

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

## Development Instructions

### Setup

If you want to develop for this project, first install [Poetry](https://python-poetry.org/docs/cli/), but make sure it is like this:

```sh
brew uninstall poetry
python3.11 -m pip install --user pipx
python3.11 -m pipx ensurepath
# re-open terminal
poetry self add poetry-plugin-export@^1.8  # allows export to requirements.txt (see below)
poetry config virtualenvs.in-project true  # creates venv inside project directory
poetry config pypi-token.pypi <TOKEN>      # add you personal project token
```

Now install the project:

```sh
brew install python@3.13 git
brew update
brew upgrade
brew cleanup -s
# or on Ubuntu/Debian: sudo apt-get install python3.13-venv git

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

pytest

deactivate
```

### Updating Dependencies

To update `poetry.lock` file to more current versions:

```sh
poetry update  # ignores current lock, updates, rewrites `poetry.lock` file
poetry run pytest
```

To add a new dependency you should:

```sh
poetry add "pkg>=1.2.3"  # regenerates lock, updates env
# also: "pkg@^1.2.3" = latest 1.* ; "pkg@~1.2.3" = latest 1.2.* ; "pkg@1.2.3" exact
poetry export --format requirements.txt --without-hashes --output requirements.txt
```

If you added a dependency to `pyproject.toml`:

```sh
poetry run pip3 freeze --all  # lists all dependencies pip knows about
poetry lock     # re-lock your dependencies, so `poetry.lock` is regenerated
poetry install  # sync your virtualenv to match the new lock file
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
