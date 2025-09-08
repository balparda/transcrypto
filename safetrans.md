<!-- cspell:disable -->
<!-- auto-generated; do not edit -->

# `safetrans` Command-Line Interface

`safetrans` is a command-line utility that provides ***safe*** crypto primitives. It serves as a convenient wrapper over the Python APIs, enabling only safe **cryptographic operations**, **number theory functions**, **secure randomness generation**, **hashing**, **AES**, **RSA**, **DSA**, **bidding**, **SSS**, and other utilities without writing code.

Invoke with:

```bash
poetry run safetrans <command> [sub-command] [options...]
```

## Global Options

| Option/Arg | Description |
|---|---|
| `-v, --verbose` | Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG) |

## Top-Level Commands

- **`random`** — `poetry run safetrans random [-h] {bits} ...`
- **`doc`** — `poetry run safetrans doc [-h] {md} ...`

```bash
Examples:

  # --- Randomness ---
  poetry run safetrans random bits 16

```

---

## `random`

Cryptographically secure randomness, from the OS CSPRNG.

```bash
poetry run safetrans random [-h] {bits} ...
```

### `random bits`

Random integer with exact bit length = `bits` (MSB will be 1).

```bash
poetry run safetrans random bits [-h] bits
```

| Option/Arg | Description |
|---|---|
| `bits` | Number of bits, ≥ 8 [type: int] |

**Example:**

```bash
$ poetry run safetrans random bits 16
36650
```

---

## `doc`

Documentation utilities. (Not for regular use: these are developer utils.)

```bash
poetry run safetrans doc [-h] {md} ...
```

### `doc md`

Emit Markdown docs for the CLI (see README.md section "Creating a New Version").

```bash
poetry run safetrans doc md [-h]
```

**Example:**

```bash
$ poetry run safetrans doc md > safetrans.md
<<saves file>>
```
