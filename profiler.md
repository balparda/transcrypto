<!-- cspell:disable -->
<!-- auto-generated; do not edit -->

# `profiler` Command-Line Interface

`profiler` is a command-line utility that provides stats on TransCrypto performance.

Invoke with:

```bash
poetry run profiler <command> [sub-command] [options...]
```

## Global Options

| Option/Arg | Description |
|---|---|
| `-v, --verbose` | Increase verbosity (use -v/-vv/-vvv/-vvvv for ERROR/WARN/INFO/DEBUG) |
| `-s, --serial` | If test can be serial, do it like that with no parallelization (default) |
| `-p, --parallel` | If test can be parallelized into processes, do it like that |
| `-n, --number` | Number of experiments (repeats) for every measurement [type: int (default: 15)] |
| `-c, --confidence` | Confidence level to evaluate measurements at as int percentage points [50,99], inclusive, representing 50% to 99% [type: int (default: 98)] |
| `-b, --bits` | Bit lengths to investigate as "int,int,int"; behaves like arguments for range(), i.e., "start,stop,step", eg. "1000,3000,500" will investigate 1000,1500,2000,2500 [type: str (default: 1000,9000,1000)] |

## Top-Level Commands

- **`primes`** — `poetry run profiler primes [-h]`
- **`dsa`** — `poetry run profiler dsa [-h]`
- **`doc`** — `poetry run profiler doc [-h] {md} ...`

```bash
Examples:

  # --- Primes ---
  poetry run profiler -p -n 10 primes
  poetry run profiler -n 20 dsa

```

---

## `primes`

Measure regular prime generation.

```bash
poetry run profiler primes [-h]
```

**Example:**

```bash
$ poetry run profiler -n 30 -b 9000,11000,1000 primes
Starting SERIAL regular primes test
9000 → 38.88 s ± 14.74 s [24.14 s … 53.63 s]98%CI@30
10000 → 41.26 s ± 22.82 s [18.44 s … 1.07 min]98%CI@30
Finished in 40.07 min
```

---

## `dsa`

Measure DSA prime generation.

```bash
poetry run profiler dsa [-h]
```

**Example:**

```bash
$ poetry run profiler -p -n 2 -b 1000,1500,100 -c 80 dsa
Starting PARALLEL DSA primes test
1000 → 236.344 ms ± 273.236 ms [*0.00 s … 509.580 ms]80%CI@2
1100 → 319.308 ms ± 639.775 ms [*0.00 s … 959.083 ms]80%CI@2
1200 → 523.885 ms ± 879.981 ms [*0.00 s … 1.40 s]80%CI@2
1300 → 506.285 ms ± 687.153 ms [*0.00 s … 1.19 s]80%CI@2
1400 → 552.840 ms ± 47.012 ms [505.828 ms … 599.852 ms]80%CI@2
Finished in 4.12 s
```

---

## `doc`

Documentation utilities. (Not for regular use: these are developer utils.)

```bash
poetry run profiler doc [-h] {md} ...
```

### `doc md`

Emit Markdown docs for the CLI (see README.md section "Creating a New Version").

```bash
poetry run profiler doc md [-h]
```

**Example:**

```bash
$ poetry run profiler doc md > profiler.md
<<saves file>>
```
