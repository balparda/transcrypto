# Copilot Instructions

This is `transcrypto`, a Python/Poetry cryptography library and CLI tool. It provides basic crypto
primitives (AES, RSA, ElGamal, DSA, Shamir Secret Sharing, modular arithmetic, hashing) as a
companion to the book *"Criptografia, Métodos e Algoritmos"*. Published on PyPI. It also provides
reusable utility modules (logging, config, human formatting, timing, random, stats, base
conversions) used by dependent projects.

## Running Code and Tests

- All non-`make` commands should be run from the Poetry environment: `poetry run <command>`
- Two CLI apps: `poetry run transcrypto <command>` and `poetry run profiler <command>`
- To run tests on a file: `poetry run pytest tests/<file>_test.py`

## Code Standards

### Required Before Each Commit

- Run `make test` to ensure all tests pass
- Run `make ci` runs everything, to ensure integration tests and linters pass, also to generate auto-generated code
- When adding new functionality, make sure you update the `README.md` and `CHANGELOG.md` files

### Styling

- Zero lint errors or warnings
- Try to always keep line length under 100 characters
- All files must have a license header (e.g., `# SPDX-License-Identifier: Apache-2.0` for Python files, `<!-- SPDX-License-Identifier: Apache-2.0 -->` for Markdown files, etc)

- Use Python conventions, but note that:
  - Use 2 spaces for indentation
  - Always prefer single quotes (`'`) but use double quotes in docstrings (`"""`)
  - Google-style docstrings with complete type annotations in the `Args` and `Returns` sections
  - Methods and Classes must be named in CamelCase; test methods can be snake_case but must start with `test_`, but I prefer test methods to be in CamelCase as well as `testSomething`
  - Start private Classes, Methods, and fields with an underscore (`_`). Only make public what is strictly necessary, the rest keep private
  - Always use `from __future__ import annotations`
  - MyPy strict + Pyright strict + typeguard everywhere. Always add complete type annotations. Avoid creating typeguard exceptions in tests as much as possible.
  - Testfiles are `<module>_test.py`, NOT `test_<module>.py` and tests mirror source structure
  - Project selects `"ALL"` Ruff rules and adds just a few exceptions
  - Never import except at the top, not even for tests, not even for type checking: ALL imports at the top always (only acceptable exception is CLI modules imports to register commands)

### CLI Architecture

- Two separate Typer apps: `transcrypto` (main crypto CLI) and `profiler` (benchmarking CLI)
- Each has a global callback (`@app.callback`) handling `--version`, `--verbose`, `--color` and storing config in `ctx.obj`
- `transcrypto` also has `--input-format`/`--output-format` (hex/b64/bin) and `--key-path`/`--protect` for key management
- Every command receives `ctx: click.Context` and reads config via `config = ctx.obj`
- Every command is decorated with `@clibase.CLIErrorGuard` (from `transcrypto.cli.clibase`)
- Subcommand groups (e.g., `random`, `mod`, `hash`, `aes`, `rsa`, `elgamal`, `dsa`, `bid`, `sss`) use `app.add_typer(...)`
- CLI modules are imported at the bottom of the main app file to register commands: `from transcrypto.cli import aeshash, bidsecret, intmath, publicalgos`

### Key Utilities

- `transcrypto.utils.logging` — Rich console singleton, `InitLogging()`, `Console()`, `ResetConsole()`
- `transcrypto.utils.config` — config management, `InitConfig()`, `ResetConfig()`, wheel build helpers
- `transcrypto.utils.base` — error classes, bytes/int/hex/base64 conversions, `Run()` subprocess helper
- `transcrypto.utils.human` — human-friendly formatting (bytes, decimals, seconds)
- `transcrypto.utils.saferandom` — cryptographically secure random generation
- `transcrypto.utils.stats` — simple statistical results
- `transcrypto.utils.timer` — timing (context manager, decorator, manual)
- `transcrypto.cli.clibase` — `CLIErrorGuard`, `CLIConfig`, `GenerateTyperHelpMarkdown()`
- `transcrypto.core.key` — `CryptoKey` base class, `Serialize`/`DeSerialize`
- `transcrypto.core.aes` — AES-256 (GCM + ECB)
- `transcrypto.core.rsa`, `.elgamal`, `.dsa` — public-key crypto implementations
- `transcrypto.core.modmath` — modular arithmetic, primality, prime generation, CRT, Lagrange
- `transcrypto.core.hashes` — SHA-256, SHA-512, file hashing
- `transcrypto.core.bid` — public bidding protocol
- `transcrypto.core.sss` — Shamir Secret Sharing

## Testing Patterns

- Test files mirror source: `src/transcrypto/cli/foo.py` → `tests/cli/foo_test.py`
- Shared test helpers (`_CallCLI()`, `Out()`, `OneToken()`, `CLIOutput()`) live in `tests/transcrypto_test.py` and are imported by sub-tests
- `tests/util.py` has shared `TestCryptoKeyEncoding()` for JSON/blob/encoded/hex/raw round-trips
- Use `@pytest.fixture(autouse=True)` to reset singletons (`cli_logging.ResetConsole()`, `app_config.ResetConfig()`) before each test
- CLI tests use `typer.testing.CliRunner().invoke(app, args, env={'COLUMNS': '2000'})` for real CLI wiring
- Use `@pytest.mark.parametrize` heavily for data-driven tests
- Use `unittest.mock.patch` to mock `transcrypto.utils.logging.rich_console.Console` and assert on `console.print(...)` calls
- Mark tests with `@pytest.mark.slow`, `@pytest.mark.veryslow`, `@pytest.mark.stochastic`, `@pytest.mark.integration` as appropriate
- Integration tests (`tests_integration/`) build a wheel, install into a temp venv, and run both `transcrypto` and `profiler` CLIs

## Repository Structure

- `CHANGELOG.md`: latest changes/releases
- `Makefile`: commands for testing, linting, generating code, etc
- `transcrypto.md` / `profiler.md`: auto-generated CLI docs (by `make docs` or `make ci`)
- `pyproject.toml`: most important configurations live here
- `README.md`: main documentation
- `requirements.txt`: auto-generated file (by `make req` or `make ci`)
- `.github/`: Github configs and pipelines
- `.vscode/`: VSCode configs
- `src/transcrypto/`: Main source code
  - `src/transcrypto/__init__.py`: Version lives here (e.g., `__version__ = "2.3.3"`) and in `pyproject.toml` both
  - `src/transcrypto/transcrypto.py`: Main crypto CLI app entry point
  - `src/transcrypto/profiler.py`: Profiler CLI app entry point
  - `src/transcrypto/cli/`: CLI subcommand modules (intmath, aeshash, publicalgos, bidsecret, clibase)
  - `src/transcrypto/core/`: Crypto implementations (aes, rsa, elgamal, dsa, modmath, hashes, key, bid, sss, constants)
  - `src/transcrypto/utils/`: Utility modules (base, human, logging, config, saferandom, stats, timer)
- `tests/`: Unit tests (mirrors source structure) + `util.py` shared helper
- `tests_integration/`: Integration tests (wheel build + install + smoke tests)
