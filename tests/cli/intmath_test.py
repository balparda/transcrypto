# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""cli/intmath.py unittest."""

from __future__ import annotations

import re
import textwrap

import pytest
from click import testing as click_testing

from tests import transcrypto_test
from transcrypto import modmath
from transcrypto.cli import clibase


@pytest.fixture(autouse=True)
def _reset_cli() -> None:
  """Reset CLI singleton before each test."""
  clibase.ResetConsole()


@pytest.mark.parametrize(
  ('argv', 'expected'),
  [
    # --- primality ---
    (['isprime', '2305843009213693951'], 'True'),
    (['isprime', '2305843009213693953'], 'False'),
    # --- gcd / xgcd ---
    (['gcd', '462', '1071'], '21'),
    (['xgcd', '100', '24'], '(4, 1, -4)'),
    # --- modular arithmetic ---
    (['mod', 'inv', '0x3', '11'], '4'),  # 3^-1 mod 11 = 4
    (['mod', 'inv', '3', '9'], '<<INVALID>> no modular inverse exists (ModularDivideError)'),
    (['mod', 'div', '0o12', '4', '13'], '9'),  # z*4 ≡ 10 (mod 13) → z = 9
    (
      ['mod', 'div', '4', '0', '13'],
      '<<INVALID>> divide-by-zero or not invertible (ModularDivideError)',
    ),
    (['mod', 'exp', '3', '20', '97'], '91'),  # 3^20 mod 97 = 91 (precomputed)
    (['mod', 'poly', '127', '19937', '10', '30', '20', '12', '31'], '12928'),
    (['mod', 'lagrange', '9', '5', '1:1', '3:3'], '4'),
    (['mod', 'crt', '0b10', '3', '3', '5'], '8'),
    (
      ['mod', 'crt', '2', '3', '3', '0xf'],
      '<<INVALID>> moduli `m1`/`m2` not co-prime (ModularDivideError)',
    ),
    # --- prime generation (deterministic with -c) ---
    (
      ['primegen', '10', '-c', '5'],
      textwrap.dedent("""\
            11
            13
            17
            19
            23""").strip(),
    ),
    (
      ['mersenne', '--min-k', '2', '--max-k', '13'],
      textwrap.dedent("""\
            k=2  M=3  perfect=6
            k=3  M=7  perfect=28
            k=5  M=31  perfect=496
            k=7  M=127  perfect=8128
            k=13  M=8191  perfect=33550336""").strip(),
    ),
  ],
)
def test_cli_deterministic_pairs(argv: list[str], expected: str) -> None:
  """Test CLI commands with deterministic outputs."""
  res: click_testing.Result = transcrypto_test.CallCLI(argv)
  assert res.exit_code == 0, f'non-zero exit for argv={argv!r}'
  if '\n' in expected:
    assert transcrypto_test.Out(res) == expected
  else:
    assert transcrypto_test.OneToken(res) == expected


@pytest.mark.parametrize(
  ('argv', 'needle'),
  [
    (
      ['primegen', '10', '-c', '0'],
      "Invalid value for '-c' / '--count': 0 is not in the range x>=1",
    ),
    (
      ['mersenne', '--min-k', '0', '--max-k', '5'],
      "Invalid value for '-k' / '--min-k': 0 is not in the range x>=1",
    ),
    (
      ['mersenne', '--min-k', '2', '--max-k', '0'],
      "Invalid value for '-m' / '--max-k': 0 is not in the range x>=1",
    ),
  ],
)
def test_cli_validations_print_errors(argv: list[str], needle: str) -> None:
  """Test CLI argument validations print expected error messages."""
  res: click_testing.Result = transcrypto_test.CallCLI(argv)
  assert res.exit_code == 2
  assert needle in transcrypto_test.CLIOutput(res)


def test_cli_gcd_both_zero_prints_error() -> None:
  """Cover GCD CLI error branch when both inputs are zero."""
  res: click_testing.Result = transcrypto_test.CallCLI(['gcd', '0', '0'])
  assert res.exit_code == 0
  assert "`a` and `b` can't both be zero" in res.output


def test_cli_xgcd_both_zero_prints_error() -> None:
  """Cover XGCD CLI error branch when both inputs are zero."""
  res: click_testing.Result = transcrypto_test.CallCLI(['xgcd', '0', '0'])
  assert res.exit_code == 0
  assert "`a` and `b` can't both be zero" in res.output


def test_cli_mersenne_max_lt_min_prints_error() -> None:
  """Cover Mersenne CLI error branch when max_k < min_k."""
  res: click_testing.Result = transcrypto_test.CallCLI(
    ['mersenne', '--min-k', '10', '--max-k', '5']
  )
  assert res.exit_code == 0
  assert 'max-k (5) must be >= min-k (10)' in res.output


def test_rand_bits_properties() -> None:
  """Test random bits CLI command output properties."""
  res: click_testing.Result = transcrypto_test.CallCLI(['random', 'bits', '16'])
  assert res.exit_code == 0
  n = int(transcrypto_test.OneToken(res))
  assert 1 << 15 <= n < (1 << 16)  # exact bit length 16, msb=1


def test_rand_int_properties() -> None:
  """Test random int CLI command output properties."""
  res: click_testing.Result = transcrypto_test.CallCLI(['random', 'int', '5', '9'])
  assert res.exit_code == 0
  n = int(transcrypto_test.OneToken(res))
  assert 5 <= n <= 9


def test_rand_bytes_shape() -> None:
  """Test random bytes CLI command output shape."""
  res: click_testing.Result = transcrypto_test.CallCLI(['random', 'bytes', '4'])
  assert res.exit_code == 0
  # CLI prints hex for rand bytes
  assert re.fullmatch(r'[0-9a-f]{8}', transcrypto_test.OneToken(res)) is not None


def test_cli_random_int_invalid_range_prints_error() -> None:
  """Cover RandomInt CLI error branch when max <= min."""
  res: click_testing.Result = transcrypto_test.CallCLI(['random', 'int', '9', '5'])
  assert res.exit_code == 0
  assert 'int must be ≥ 10, got 5' in res.output


@pytest.mark.parametrize('bits', [11, 32, 64])
def test_random_prime_properties(bits: int) -> None:
  """Test randomprime CLI command output properties."""
  res: click_testing.Result = transcrypto_test.CallCLI(['random', 'prime', str(bits)])
  assert res.exit_code == 0
  p = int(transcrypto_test.OneToken(res))
  # exact bit-size guarantee and primality
  assert p.bit_length() == bits
  assert modmath.IsPrime(p) is True
