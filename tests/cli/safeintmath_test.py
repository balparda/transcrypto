# SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0
"""cli/safeintmath.py unittest.

Run with:
  poetry run pytest -vvv tests/cli/safeintmath_test.py
"""

from __future__ import annotations

import re

import pytest
from click import testing as click_testing

from tests import safetrans_test
from transcrypto.core import modmath
from transcrypto.utils import config as app_config
from transcrypto.utils import logging as tc_logging


@pytest.fixture(autouse=True)
def reset_cli() -> None:
  """Reset CLI singleton before each test."""
  tc_logging.ResetConsole()
  app_config.ResetConfig()


def test_rand_bits_properties() -> None:
  """Test random bits CLI command output properties."""
  res: click_testing.Result = safetrans_test._CallCLI(['random', 'bits', '16'])
  assert res.exit_code == 0
  n = int(safetrans_test.OneToken(res))
  assert 1 << 15 <= n < (1 << 16)  # exact bit length 16, msb=1


def test_rand_int_properties() -> None:
  """Test random int CLI command output properties."""
  res: click_testing.Result = safetrans_test._CallCLI(['random', 'int', '5', '9'])
  assert res.exit_code == 0
  n = int(safetrans_test.OneToken(res))
  assert 5 <= n <= 9


def test_rand_bytes_shape() -> None:
  """Test random bytes CLI command output shape."""
  res: click_testing.Result = safetrans_test._CallCLI(['random', 'bytes', '4'])
  assert res.exit_code == 0
  # CLI prints hex for rand bytes
  assert re.fullmatch(r'[0-9a-f]{8}', safetrans_test.OneToken(res)) is not None


def test_cli_random_int_invalid_range_prints_error() -> None:
  """Cover RandomInt CLI error branch when max <= min."""
  res: click_testing.Result = safetrans_test._CallCLI(['random', 'int', '9', '5'])
  assert res.exit_code == 0
  assert 'int must be ≥ 10, got 5' in res.output


@pytest.mark.parametrize('bits', [11, 32, 64])
def test_random_prime_properties(bits: int) -> None:
  """Test randomprime CLI command output properties."""
  res: click_testing.Result = safetrans_test._CallCLI(['random', 'prime', str(bits)])
  assert res.exit_code == 0
  p = int(safetrans_test.OneToken(res))
  # exact bit-size guarantee and primality
  assert p.bit_length() == bits
  assert modmath.IsPrime(p) is True
