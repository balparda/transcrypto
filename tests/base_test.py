#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""base.py unittest."""

# import pdb
import sys

import pytest

from src.transcrypto import base

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: tuple[int, int, int] = base.__version__  # tests inherit version from module


@pytest.mark.parametrize('n', [1, 17, 10 ** 12])
def test_GCD_same_number(n: int) -> None:
  """Test."""
  assert base.GCD(n, n) == n
  g, x, y = base.ExtendedGCD(n, n)
  assert g == n == n * (x + y)  # because x or y will be 0


@pytest.mark.parametrize('a, b, gcd, x, y', [
    (0, 1, 1, 0, 1),
    (1, 0, 1, 1, 0),
    (1, 2, 1, 1, 0),
    (2, 1, 1, 0, 1),
    (12, 18, 6, -1, 1),
    (3, 7, 1, -2, 1),
    (7, 3, 1, 1, -2),
    (100, 24, 4, 1, -4),
    (100, 0, 100, 1, 0),
    (24, 100, 4, -4, 1),
    (367613542, 2136213, 59, 15377, -2646175),
    (2354153438, 65246322, 2, 4133449, -149139030),
    (7238649876345, 36193249381725, 7238649876345, 1, 0),
])
def test_GCD(a: int, b: int, gcd: int, x: int, y: int) -> None:
  """Test."""
  assert base.GCD(a, b) == gcd
  assert base.ExtendedGCD(a, b) == (gcd, x, y)
  assert gcd == a * x + b * y


@pytest.mark.parametrize('a, b', [
    (-1, 1),
    (1, -1),
    (0, 0),
])
def test_GCD_negative(a: int, b: int) -> None:
  """Test."""
  with pytest.raises(base.InputError, match='negative input'):
    base.GCD(a, b)
  with pytest.raises(base.InputError, match='negative input'):
    base.ExtendedGCD(a, b)


def test_NegativeZero() -> None:
  """Test."""
  assert base.GCD(-0, 5) == 5  # Python’s -0 is 0
  g, x, y = base.ExtendedGCD(-0, 5)
  assert g == 5 and 5 * y == 5 and not x
  assert 0 == -0


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
