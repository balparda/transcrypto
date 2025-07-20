#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""transcrypto.py unittest."""

# import pdb
import sys

import pytest

from src.transcrypto import transcrypto

__author__ = 'balparda@github.com (Daniel Balparda)'
__version__: tuple[int, int, int] = transcrypto.__version__  # tests inherit version from module


@pytest.mark.parametrize('a, b, gcd, x, y', [
    (0, 0, 0, 1, 0),
    (0, 1, 1, 0, 1),
    (1, 0, 1, 1, 0),
    (1, 2, 1, 1, 0),
    (2, 1, 1, 0, 1),
    (12, 18, 6, -1, 1),
    (3, 7, 1, -2, 1),
    (7, 3, 1, 1, -2),
    (100, 24, 4, 1, -4),
    (24, 100, 4, -4, 1),
    (367613542, 2136213, 59, 15377, -2646175),
    (2354153438, 65246322, 2, 4133449, -149139030),
    (7238649876345, 36193249381725, 7238649876345, 1, 0),
])
def test_GCD(a: int, b: int, gcd: int, x: int, y: int) -> None:
  """Test."""
  assert transcrypto.GCD(a, b) == gcd
  assert transcrypto.ExtendedGCD(a, b) == (gcd, x, y)
  assert gcd == a * x + b * y


@pytest.mark.parametrize('a, b', [
    (-1, 1),
    (1, -1),
])
def test_GCD_negative(a, b) -> None:
  """Test."""
  with pytest.raises(transcrypto.Error, match='negative input'):
    transcrypto.GCD(a, b)
  with pytest.raises(transcrypto.Error, match='negative input'):
    transcrypto.ExtendedGCD(a, b)


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
