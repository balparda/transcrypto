#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
"""Balparda's TransCrypto."""

# import pdb

__author__ = 'balparda@github.com'
__version__: tuple[int, int, int] = (1, 0, 0)  # v1.0.0, 2025-07-20


class Error(Exception):
  """TransCrypto exception."""


def GCD(a: int, b: int) -> int:
  """Greatest Common Divisor, by the Euclid method."""
  if a < 0 or b < 0:
    raise Error(f'negative input: {a=} , {b=}')
  if a < b:
    a, b = b, a
  while b:
    r = a % b
    a, b = b, r
  return a


def ExtendedGCD(a: int, b: int) -> tuple[int, int, int]:
  """Greatest Common Divisor, extended, by the Euclid method.

  Returns:
    (gcd, x, y) so that a * x + b * y = gcd
  """
  if a < 0 or b < 0:
    raise Error(f'negative input: {a=} , {b=}')
  swapped = False
  if a < b:
    a, b = b, a
    swapped = True
  if not b:
    return (a, 0 if swapped else 1, 1 if swapped else 0)
  x1, x2, y1, y2 = 0, 1, 1, 0
  while b:
    q, r = divmod(a, b)
    x, y = x2 - q * x1, y2 - q * y1
    a, b, x1, x2, y1, y2 = b, r, x, x1, y, y1
  return (a, y2 if swapped else x2, x2 if swapped else y2)
