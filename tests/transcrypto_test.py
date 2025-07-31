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
__version__: str = transcrypto.__version__  # tests inherit version from module


if __name__ == '__main__':
  # run only the tests in THIS file but pass through any extra CLI flags
  args: list[str] = sys.argv[1:] + [__file__]
  print(f'pytest {" ".join(args)}')
  sys.exit(pytest.main(sys.argv[1:] + [__file__]))
