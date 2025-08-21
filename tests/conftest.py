#!/usr/bin/env python3
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# pylint: disable=invalid-name,protected-access
# pyright: reportPrivateUsage=false
"""pytest configurations."""

import pytest
from typeguard import install_import_hook


@pytest.hookimpl(tryfirst=True)               # cspell:disable-line
def pytest_configure(unused_config) -> None:  # type:ignore
  """Configure pytest to use typeguard for type checking."""
  install_import_hook('src.transcrypto')
