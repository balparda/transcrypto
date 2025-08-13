#!/usr/bin/env bash
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# https://coverage.readthedocs.io/
#

poetry run python3 -m coverage run --omit=__init__.py,*_test.py,*_tests.py,conftest.py,*/dist-packages/*,*/site-packages/* -m pytest
poetry run python3 -m coverage report -m
poetry run python3 -m coverage html
