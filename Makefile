# SPDX-FileCopyrightText: 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0

.PHONY: install fmt lint type test cov precommit ci

install:
	poetry install

fmt:
	poetry run ruff format .

lint:
	poetry run ruff check .

type:
	poetry run mypy src

test:
	poetry run pytest -q tests

integration:
	poetry run pytest -q tests_integration

cov:
	poetry run pytest --cov=src --cov-report=term-missing

flakes:
	poetry run pytest --flake-finder --flake-runs=100 -q tests

precommit:
	poetry run pre-commit run --all-files

ci: fmt lint type test integration precommit
