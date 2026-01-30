# SPDX-FileCopyrightText: 2026 Daniel Balparda <balparda@github.com>
# SPDX-License-Identifier: Apache-2.0

.PHONY: install fmt lint type test integration cov flakes precommit docs ci

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
	poetry run pytest --cov=src --cov-report=term-missing -q tests

flakes:
	poetry run pytest --flake-finder --flake-runs=100 -q tests

precommit:
	poetry run pre-commit run --all-files

docs:
	@echo "Generating transcrypto.md & profiler.md"
	poetry run transcrypto markdown > transcrypto.md
	poetry run profiler markdown > profiler.md

ci: cov integration precommit docs
	@echo "CI checks passed! Generated docs."
