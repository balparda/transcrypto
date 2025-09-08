#!/usr/bin/env bash
#
# Copyright 2025 Daniel Balparda (balparda@github.com) - Apache-2.0 license
#
# Generates markdown docs
#

poetry run transcrypto doc md > transcrypto.md
poetry run profiler doc md > profiler.md
poetry run safetrans doc md > safetrans.md
