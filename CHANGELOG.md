<!-- SPDX-FileCopyrightText: Copyright 2026 Daniel Balparda <balparda@github.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

All notable changes to this project will be documented in this file.

- [Changelog](#changelog)
  - [V.V.V - YYYY-MM-DD - Placeholder](#vvv---yyyy-mm-dd---placeholder)
  - [2.7.0 - 2026-06-09](#270---2026-06-09)
  - [2.6.0 - 2026-04-09](#260---2026-04-09)
  - [2.5.0 - 2026-04-03](#250---2026-04-03)
  - [2.0.0 - 2026-01-30](#200---2026-01-30)
  - [1.7.0 - 2026-01-26](#170---2026-01-26)

This project follows a pragmatic versioning approach:

- **Patch**: bug fixes / docs / small improvements.
- **Minor**: new template features or non-breaking developer workflow changes.
- **Major**: breaking template changes (e.g., required file/command renames).

## V.V.V - YYYY-MM-DD - Placeholder

- Added
  - Placeholder for future changes.

- Changed
  - Placeholder for future changes.

- Fixed
  - Placeholder for future changes.

## 2.7.0 - 2026-06-09

- Added
  - SHA algorithm enum for hash selection

- Changed
  - Upgraded Typer from 0.24.1 to 0.26.7 (now uses typer's own CLI infrastructure, removed click dependency)
  - Upgraded Rich from 14.3.3 to 15.0
  - Upgraded Cryptography from 46.0 to 48.0
  - Upgraded MyPy from 1.20 to 2.1
  - Upgraded Ruff from 0.15.10 to 0.15.16
  - Upgraded Poetry requirement from 2.1 to 2.4
  - Upgraded other dependencies: platformdirs (4.9→4.10), pre-commit (4.5→4.6), poetry-core (2.3→2.4)

- Fixed
  - Various fixes related to Typer migration

## 2.6.0 - 2026-04-09

- Added
  - N/A

- Changed
  - Simpler/better Timer() class/decorator
  - No more "unnecessary" call-by-name limitations in most public methods (ex: `def Foo(a, /)`)

- Fixed
  - Clean /dist in integration test runs (2.5.1)
  - Better JSON definitions

## 2.5.0 - 2026-04-03

- Added
  - safetrans

## 2.0.0 - 2026-01-30

- Added
  - small custom statistical implementation

- Changed
  - Major restructure in how modules are organized
    - Mostly backward incompatible, thus a major version
  - Does **not** depend anymore on **scipy** and **numpy**, and this means install is 150Mb smaller

- Fixed
  - Many small fixes

## 1.7.0 - 2026-01-26

- Added
  - Created this CHANGELOG.

- Changed
  - CLI now using **Typer**.
    - Some flags and options had to be changed.
  - **Rich** terminal text.

- Fixed
  - Minor documentation
  - Bugs
