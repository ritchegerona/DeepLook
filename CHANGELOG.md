# Changelog

All notable changes to **DeepLook** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **AI analysis** — wired the existing `AIEngine` into a `deeplook ai` command
  (`summarize`, `pivot`, `report`, `query`) and an **AI** GUI page. Degrades
  gracefully with a clear message when no API key is configured.
- **Recursive pivot engine** (`deeplook pivot`) — cycle-safe breadth-first entity
  expansion with `--depth` and `--max-entities` controls.
- **MITRE ATT&CK mapping** (`deeplook attack`) — maps workspace activity to 34
  Reconnaissance / Resource Development techniques, with `--annotate` and JSON
  output; added a dedicated `ATT&CK` sheet to Excel exports.
- **IOC ingestion** (`deeplook ingest`) — parses plain text, CSV, STIX 2.x, and
  MISP feeds with automatic format detection, defang/refang, deduplication, tags,
  and ingestion provenance.
- **Indicator watchlist** (`deeplook watch`) — persistent watchlist with
  add/list/remove/check and change detection (snapshot diffing).
- **GUI pages** — Pivot, ATT&CK, Ingest, Watchlist, and AI pages for full CLI
  parity.
- **Monitoring reports** — new `Watchlist` and `Ingestion` Excel sheets and a
  `monitoring` report template; the Summary sheet now counts watched and
  ingested indicators, and full/technical exports include the new sheets.
- **Test suite** — expanded from 52 to 99 tests, including CLI smoke tests via
  Typer's `CliRunner`.
- **Automation** — GitHub Actions CI (lint, format check, tests with a coverage
  gate) and `pytest-cov` coverage configuration.

### Fixed

- `.gitignore` no longer excludes the `deeplook/output/` package (pattern
  narrowed to `/output/` and `/reports/`).
- Lint cleanup in `deeplook/output/security_report.py` (unused imports, f-string,
  unused variable).

### Documentation

- Expanded README, `docs/USAGE.md`, and `docs/CTIA.md` to cover the new commands,
  ATT&CK mapping, and the CTIA lifecycle alignment.

## [1.0.0]

### Added

- Initial terminal OSINT & threat-intelligence framework: 38 reconnaissance and
  security plugins (domain, IP, email, username, phone, hash, BTC, website, and
  security-assessment suites), SQLite-backed workspaces, entity/edge graph with
  ASCII and geo rendering, correlation, STIX/CSV/JSON/Excel export, security
  scoring, and a full Streamlit GUI dashboard.

[Unreleased]: https://github.com/ritchegerona/DeepLook/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ritchegerona/DeepLook/releases/tag/v1.0.0
