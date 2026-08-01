# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Binary Triage** — static PE/TLS/API/packing analysis without execution. Select a binary via file dialog, get entropy, imports classification, compile timestamp, TLS callbacks, signature status, and risk indicators.
- **Results Screen v2** — filter chips (risk/type/source), quick search, threat grouping. Replaced monolithic result rendering with a deep `ResultsView` module.
- **Harden scan trust flow** — inconclusive scans are marked distinctly, diagnostics displayed in results, website updated.
- **Docker containerization** — multi-service docker-compose: MySQL 8, Node.js server (non-root), nginx reverse proxy with admin/website SPAs, Socket.IO WebSocket proxy, healthchecks, named volumes. One command: `docker compose up -d`.
- **Auto-migration on startup** — `db-migrate` one-shot container applies drizzle SQL migrations via programmatic `migrate.ts`. Uses `__drizzle_migrations` tracking table, idempotent on restart.
- **GitHub Actions: Docker Release** — build & push `predator-server` + `predator-nginx` images to GHCR on push to main. Typecheck gates (server + admin + website) before Docker build. Layer caching via `gha` backend. Manual dispatch supported.
- **`.env.docker`** — environment template for Docker deployment (`DB_HOST=mysql`, `JWT_SECRET`, `MYSQL_ROOT_PASSWORD`).
- **`.dockerignore`** — excludes Electron, docs, tests, CI from Docker build context.

### Changed

- **Checker.tsx decomposed** — 713-line monolith split into `checker-config.tsx` (220 lines), `useCheckerScan` hook (190 lines), `useCheckerTabs` hook (50 lines). Checker.tsx now 348 lines of pure UI composition. Icon rendering simplified via `iconMap` + `renderTabIcon()`.
- **Signature check API refactored** — `checkDigitalSignatureStatus()` returns tri-state (`'valid' | 'unsigned' | 'unknown'`) instead of boolean. Boolean API preserved for backward compatibility.

### Fixed

- **FK column type mismatch** — 5 foreign key columns changed from `int()` to `bigint({ mode: 'number', unsigned: true })` to match `serial()` IDs. MySQL 8 enforces strict FK type matching. Migration `0003_hot_sleeper` added.
- **Docker: port conflicts** — MySQL external port removed (communicates internally via Docker network), nginx moved to 8080 (host Apache occupies 80).
- **Docker: `npx` cache crash** — `db-migrate` used `npx drizzle-kit migrate` which failed silently as non-root user with no home directory. Replaced with programmatic migrator.
- **Docker: Socket.IO proxying** — added dedicated `/socket.io/` nginx location with WebSocket upgrade headers. Admin panel real-time updates now work through the reverse proxy.

## [0.5.1] — 2026-07-29

### Added

- Onboarding: persist language & token across sessions
- Risk-scorer fixes and improvements

### Changed

- Removed demo scan from onboarding flow

## [0.5.0] — 2026-07-28

### Added

- Security: integrity baseline, server client-hashes, evidence model
- Website: sortable PlayersDB table columns

[unreleased]: https://github.com/Luma/Predator/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/Luma/Predator/releases/tag/v0.5.1
[0.5.0]: https://github.com/Luma/Predator/releases/tag/v0.5.0
