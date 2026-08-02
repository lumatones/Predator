# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.2] — 2026-08-02

### Added

- **Binary Triage** — static PE/TLS/API/packing analysis without execution. Select a binary via file dialog, get entropy, imports classification, compile timestamp, TLS callbacks, signature status, and risk indicators.
- **Results Screen v2** — filter chips (risk/type/source), quick search, threat grouping. Replaced monolithic result rendering with a deep `ResultsView` module.
- **Harden scan trust flow** — inconclusive scans are marked distinctly, diagnostics displayed in results, website updated.
- **Docker containerization** — multi-service docker-compose: MySQL 8, Node.js server (non-root), nginx reverse proxy with admin/website SPAs, Socket.IO WebSocket proxy, healthchecks, named volumes. One command: `docker compose up -d`.
- **Auto-migration on startup** — `db-migrate` one-shot container applies drizzle SQL migrations via programmatic `migrate.ts`. Uses `__drizzle_migrations` tracking table, idempotent on restart.
- **HTTPS + certbot + self-signed fallback** — nginx entrypoint generates self-signed cert on first start, certbot obtains Let's Encrypt cert when DOMAIN is configured. HSTS, TLS 1.2/1.3, OCSP stapling.
- **Playwright E2E tests** — 15 browser tests: website hero + PlayersDB (10), admin login (5). Chromium, auto-start dev servers, HTML reporter.
- **GitHub Actions: Docker Release** — build & push `predator-server` + `predator-nginx` images to GHCR on push to main. Typecheck gates (server + admin + website) before Docker build. Layer caching via `gha` backend. Manual dispatch supported.
- **CHANGELOG.md** — Keep a Changelog format, versions 0.5.0 through 0.5.2.
- **`.env.docker`** — environment template for Docker deployment (`DB_HOST=mysql`, `DOMAIN=localhost`, `JWT_SECRET`, `MYSQL_ROOT_PASSWORD`).
- **`.dockerignore`** — excludes Electron, docs, tests, CI from Docker build context.

### Changed

- **Checker.tsx decomposed** — 713-line monolith split into `checker-config.tsx` (220 lines), `useCheckerScan` hook (190 lines), `useCheckerTabs` hook (50 lines). Checker.tsx now 348 lines of pure UI composition. Icon rendering simplified via `iconMap` + `renderTabIcon()`.
- **Signature check API refactored** — `checkDigitalSignatureStatus()` returns tri-state (`'valid' | 'unsigned' | 'unknown'`) instead of boolean. Boolean API preserved for backward compatibility.

### Fixed

- **FK column type mismatch** — 5 foreign key columns changed from `int()` to `bigint({ mode: 'number', unsigned: true })` to match `serial()` IDs. MySQL 8 enforces strict FK type matching. Migration `0003_hot_sleeper` added.
- **`admin_audit_log` FK constraint** — `admin_id` was `INT` referencing `admins.id` (`BIGINT UNSIGNED`), causing incompatible FK error in MySQL 8. Fixed in audit-log.ts + migration `0004_fix_audit_log_fk` (idempotent: handles fresh and existing DBs).
- **GitHub Actions cache miss** — `admin/package-lock.json` was missing from the repo, causing `cache-dependency-path` resolution failure in `docker-release.yml`.
- **Certbot "empty label" warning** — `DOMAIN` variable not resolved by Docker Compose. Fixed with `DOMAIN=localhost` defaults and `.env` → `.env.docker` copy for Compose interpolation.
- **Docker: port conflicts** — MySQL external port removed (communicates internally via Docker network), nginx moved to 8080 (host Apache occupies 80).
- **Docker: `npx` cache crash** — `db-migrate` used `npx drizzle-kit migrate` which failed silently as non-root user with no home directory. Replaced with programmatic migrator.
- **Docker: Socket.IO proxying** — added dedicated `/socket.io/` nginx location with WebSocket upgrade headers. Admin panel real-time updates now work through the reverse proxy.
- **Playwright test runner** — fixed port conflict (Windows/Hyper-V reserves 3000), IPv4/IPv6 binding, vitest file collision, and API-unavailable resilience. All 15 e2e tests pass in 6s.
- **Music player in EXE builds** — `webSecurity: false` in BrowserWindow to bypass CORS/Same-Origin Policy for `file://` protocol. `fetch()` to iTunes, Jamendo, Invidious, and `Audio()` from Pixabay CDN now work in packaged app.

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

[unreleased]: https://github.com/lumatones/Predator/compare/v0.5.1...HEAD
[0.5.2]: https://github.com/lumatones/Predator/releases/tag/v0.5.2
[0.5.1]: https://github.com/lumatones/Predator/releases/tag/v0.5.1
[0.5.0]: https://github.com/lumatones/Predator/releases/tag/v0.5.0
