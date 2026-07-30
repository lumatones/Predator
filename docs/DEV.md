# Predator &mdash; Developer Guide

> Version 0.4.3 &middot; Last updated 2026-07-30

## Project Structure

```
Predator/
├── electron/                # Electron main process (Node.js) - 41 files + submodules
│   ├── main.ts              # App entry, window, tray, auto-updater, crash log
│   ├── preload.ts           # contextBridge API (15 IPC channels)
│   ├── scanner.ts           # Scan orchestrator (~100 lines) + IPC handlers
│   ├── types.ts             # ScanContext, ScanResult, parsePsJson, execCmd
│   ├── config.ts            # API config, CFG paths, theme, language
│   ├── constants.ts         # Game paths, module lists, platform identifiers
│   ├── heuristic.ts         # Heuristic barrel (re-exports from submodules)
│   ├── heuristic/           # Decomposed heuristic modules (7 files)
│   │   ├── constants.ts     # SUSPICIOUS_EXTENSIONS, SCAN_CONFIG, PROTECTED_PATHS
│   │   ├── name-matcher.ts  # matchKnownCheat, riskScoreToLevel, getFileRiskLevel
│   │   ├── combo-detector.ts
│   │   ├── signature-batch.ts
│   │   ├── masquerading.ts
│   │   ├── archive-scan.ts
│   │   └── cheat-names.ts   # Pre-computed name arrays
│   ├── signature-registry.ts # 9 categories, 250+ keywords, 60+ patterns
│   ├── cheats-db.ts         # Known cheat process/file/lua/folder names
│   ├── cheat-rules.ts       # YARA rules (13), PE analysis, whitelist
│   ├── auto-yara.ts         # Self-learning YARA engine v2 (Unicode/TLSH/decay)
│   ├── fuzzy-hash.ts        # TLSH persistent DB with prefix trie
│   ├── risk-scorer.ts       # 25 weighted signal categories
│   ├── behavior-engine.ts   # Cross-process correlation, attack chains
│   ├── behavior-profile.ts  # Per-process behavior profiling
│   ├── scan-pipeline.ts     # 5 post-scan handlers (composable pipeline)
│   ├── scan-scheduler.ts    # Periodic + incremental scanning
│   ├── cloud-sync.ts        # HTTP polling + WebSocket hash sync
│   ├── telemetry-queue.ts   # Reliable result delivery queue
│   ├── safe-files-db.ts     # Community whitelist
│   ├── signature-watcher.ts # Hot-reload signal file watching
│   ├── result-grouper.ts    # Noise filtering + result grouping
│   ├── persistent-profile.ts # Cross-session risk escalation
│   ├── self-integrity.ts    # SHA256 baseline, INT3 scan, IAT proxy
│   ├── self-protect.ts      # ACL Deny ACE, SeDebugPrivilege removal
│   ├── anti-tamper.ts       # Anti-debug (7 tiers), VM detection
│   ├── anti-forensic.ts     # Log clearing, prefetch cleaning detection
│   ├── forensic-traces.ts   # Prefetch, Amcache, BAM, UserAssist, MuiCache
│   ├── pc-cleaner-detection.ts # USN journal, timestomping, ShellBags
│   ├── memory-dump.ts       # MiniDumpWriteDump + string analysis
│   ├── rwx-scanner.ts       # RWX regions + thread start address anomalies
│   ├── disk-vs-memory.ts    # Inline hook detection (disk vs memory .text)
│   ├── etw-provider.ts      # ETW kernel provider (process/thread events)
│   ├── etw-amsi-patch.ts    # AMSI/ETW tampering detection
│   ├── api-hashing.ts       # API Hashing / PEB walking detection
│   ├── browser-history.ts   # SQLite browser history parser (6 browsers)
│   ├── system-info.ts       # CPU/RAM/GPU dashboard data streaming
│   ├── native-hv-detect.ts  # Hypervisor detection via koffi FFI
│   ├── ipc-handlers.ts      # Config, PC name, tray IPC handlers
│   ├── ipc-handlers-scan.ts # Cancel scan handler
│   ├── analysis/            # Analysis utilities (entropy, strings)
│   ├── modes/               # Detection modes (14 files + submodules)
│   │   ├── anti-debug.ts, browser.ts, byovd.ts, dma.ts
│   │   ├── etw-amsi.ts, files.ts, game-memory.ts, games.ts
│   │   ├── network.ts, network-intel.ts, processes.ts, registry.ts
│   │   ├── usb-devices.ts, apc-detector.ts
│   │   ├── apc/             # APC injection submodules (7 files)
│   │   ├── process/         # Process submodules (3 files)
│   │   └── usb/             # USB submodules (4 files)
│   ├── scanner/             # Scan mode functions (full, quick, cleaner)
│   ├── utils/               # exec.ts (safe wrappers), safe-spread.ts
│   └── __tests__/           # 9 test files, 243 tests
│
├── src/                     # React renderer (Vite + React 19 + TS 5.7)
│   ├── main.tsx             # React entry point
│   ├── App.tsx              # Onboarding, auth, routing
│   ├── api.ts               # HTTP client with offline queue + retry
│   ├── pages/               # Checker.tsx, Dashboard.tsx
│   ├── components/          # ErrorBoundary, ServerStatus, ui/ (20+ components)
│   ├── hooks/               # useAuth, useScan, useThemeEngine, useMusicPlayer, etc.
│   ├── icons/               # 14 SVG icons with animations
│   ├── styles/              # CSS modules (checker, dashboard, layout, components)
│   ├── services/            # music-sources.ts
│   ├── utils/               # export-report, finding-explainer, result-grouper, webgl
│   └── types/               # electron.d.ts, music.ts
│
├── server/                  # Backend API (Express 4 + MySQL 8 + Drizzle ORM)
│   ├── package.json
│   └── src/
│       ├── index.ts         # Server entry, Socket.IO, graceful shutdown
│       ├── config/database.ts
│       ├── db/              # Drizzle ORM schema + migrations
│       ├── middleware/       # 7 middleware modules
│       ├── routes/          # auth.ts, admin.ts, v1.ts
│       ├── services/        # classifier.ts, tlsh-matcher.ts, cheat-knowledge.ts
│       ├── helpers/         # errors.ts, pagination.ts
│       └── __tests__/       # 5 test files
│
├── admin/                   # Admin panel (Vite + React 19 + TS)
│   ├── package.json
│   └── src/
│       ├── App.tsx, api.ts
│       ├── components/      # Layout, CommandPalette, HashDetailModal, etc.
│       ├── hooks/           # useSessionTimeout, useKeyboardShortcuts
│       └── pages/           # 8 pages (Login, Dashboard, Pending, Tokens, etc.)
│
├── scripts/                 # Release helpers
│   ├── release.js           # Full release cycle
│   ├── generate-latest-yml.js, upload-release.js
│   ├── generate-resources.js
│   ├── test-cheat-detect.ts, test-cheat-direct.mjs
│   └── monitor-cheat.ps1
│
├── docs/                    # Documentation
│   ├── ARCHITECTURE.md      # Full system architecture
│   ├── CHANGELOG.md         # Release history
│   ├── CONTEXT.md           # Domain glossary
│   ├── DEV.md               # This file
│   ├── REFACTORING.md       # Refactoring plan and progress
│   ├── ROADMAP.md           # Planned features
│   └── RULES.md             # Development rules
│
├── resources/               # Icons, installer assets
└── .github/workflows/       # CI (ci.yml) + auto-release (release.yml)
```

## Quick Start

### Prerequisites

- Node.js 22+
- npm 10+
- MySQL 8 (for server)
- Windows 10/11 (for Electron app)

### Setup

```bash
git clone https://github.com/lumatones/Predator.git
cd Predator

# Install all dependencies (root + workspaces)
npm install

# Setup server environment
cp server/.env.example server/.env
# Edit server/.env with your JWT_SECRET and DB credentials

# Initialize database
cd server && npm run db:init
```

### Development

```bash
# Desktop app - renderer only (Vite dev server)
npm run dev

# Desktop app - Electron + Vite (hot reload)
npm run electron:dev

# Server - watch mode (auto-restart on changes)
cd server && npm run dev

# Admin panel
cd admin && npm run dev
```

## TypeScript

Four separate tsconfig files, each checking a different component:

| Config | Scope | Command |
|--------|-------|---------|
| `tsconfig.json` | `src/` (renderer) | `npm run typecheck:renderer` |
| `tsconfig.electron.json` | `electron/` (main process) | `npm run typecheck:electron` |
| `admin/tsconfig.json` | `admin/` (admin panel) | `cd admin && npx tsc --noEmit` |
| `server/tsconfig.json` | `server/` (backend) | `cd server && npm run typecheck` |

Run all typecheck at once:

```bash
npm run typecheck
```

This is equivalent to running `typecheck:renderer`, `typecheck:electron`, and admin typecheck sequentially. Typecheck also runs automatically before `npm run build` via the `prebuild` hook.

## Testing

Vitest is configured for unit testing. Tests live in `electron/__tests__/`.

```bash
# Run all tests
npx vitest run

# Electron tests only
npx vitest run electron

# Watch mode
npx vitest

# Server tests
cd server && npx vitest run
```

Current test files (243 tests):

| File | Tests | Coverage |
|------|-------|----------|
| `heuristic.test.ts` | 24 | Core heuristic logic |
| `heuristic-extended.test.ts` | 35 | Extended edge cases |
| `heuristic-file-scan.test.ts` | 19 | File scan integration |
| `fuzzy-hash.test.ts` | ~30 | TLSH matching |
| `ipc-handlers.test.ts` | ~20 | IPC handler logic |
| `risk-scorer.test.ts` | ~30 | Risk scoring |
| `scan-pipeline.test.ts` | 21 | Pipeline execution |
| `signature-effectiveness.test.ts` | ~30 | Hit counters |
| `signature-registry.test.ts` | ~34 | Registry operations |

## Code Quality

### Pre-commit Hook

Husky runs before every commit:

```
lint-staged (eslint: electron + src, tsc: server + admin)
  ↓
Full typecheck (electron)
  ↓
Full typecheck (server)
```

### Linting

```bash
# Check code quality
npm run lint

# Auto-fix issues
npm run lint:fix

# Format code with Prettier
npm run format

# Check formatting
npm run format:check
```

### Style Guide

- **Indentation** - 2 spaces (enforced by `.editorconfig`)
- **TypeScript** - Strict mode, avoid `any`
- **Naming** - camelCase (variables/functions), PascalCase (types/interfaces)
- **Imports** - External first, internal second, alphabetized within groups
- **Error handling** - `execPowerShell`/`execWithTimeout` return `string | null`, always add `|| ''` before `.trim()` or `.split()`
- **Modules** - Prefer shallow modules (interface as simple as implementation)

## Building

```bash
# Typecheck everything first
npm run typecheck

# Build frontend + electron
npm run build

# Package for Windows (portable .exe)
npm run electron:build:win

# Clean all build artifacts
npm run clean

# Build everything (desktop + admin)
npm run build:all
```

## Release

### Automatic (recommended)

```bash
npm run release
```

This runs the full cycle:
1. Typecheck (electron)
2. Clean build artifacts
3. Build portable .exe
4. Generate `latest.yml` (SHA512 checksums)
5. Create/update GitHub Release + upload assets

Requires `GITHUB_TOKEN` in `.env`.

### CI Auto-Release

Push a version tag to trigger GitHub Actions:

```bash
git tag v0.4.3
git push origin v0.4.3
```

The `release.yml` workflow builds the `.exe` and publishes to GitHub Releases automatically.

## Server Setup

### Environment Variables

Create `server/.env`:

```env
PORT=3001
CLIENT_URL=http://localhost:5173,http://localhost:3000
JWT_SECRET=your-secret-here-at-least-32-chars

DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your-password
DB_NAME=predator

REQUEST_EXPIRY_MINUTES=30
```

### Database

```bash
cd server

# Push schema to MySQL (Drizzle ORM)
npm run db:push

# Generate migration files
npm run db:generate

# Run migrations
npm run db:migrate

# Open Drizzle Studio (visual DB browser)
npm run db:studio
```

### Server Commands

```bash
cd server

# Start (production)
npm start

# Dev mode with hot reload
npm run dev

# Typecheck
npm run typecheck

# Run tests
npm test
```

## Key Architecture Decisions

### execSync replaced with safe wrappers

All `child_process.execSync` calls have been migrated to `electron/utils/exec.ts`. Use these three wrappers:

- `execPowerShell(script, opts)` for PowerShell commands (handles escaping, `-NoProfile`, line collapsing)
- `execWithTimeout(cmd, opts)` for non-PowerShell commands (netstat, wmic, tasklist, reg query)
- `execFileWithTimeout(file, args, opts)` for binary execution

Both return `string | null`. Always handle the null case with `|| ''`.

### ScanContext for shared state

Global mutable state is centralized in `electron/types.ts` via the `ScanContext` class. A single `ctx` instance is shared across all scan modules. Call `ctx.resetScan()` before each new scan to clear dedup and create a new abort controller. Expensive caches (signatures, PE headers) persist between scans.

### Scan Pipeline

Post-scan side effects use a composable handler chain in `electron/scan-pipeline.ts`:
SessionRecorder &rarr; ShadowSubmitter &rarr; AutoWhitelister &rarr; HashSubmitter &rarr; ResultUploader

Each handler runs independently. One handler's failure does not block others.
