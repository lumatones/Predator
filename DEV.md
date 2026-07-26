# Predator — Development Guide

## 📦 Architecture

```
Predator/
├── electron/          # Electron main process (Node.js) — 20 файлов
│   ├── main.ts        # App entry, IPC handlers, auto-updater
│   ├── config.ts      # API config, CFG paths, theme, language
│   ├── constants.ts   # Cheat names, keywords, scan paths
│   ├── cloud-sync.ts  # Cloud hash sync (fetchCheatHashes, start/stop)
│   ├── scanner.ts     # Core scan orchestrator + IPC handlers
│   ├── types.ts       # Types, ScanContext, parsePsJson, utilities
│   ├── heuristic.ts   # Heuristic analysis: PE, entropy, signatures
│   ├── cheat-rules.ts # YARA-like rules, PE analysis, whitelist
│   ├── cheats-db.ts   # Known cheat signatures, hashes, paths
│   ├── auto-yara.ts   # Self-learning rule engine
│   ├── memory-dump.ts # MiniDumpWriteDump + string analysis
│   ├── api-hashing.ts # API Hashing / PEB walking detection
│   ├── etw-amsi-patch.ts  # AMSI/ETW tampering detection
│   ├── rwx-scanner.ts     # RWX memory regions + thread analysis
│   ├── disk-vs-memory.ts  # Inline hook detection (disk vs memory)
│   ├── behavior-profile.ts  # Process behavior profiling
│   ├── browser-history.ts   # SQLite browser history parser
│   ├── system-info.ts     # System dashboard data
│   ├── preload.ts         # Context bridge
│   ├── modes/         # Scan modes (7 files)
│   │   ├── browser.ts, dma.ts, files.ts, games.ts
│   │   ├── network.ts, processes.ts, registry.ts
│   └── __tests__/     # Unit tests
│       └── heuristic.test.ts
├── src/               # Renderer process (React + Vite)
│   ├── pages/         # UI pages (Checker, Dashboard)
│   ├── components/    # ErrorBoundary, ServerStatus
│   ├── icons/         # 14 SVG icons
│   └── utils/         # Report export
├── admin/             # Admin panel (React + Vite, separate)
├── server/            # Backend API (Express + MySQL + Socket.IO)
├── resources/         # Icons, installer assets
├── scripts/           # Build/release helpers (release.js, etc.)
└── release/           # electron-builder output
```

## 🚀 Quick Start

### Prerequisites
- Node.js 22+
- npm 10+

### Install
```bash
git clone https://github.com/lumatones/Predator.git
cd Predator
npm install
```

### Development
```bash
# Frontend + Electron main process (hot reload)
npm run dev

# Admin panel (separate terminal)
cd admin && npm run dev

# Server (separate terminal)
cd server && npm run dev
```

### Build
```bash
# Typecheck all projects
npm run typecheck

# Build frontend + electron
npm run build

# Package for Windows (portable .exe)
npm run electron:build:win
```

## 🔍 TypeScript

Three separate `tsconfig.json` files:

| Config | Scope | Check command |
|--------|-------|---------------|
| `tsconfig.json` | `src/` (renderer) | `npm run typecheck` |
| `tsconfig.electron.json` | `electron/` (main) | `npm run typecheck:electron` |
| `admin/tsconfig.json` | `admin/` (admin panel) | `cd admin && npx tsc --noEmit` |

Typecheck is also run automatically before `npm run build` via the `prebuild` script.

## 🧪 Testing

**Vitest** настроен для unit-тестов.

```bash
# Запуск тестов
npx vitest run

# Watch mode
npx vitest
```

Текущие тесты:
- `electron/__tests__/heuristic.test.ts` — тесты эвристического анализа

Для добавления новых тестов:
- **Unit tests**: Vitest (уже настроен в `vitest.config.ts`)
- **Electron tests**: Playwright + electron (spectron alternative)
- **Integration**: Manual via dev server (`npm run dev`)

## 📦 Release

### Автоматический релиз (единый скрипт):
```bash
npm run release
```
Скрипт делает всё автоматически:
1. Typecheck (Electron)
2. Clean + Build .exe
3. Generate latest.yml (SHA512 checksum)
4. GitHub Release (create or update) + Upload assets

Требуется `GITHUB_TOKEN` в `.env` файле.

### Ручной релиз (по шагам):
```bash
# 1. Bump version в package.json

# 2. Build
npm run electron:build:win

# 3. Upload
node scripts/upload-release.js

# 4. Git
git add -A && git commit -m "vX.Y.Z — description"
git tag vX.Y.Z && git push origin main --tags
```

### CI авто-релиз:
Push тега `v*` → GitHub Actions (`release.yml`) соберёт и опубликует .exe автоматически:
```bash
git tag v0.1.0 && git push origin v0.1.0
```

## 🧹 Code Style

- **Indentation**: 2 spaces (enforced by `.editorconfig`)
- **TypeScript**: Strict mode, no `any` when possible
- **Naming**: camelCase for vars/functions, PascalCase for types/interfaces
- **Imports**: Grouped (external → internal), alphabetized
- **Error handling**: Always wrap `execSync` in try-catch, prefer `await` for async

## 🛠️ Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start Vite dev server |
| `npm run build` | Typecheck + build (frontend + electron) |
| `npm run typecheck` | Typecheck both `src/` and `electron/` |
| `npm run typecheck:electron` | Typecheck only `electron/` |
| `npm run lint` | Check formatting with Prettier |
| `npm run clean` | Remove all build artifacts |
| `npm run electron:build` | Full build + electron-builder |
| `npm run electron:build:win` | Build + Windows portable .exe |
