# Predator

**Anti-cheat scanner for GTA 5 RP — FiveM, RAGE MP, ALT:V**

<p align="center">
  <a href="https://github.com/lumatones/Predator/releases/latest">
    <img src="https://img.shields.io/badge/Download_Predator-ff4444?style=for-the-badge&logo=windows&logoColor=white&labelColor=1a1a2e" alt="Download Predator">
  </a>
  <br>
  <a href="https://github.com/lumatones/Predator/releases">
    <img src="https://img.shields.io/github/v/release/lumatones/Predator?style=flat-square&label=Version&color=ff4444" alt="Version">
  </a>
  <a href="https://github.com/lumatones/Predator/releases">
    <img src="https://img.shields.io/github/downloads/lumatones/Predator/total?style=flat-square&label=Downloads&color=ff6b35" alt="Downloads">
  </a>
  <a href="https://github.com/lumatones/Predator/actions/workflows/release.yml">
    <img src="https://img.shields.io/github/workflow/status/lumatones/Predator/release.yml?style=flat-square&label=Build&color=3B82F6" alt="Build">
  </a>
</p>

Predator is a desktop application that scans a user's PC for traces of cheat software. It performs multi-layered analysis across files, processes, registry, network, DMA hardware, browser history, and game directories.

**Version**: 0.0.26 | **Stack**: Electron 33 + React 19 + TypeScript 5.7 + Vite 6

Full ecosystem: Desktop App -> API Server -> Admin Panel.

Documentation: [CHANGELOG](docs/CHANGELOG.md) | [DEV](docs/DEV.md) | [RULES](docs/RULES.md)

---

## Installation

1. Download the latest version from [Releases](https://github.com/lumatones/Predator/releases)
2. Run the downloaded `.exe` file
3. Auto-updater will notify you of new versions

> **System requirements:** Windows 10/11, 64-bit

---

## First Launch

On first launch, the app guides you through a short onboarding:

1. **Language** — Russian / English
2. **Theme** — choose from Predator Red, Ocean Blue, Stealth Black, or Nebula Purple
3. **Authorization** — enter your 32-character access token or request one

After authorization, the main screen offers:

- **Start Check** — open the scanner
- **Dashboard** — system monitor (CPU, RAM, temperature, processes)

---

## Scan Modes

| Mode | Description |
|------|-------------|
| **Full Scan** | 9-phase deep scan: processes, heuristic file analysis, registry, prefetch, network, game integrity, AMSI/ETW, behavior, RWX memory, disk-vs-memory, DMA, browser history |
| **Quick Scan** | 6-phase fast check: processes, prefetch, registry, named pipes, network, browser history |
| **DMA Devices** | PCI hardware detection, drivers, USB-FPGA bridges, registry services, scheduled tasks |

### Full Scan Phases

1. **Process scanning** — DLL modules, known cheat signatures, masquerading detection
2. **Heuristic file analysis** — Shannon entropy, 13 YARA rules, PE header inspection, section entropy, digital signatures, fuzzy hashing (TLSH), API hashing
3. **Registry deep scan** — Run/RunOnce, Services, Winlogon, 9 threat categories
4. **Prefetch analysis** — execution history by category
5. **System integration** — network connections, game integrity (FiveM/RAGE MP/ALT:V), masquerading processes, named pipes, WMI persistence, AMSI/ETW patch detection, behavior profiling, RWX memory scanning, disk-vs-memory comparison
6. **DMA detection** — PCI devices, firmware fingerprinting
7. **Registry cheat scan** — 8 registry paths
8. **Browser history** — SQLite parser (Chrome, Edge, Firefox, Opera, Brave)
9. **Cloud submission** — SHA256 and TLSH hashes sent to backend

### Detection Engine

| Layer | Technique |
|-------|-----------|
| **Signatures** | 250+ cheat names, SHA256 hashes, TLSH fuzzy hashes, binary string patterns |
| **Heuristics** | Shannon entropy (packed/encrypted detection), PE header anomalies, section entropy, suspicious extension/name categories |
| **YARA** | 13 rules covering: injectors, debuggers, hooks, kernel drivers, spoofers, bypasses, overlays, network tools, obfuscators |
| **Auto-YARA** | Self-learning engine: extracts strings from high-risk files, clusters by TLSH similarity, Jaccard distance matching, false positive correction |
| **Cloud Sync** | Real-time WebSocket + HTTP polling fallback for hash updates every 5 minutes |
| **Shadow Rules** | New signatures deployed in silent mode — collect telemetry without flagging users until validated |

### Platform Coverage

| Platform | Detection |
|----------|-----------|
| **FiveM** | Module whitelist (14 entries), mods/plugins directory scanning, game process identification |
| **RAGE MP** | Module whitelist (17 entries), CEF-based cheat detection, client_packages scanning, dinput8.dll detection |
| **ALT:V** | Module whitelist (14 entries), obfuscated module naming detection, compiled JS resource scanning, .NET assembly injection |

### Advanced Modules

| Module | What it detects |
|--------|----------------|
| **AMSI/ETW Patch** | Patched Windows security hooks (byte pattern search in process memory) |
| **Behavior Profile** | Suspicious handle patterns, unexpected parent processes, unsigned DLLs |
| **RWX Scanner** | Shellcode in Read-Write-Execute memory regions, thread start address anomalies |
| **Disk vs Memory** | Inline hooks — .text section differences between file on disk and memory |
| **ETW/WMI Monitor** | Kernel-level process creation events, image load from suspicious paths |
| **PCI Fingerprinting** | Generic bridge class codes masquerading as FPGA devices |
| **Persistent Scoring** | Cross-session cumulative risk tracking — catches "quiet" cheaters over time |

### After Scanning

- Search results by filename, path, or match description
- Filter by risk level: high, medium, low
- Export report as HTML (with charts) or JSON
- Results automatically submitted to backend

---

## System Architecture

```
Desktop App (Electron)       Backend API (Express)         Admin Panel (React)
        |                          |                            |
        |-- start-scan ----------->|                            |
        |                          |-- Socket.IO broadcast ---->|
        |-- submit-hashes -------->|                            |
        |-- fetch-hashes <--------|                            |
        |                          |                            |
        |                          |<-- JWT auth ---------------|
        |                          |-- pending/approve/reject ->|
```

- **Desktop App**: Electron 33 + React 19 + TypeScript. IPC bridge between scanner (Node.js) and UI (Vite/React)
- **Backend**: Express 4 + MySQL 8 + Socket.IO + JWT. Token management, scan results storage, hash cloud database
- **Admin Panel**: React 18 + TypeScript + Chart.js. Login, pending requests, token management, scan history, hash review

---

## Updates

- Auto-check on startup (1.5 second delay)
- Background polling every 5 minutes
- Real-time WebSocket updates in admin panel
- Pulsing red indicator in footer when update is available

---

## API Endpoints

### Public

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/token` | Validate 32-character token |
| POST | `/api/auth/token/use` | Activate token with PC name |
| POST | `/api/auth/request` | Create access request |
| GET | `/api/auth/status/:id` | Check request status |
| POST | `/api/auth/submit-scan` | Submit scan results |
| POST | `/api/auth/submit-hashes` | Submit suspicious file hashes |
| POST | `/api/auth/submit-shadow` | Submit shadow-mode telemetry |
| GET | `/api/auth/fetch-hashes` | Fetch latest cheat hashes |

### Admin (JWT required)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/admin/login` | Admin login |
| GET | `/api/admin/pending` | Pending requests |
| POST | `/api/admin/approve/:id` | Approve request |
| POST | `/api/admin/reject/:id` | Reject request |
| POST | `/api/admin/tokens/generate` | Generate tokens (1-10) |
| GET | `/api/admin/tokens` | Token list |
| POST | `/api/admin/tokens/revoke/:id` | Revoke token |
| GET | `/api/admin/history` | Event history |
| GET | `/api/admin/scan-stats` | Scan statistics |
| GET | `/api/admin/suspicious-hashes` | Hash database |

---

## Security

- Parameterized SQL queries throughout
- `token_id` validated against database before saving results
- Admin endpoints protected by JWT (24-hour expiry)
- Access tokens: 32-character hex (crypto.randomBytes)
- Passwords: bcrypt + salt
- Application runs in isolated Electron environment

---

## Development

```bash
# Desktop app
npm run dev                 # Vite dev server
npm run electron:dev        # Electron + Vite
npm run electron:build:win  # Build Windows .exe

# Backend
cd server && npm start

# Admin panel
cd admin && npm run dev
```

### Testing

```bash
npm run typecheck           # Full type check (electron + admin)
npm run typecheck:electron  # Electron only
npx vitest run              # Unit tests
npm run lint                # Code quality check
```

### Release

```bash
npm run release             # Full cycle: typecheck -> build -> latest.yml -> GitHub Release
```

Requires `GITHUB_TOKEN` in `.env` file for release upload.

---

## License

All rights reserved. Unauthorized copying or distribution is prohibited.
