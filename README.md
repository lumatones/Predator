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

**Version**: 0.4.0 | **Stack**: Electron 33 + React 19 + TypeScript 5.7 + Vite 6

Full ecosystem: Desktop App → API Server → Admin Panel.

Documentation: [CHANGELOG](docs/CHANGELOG.md) | [DEV](docs/DEV.md) | [RULES](docs/RULES.md) | [ROADMAP](docs/ROADMAP.md)

---

## v0.4.0 — What's New

> **Massive update:** 43 tasks completed across 7 phases. 28 files created/modified (~8,400 lines). 243 tests (up from 165). 10 security risks fixed.

### 🛡️ Anti-Debug & Self-Protection (Phase 5)

| Module | What it does |
|--------|-------------|
| **Anti-Debug 7 tiers** | RE tools detection → DLL imports → **Hardware Breakpoints** (Dr0–Dr3) → **ProcessDebugPort** → **PEB scan** (IsWow64Process x32/x64) → Parent process → **QPC timing** (μs precision) |
| **Self-Integrity** | SHA256 .exe baseline, **INT3 patch scan** (PE parser — only `.text`), IAT DLL proxy detection, version-seed anti-tampering |
| **Self-Protect** | **ACL hardening** (Deny ACE for Everyone: VM_READ\|WRITE\|OP, Allow ACE for owner), **BreakOnTermination** (disabled in DEV), **SeDebugPrivilege** removal, DLL injection snapshot (node_modules excluded) |

### 🎮 Game-Specific Detectors (Phase 3)

| Module | What it detects |
|--------|----------------|
| **Game Memory** | ReadProcessMemory hooks, CEF debug ports, aimbot patterns (bone ESP tracking), internal overlay detection |
| **Network Intel** | Suspicious DNS (no-ip, duckdns), C2 patterns, unusual outbound connections, proxy/VPN detection via system proxy + adapter check |
| **USB Anomaly** | Bandwidth spikes (>100MB/s), FPGA behavior models (DMA attack patterns), re-enumeration timing attacks, unexpected descriptor changes |

### 🧠 Behavior & Risk Engine (Phase 4)

| Module | What it does |
|--------|-------------|
| **Behavior Engine** | Cross-process correlation: thread-injection pairs, memory-access clusters, attack chains (mapped→hollowed→network) |
| **Risk Scorer** | **25 weighted signal categories** (0.1–0.95 weight), log-scale accumulation, evidence-based escalation, device fingerprint tracking |
| **Persistent Profiles** | Cross-session risk escalation, consistency scoring (CV), trend detection, behavioral fingerprint |

### 🔍 Signature Intelligence (Phase 6)

| Module | Upgrade |
|--------|---------|
| **Fuzzy Hash v2** | **Persistent TLSH DB** (`.predator_tlsh_db.json`), **prefix trie** (O(1) rejection for 99%+ queries), size-aware thresholds (tiny=15, small=22, medium=30, large=35) |
| **Auto-YARA v2** | In-memory cache (60s TTL), **Unicode/UTF-16LE** extraction (.NET cheats), rule sharding, **confidence decay** (14-day idle), YARA 4.x export |
| **Signature Effectiveness** | Hit counters in matchKeywords/matchPatterns, getTopKeywords/Patterns, pruneColdSignatures, effectiveness reports |

### 🏗️ Scan Infrastructure (Phase 2)

| Module | What it does |
|--------|-------------|
| **Incremental Scan** | File-watch on game directories + registry audit — only re-scans changed files |
| **Scan Scheduler** | cron-like periodic scans (daily/weekly), idle-time detection |
| **Hot-Reload Signatures** | WebSocket push for instant signature updates without restart |

### 🖥️ Admin Dashboard Upgrades (Phase 1)

| Feature | Description |
|---------|-------------|
| **Hash Detail Modal** | Click any hash → full detail view: SHA256, risk bar, reviewer info, occurrence stats, copy-to-clipboard |
| **Session Timeout** | Auto-logout after 30min inactivity with countdown ring + urgency levels |
| **Keyboard Shortcuts** | `?` help modal, `Ctrl+K` command palette, `1-6` navigation, `A`/`R` approve/reject |
| **WebSocket Auth** | JWT-authenticated WS rooms for scanner + admin, auth error handling |

### 🔧 Server Hardening (Phase 1)

| Feature | Description |
|---------|-------------|
| **Drizzle ORM** | Type-safe schema migrations for MySQL |
| **RBAC Middleware** | Role-based access control (admin/operator/viewer) |
| **Rate-Limit Login** | 5 attempts / 15 min per IP, account lockout after 10 failures |
| **Request ID + Audit Log** | X-Request-ID propagation, structured audit logging |
| **Pagination Helper** | Unified cursor-based + offset pagination for all list endpoints |

---

## 📊 Metrics

| Metric | v0.3.3 | v0.4.0 |
|--------|--------|--------|
| Electron source files | 68 | **92** (+24) |
| Source lines | ~15,000 | **~18,700** (+3,700) |
| Test files | 6 | **9** (+3) |
| Tests | 165 | **243** (+78) |
| TypeScript errors | 0 | **0** |
| Scan phases (full scan) | 11 | **15** (+game memory, network intel, behavior, self-integrity) |
| Anti-debug tiers | 2 | **7** |
| Risk signal categories | 0 | **25** |
| Server endpoints | ~14 | **~22** |

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
| **Full Scan** | 15-phase deep scan: processes, heuristic file analysis, registry, prefetch, network, game integrity, AMSI/ETW, behavior, RWX memory, disk-vs-memory, DMA, browser history, **game memory**, **network intel**, **self-integrity** |
| **Quick Scan** | 6-phase fast check: processes, prefetch, registry, named pipes, network, browser history |
| **DMA Devices** | PCI hardware detection, drivers, USB-FPGA bridges, registry services, scheduled tasks |

### Full Scan Phases

1. **Self-integrity** — SHA256 .exe baseline, INT3 patch scan, IAT DLL proxy detection
2. **Process scanning** — DLL modules, known cheat signatures, masquerading detection
3. **Heuristic file analysis** — Shannon entropy, YARA rules, PE header inspection, section entropy, digital signatures, fuzzy hashing (TLSH), API hashing
4. **Registry deep scan** — Run/RunOnce, Services, Winlogon, 9 threat categories
5. **Prefetch analysis** — execution history by category
6. **System integration** — network connections, game integrity (FiveM/RAGE MP/ALT:V), masquerading processes, named pipes, WMI persistence, AMSI/ETW patch detection, behavior profiling, RWX memory scanning, disk-vs-memory comparison
7. **Game memory** — ReadProcessMemory hooks, CEF debug ports, aimbot/ESP patterns
8. **Network intel** — C2 patterns, proxy/VPN detection, suspicious DNS
9. **DMA detection** — PCI devices, firmware fingerprinting, USB anomaly detection
10. **Registry cheat scan** — 8 registry paths
11. **Browser history** — SQLite parser (Chrome, Edge, Firefox, Opera, Brave)
12. **Behavior analysis** — cross-process correlation, attack chain detection
13. **Anti-debug** — 7 tiers: RE tools, DLLs, HWBP, ProcessDebugPort, PEB, parent, QPC timing
14. **Anti-tamper** — Integrity verification, debugger detection
15. **Cloud submission** — SHA256 and TLSH hashes sent to backend

### Detection Engine

| Layer | Technique |
|-------|-----------|
| **Signatures** | 250+ cheat names, SHA256 hashes, TLSH fuzzy hashes (persistent DB + prefix trie), binary string patterns |
| **Heuristics** | Shannon entropy (packed/encrypted detection), PE header anomalies, section entropy, suspicious extension/name categories |
| **YARA** | 13 rules covering: injectors, debuggers, hooks, kernel drivers, spoofers, bypasses, overlays, network tools, obfuscators |
| **Auto-YARA** | Self-learning engine v2: Unicode/UTF-16LE extraction, TLSH clustering, Jaccard matching, confidence decay, YARA 4.x export, in-memory cache |
| **Signature Registry** | Single source of truth with hit counters, cold signature pruning, effectiveness reports |
| **Behavioral** | Cross-process correlation, attack chain detection, thread-injection pair analysis |
| **Risk Scorer** | 25 weighted signal categories, log-scale accumulation, evidence escalation, device fingerprint |
| **Cloud Sync** | Real-time WebSocket + HTTP polling, hot-reload signatures |
| **ScanPipeline** | Composable post-scan handler chain: session recording, shadow telemetry, auto-whitelist, hash submission, result upload |
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
| **Anti-Debug (7 tiers)** | RE tools (x64dbg, IDA, Ghidra, CheatEngine), HW breakpoints (Dr0-Dr3), ProcessDebugPort, PEB scan (x32/x64), QPC timing analysis |
| **Self-Protect** | ACL Deny ACE hardening, BreakOnTermination, SeDebugPrivilege removal, DLL injection monitoring |
| **Self-Integrity** | SHA256 .exe baseline, INT3 patch scan (.text only), IAT DLL proxy detection, version-seed anti-tampering |
| **Game Memory** | ReadProcessMemory hooks, CEF debug ports, aimbot bone-ESP patterns, internal overlay detection |
| **Network Intel** | C2 communication patterns, proxy/VPN detection, suspicious DNS (duckdns, no-ip) |
| **USB Anomaly** | Bandwidth spike detection, FPGA behavior modeling, re-enumeration attacks |
| **AMSI/ETW Patch** | Patched Windows security hooks (byte pattern search in process memory) |
| **Behavior Engine** | Cross-process correlation, thread-injection pairs, memory-access clusters, attack chain detection |
| **Risk Scorer** | 25 weighted categories, log-scale accumulation, device fingerprint, persistent escalation |
| **RWX Scanner** | Shellcode in Read-Write-Execute memory regions, thread start address anomalies |
| **Disk vs Memory** | Inline hooks — .text section differences between file on disk and memory |
| **ETW/WMI Monitor** | Kernel-level process creation events, image load from suspicious paths |
| **PCI Fingerprinting** | Generic bridge class codes masquerading as FPGA devices |
| **Persistent Scoring** | Cross-session cumulative risk tracking — catches "quiet" cheaters over time |

### After Scanning

- Search results by filename, path, or match description
- Filter by risk level: high, medium, low
- Export report as HTML (with charts), JSON, Markdown, PDF, or Telegram
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

Desktop App Internal:
  scanner.ts ──► ScanPipeline (5 handlers)
       │              ├── SessionRecorder
       │              ├── ShadowSubmitter
       │              ├── AutoWhitelister
       │              ├── HashSubmitter
       │              └── ResultUploader
       │
       ├──► Signature Registry (query API + hit counters + pruning)
       │       ├── SUSPICIOUS_CATEGORIES (9)
       │       ├── ALL_CHEAT_KEYWORDS (~200)
       │       └── SUSPICIOUS_PATTERNS (60 regex)
       │
       ├──► Behavior Engine (cross-process correlation, attack chains)
       ├──► Risk Scorer (25 signals, log-scale, device fingerprint)
       ├──► Anti-Debug (7 tiers) + Self-Protect + Self-Integrity
       ├──► Game Memory + Network Intel + USB Anomaly
       └──► Scan Scheduler (incremental + periodic)
```

- **Desktop App**: Electron 33 + React 19 + TypeScript. 92 source files, 15 scan phases, 7 anti-debug tiers
- **Backend**: Express 4 + MySQL 8 (Drizzle ORM) + Socket.IO + JWT + RBAC. 22+ endpoints, audit logging
- **Admin Panel**: React 18 + TypeScript + Recharts. 8 pages, WebSocket real-time, session timeout, keyboard shortcuts

---

## Updates

- Auto-check on startup (1.5 second delay)
- Background polling every 5 minutes
- Real-time WebSocket updates in admin panel
- Hot-reload signatures via WebSocket push
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
| POST | `/api/admin/login` | Admin login (rate-limited: 5/15min) |
| GET | `/api/admin/pending` | Pending requests (paginated) |
| POST | `/api/admin/approve/:id` | Approve request |
| POST | `/api/admin/reject/:id` | Reject request |
| POST | `/api/admin/tokens/generate` | Generate tokens (1-10) |
| GET | `/api/admin/tokens` | Token list |
| POST | `/api/admin/tokens/revoke/:id` | Revoke token |
| GET | `/api/admin/history` | Event history (paginated) |
| GET | `/api/admin/scan-stats` | Scan statistics |
| GET | `/api/admin/suspicious-hashes` | Hash database |
| GET | `/api/admin/safe-files` | Community whitelist |
| GET | `/api/v1/signatures` | Hot-reload signatures |

---

## Security

- Parameterized SQL queries throughout (Drizzle ORM)
- `token_id` validated against database before saving results
- Admin endpoints protected by JWT (24-hour expiry) + RBAC
- Rate limiting: general 100/min, auth write 10/min, login 5/15min
- Access tokens: 32-character hex (crypto.randomBytes)
- Passwords: bcrypt + salt
- Application self-protection: ACL Deny ACE, SeDebugPrivilege removal, DLL injection monitoring
- WebSocket JWT auth for scanner/admin rooms
- X-Request-ID propagation + structured audit logging

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
npx vitest run              # Unit tests (9 files, 243 tests)
npm run lint                # Code quality check
```

### Release

```bash
npm run release             # Full cycle: typecheck → build → latest.yml → GitHub Release
```

Requires `GITHUB_TOKEN` in `.env` file for release upload.

---

## License

All rights reserved. Unauthorized copying or distribution is prohibited.
