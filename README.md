<p align="center">
  <a href="https://github.com/lumatones/Predator/releases/latest">
    <img src="https://img.shields.io/badge/Download_Predator-ff4444?style=for-the-badge&logo=windows&logoColor=white&labelColor=1a1a2e" alt="Download Predator">
  </a>
</p>

<p align="center">
  <a href="https://github.com/lumatones/Predator/releases">
    <img src="https://img.shields.io/github/v/release/lumatones/Predator?style=flat-square&label=Version&color=ff4444" alt="Version">
  </a>
  <a href="https://github.com/lumatones/Predator/releases">
    <img src="https://img.shields.io/github/downloads/lumatones/Predator/total?style=flat-square&label=Downloads&color=ff6b35" alt="Downloads">
  </a>
  <a href="https://github.com/lumatones/Predator/actions/workflows/release.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/lumatones/Predator/release.yml?style=flat-square&label=Build&color=3B82F6" alt="Build">
  </a>
  <a href="https://github.com/lumatones/Predator/blob/main/LICENSE.txt">
    <img src="https://img.shields.io/badge/License-UNLICENSED-808080?style=flat-square" alt="License">
  </a>
</p>

---

Predator is a cross-platform desktop anti-cheat scanner for GTA 5 roleplay servers. It performs deep multi-layered analysis of files, processes, registry, network connections, DMA hardware, browser history, and game directories to detect cheat software on a player's PC. Built for FiveM, RAGE MP, and ALT:V communities.

**[Download Latest Release](https://github.com/lumatones/Predator/releases/latest)**

---

## Quick Start

1. Download the latest `.exe` from [Releases](https://github.com/lumatones/Predator/releases)
2. Run the installer (requires administrator privileges)
3. Follow the onboarding flow to set language, theme, and authorize with your access token
4. Choose a scan mode and start scanning

**System requirements:** Windows 10 or 11, 64-bit

---

## Scan Modes

Four scan modes cover different threat profiles

**Full Scan** - 15 phases covering every detection layer. Processes, heuristic file analysis, registry deep scan, prefetch history, network connections, game memory, DMA devices, browser history, behavior analysis, anti-debug, anti-tamper, and cloud submission. Recommended for thorough checks.

**Quick Scan** - 6 phases for fast verification. Processes, prefetch, registry, named pipes, network, and browser history. Completes in under 30 seconds.

**DMA Devices** - Hardware-focused scan. Detects PCI FPGA devices, USB-FPGA bridges, PCILeech ecosystem, and registry services commonly used with DMA cheat cards.

**PC Cleaner Detection** - Anti-forensic analysis. Detects USN journal tampering, timestomping, ShellBags wiping, HWID changes, and traces of cleaning tools like CCleaner or BleachBit.

## Detection Engine

Nine threat categories drive the signature engine

| Category | Risk | Targets |
|----------|------|---------|
| Injector | Critical | DLL injection, CreateRemoteThread, VirtualAllocEx |
| Debugger | Critical | x64dbg, Cheat Engine, IDA Pro, Ghidra |
| Hook | High | SetWindowsHookEx, DetourAttach, MinHook |
| Driver | Critical | Kernel drivers, IoCreateDevice |
| Spoofer | High | HWID spoofing, MAC address manipulation |
| Bypass | Critical | Anti-cheat evasion, security mechanism bypass |
| Menu | High | Game overlays, ImGui, Direct3D rendering hooks |
| Network | Medium | Proxy chains, VPNs, packet manipulation |
| Obfuscator | High | VMProtect, Themida, code packing |

Multiple detection layers work together

- **Signatures** - 250+ known cheat names, SHA256 hashes, TLSH fuzzy hashes with prefix trie indexing
- **Heuristics** - Shannon entropy analysis, YARA rules (13 rules), PE header inspection, digital signature verification
- **Behavioral** - Cross-process correlation, injection pair detection, attack chain reconstruction
- **Memory** - RWX region scanning, disk-vs-memory comparison, MiniDump analysis, thread start address anomalies
- **Anti-Debug** - 7-tier protection: RE tool detection, hardware breakpoints, ProcessDebugPort, PEB scan, QPC timing analysis
- **Risk Scorer** - 25 weighted signal categories with log-scale accumulation and cross-session persistence

## Architecture

Three components form the Predator ecosystem

```
Desktop App (Electron)      Backend API (Express)      Admin Panel (React)
       │                          │                         │
       │   start-scan            │                         │
       │────────────────────────►│                         │
       │                          │   Socket.IO             │
       │                          │────────────────────────►│
       │   submit hashes         │                         │
       │────────────────────────►│                         │
       │   fetch hashes          │                         │
       │◄────────────────────────│                         │
       │                          │   JWT auth              │
       │                          │◄────────────────────────│
       │                          │   approve/reject        │
       │                          │◄────────────────────────│
```

**Desktop App** - Electron 33 with React 19 frontend. 41 main-process modules, 15 scan phases, 243 tests. Runs with administrator privileges for deep system access.

**Backend API** - Express 4 server with MySQL 8 and Drizzle ORM. JWT authentication with RBAC roles, Socket.IO for real-time updates, Prometheus metrics, structured audit logging, and auto-classifier service.

**Admin Panel** - React 19 dashboard with WebSocket real-time notifications. Manage access requests, tokens, suspicious hashes, shadow findings, and community whitelist.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full module map and data flow diagrams.

## Development

```bash
# Install dependencies
npm install

# Desktop app (renderer only)
npm run dev

# Desktop app (Electron + Vite)
npm run electron:dev

# Backend server
cd server && npm run dev

# Admin panel
cd admin && npm run dev

# Type checking
npm run typecheck

# Run tests (243 tests)
npx vitest run

# Build Windows executable
npm run electron:build:win

# Full release cycle
npm run release
```

Requires `GITHUB_TOKEN` in `.env` for release uploads. See [DEV.md](docs/DEV.md) for detailed setup instructions.

## Documentation

| Document | Purpose |
|----------|---------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full system architecture, module map, data flows |
| [CHANGELOG.md](docs/CHANGELOG.md) | Version history and release notes |
| [DEV.md](docs/DEV.md) | Developer guide and setup instructions |
| [RULES.md](docs/RULES.md) | Development rules and domain glossary |
| [ROADMAP.md](docs/ROADMAP.md) | Planned features and milestones |

## Security

The application handles sensitive cheat detection data and implements multiple security layers

- Parameterized SQL queries throughout (Drizzle ORM)
- JWT authentication with 24-hour expiry and RBAC (admin, operator, viewer)
- Rate limiting at multiple levels (100/min general, 5/15min login, WebSocket connection limits)
- Access tokens generated as 32-character hex via crypto.randomBytes
- Admin passwords hashed with bcrypt and salt
- Application self-protection via ACL hardening, SeDebugPrivilege removal, and DLL injection monitoring
- X-Request-ID propagation and structured audit logging for traceability

## License

All rights reserved. Unauthorized copying or distribution is prohibited.
