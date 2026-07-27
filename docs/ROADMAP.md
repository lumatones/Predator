# Predator — Professional Development Plan

> **Version**: 1.0 | **Updated**: 2026-07-27 | **Current Product**: v0.1.14
> **Principle**: THINK FIRST → Research → Propose → Implement by stages
> **Role**: Senior Engineer (10+ yrs) + Security Analyst + Motion Designer + Researcher

---

## VISION

Transform Predator from a working prototype into a **professional anti-cheat ecosystem** — a product at the level of CrowdStrike/ESET for GTA 5 RP.

**4 Pillars:**
```
DESKTOP EXE ←→ SERVER API ←→ ADMIN DASHBOARD
                    ↕
              PUBLIC WEBSITE
```

---

## PILLAR 1: DESKTOP EXE APP (Electron + React + TypeScript)

**Current**: 40 TS (electron) + 51 TSX (src) files. Scanner engine is deep. Architecture: ScanPipeline + Signature Registry = clean.
**Goal**: Industrial-grade anti-cheat client. Flawless UI/UX. 20%+ test coverage. 99.9% crash-free.

### 1.1 SCANNER ENGINE (electron/)

**Current**: scanner.ts orchestrator (now ~300 lines after ScanPipeline extraction). 7 scan modes. heuristic.ts = scoring logic. cheats-db.ts = signatures. signature-registry.ts = central data.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No parallel file scanning (sequential walkDirAsync) | Full scan takes 5+ min on large drives | P0 |
| ALL_CHEAT_KEYWORDS has ~30% duplicates (DB arrays + hardcoded overlap) | Wasted CPU, redundant matching | P1 |
| matchKeywords() unused by heuristicFileScan (still iterates inline) | Inconsistent filtering, MIN_KEYWORD_LENGTH applied twice | P1 |
| No scan cancellation mid-flight | User stuck waiting | P1 |
| PowerShell commands have no timeout recovery | Hangs on locked files | P1 |
| No incremental scan (re-scan everything every time) | Wasted time on already-analyzed files | P2 |
| No scan scheduler (manual trigger only) | Can't run background periodic scans | P2 |

**Improvements**:
```
v0.1.15: Parallel file scanning (worker_threads pool, 4-8 workers)
v0.1.16: Deduplicate ALL_CHEAT_KEYWORDS with Set
v0.1.17: Migrate heuristicFileScan to use matchKeywords() + matchPatterns()
v0.1.18: Scan cancellation via AbortController
v0.1.19: PowerShell executor with timeout + retry + CircuitBreaker
v0.2.0:  Incremental scan (file hash cache, skip unchanged)
v0.2.1:  Scan scheduler (cron-like: every 6h, on boot, on game launch)
```

**Success criteria**:
- Full scan time reduced by 40% (parallel workers)
- 0 duplicate keyword matches
- Scan cancellation within 2 seconds
- 0 PowerShell timeout hangs

### 1.2 DETECTION DATABASE (cheats-db.ts + signature-registry.ts)

**Current**: 730-line flat data file. 250+ process names. 100+ file hashes. 150+ binary signatures. 58 regex patterns. 9 categories. Query API (matchKeywords, matchPatterns, getCategory).

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No versioning for signature data | Can't rollback bad signatures | P1 |
| No community contribution pipeline | New cheats require code PR | P1 |
| Hot-reload not implemented | Requires app restart to update signatures | P2 |
| No signature effectiveness metrics | Don't know which sigs actually catch cheats | P2 |
| Binary signatures lack context (why each was added) | Hard to maintain, risk of FPs | P2 |

**Improvements**:
```
v0.2.2: Signature versioning (sig-version.json, semantic version)
v0.2.3: Community JSON format (cheats.json → parsed at runtime)
v0.2.4: Hot-reload via cloud-sync (fetch signatures without restart)
v0.2.5: Telemetry: track which signatures fire (anonymized)
v0.3.0: Signature metadata: date_added, source, false_positive_rate
```

**Success criteria**:
- New cheat added in < 5 min (edit JSON, push, all clients get it)
- 0 app restarts for signature updates
- FP rate tracked and visible in admin panel

### 1.3 SCAN MODES (electron/modes/)

**Current**: 7 scan modes (files, processes, games, network, registry, browser, dma). Each ~100-300 lines.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No combined report (each mode reports separately) | User sees fragmented results | P1 |
| Game detection requires manual PID finding | Misses processes if GTA isn't running | P1 |
| Network scan is basic (netstat grep) | Missing: packet inspection, DNS tunneling | P2 |
| Browser history scan is slow (SQLite WASM parse all) | 10-30s per browser | P2 |
| DMA scan: no firmware fingerprint database | Relies on generic PCI class codes | P2 |

**Improvements**:
```
v0.2.6: Unified scan report (all modes → single risk assessment)
v0.2.7: Process tree detection (parent-child analysis)
v0.2.8: Enhanced network: DNS tunneling, known C2 IPs, bad ASNs
v0.2.9: Browser: incremental scan (only new history entries)
v0.3.0: DMA firmware DB: known cheat FPGA bitstreams
```

### 1.4 REACT UI (src/)

**Current**: 51 TSX files. App.tsx (400 lines, god component). Checker.tsx (scan UI). Dashboard.tsx (system monitor). 14 SVG icons. Glassmorphism + ParticleBackground + Framer Motion. 4 themes.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| App.tsx is a god component (10+ state vars, 15+ callbacks) | Any change risks breaking onboarding/theme/auth | P0 |
| Checker UI overflows on small screens (<1200px) | Buttons cut off, tabs hidden | P1 |
| No dark/light mode system (4 fixed themes) | Can't match OS preference | P2 |
| export-report.ts still has Unicode emoji (not SVG) | Brand inconsistency | P1 |
| No accessibility (ARIA labels, keyboard nav, screen reader) | Can't be used by visually impaired | P2 |
| No i18n framework (manual T object) | Hard to add new languages | P3 |
| No toast notification system for errors | Errors are silent | P1 |
| No confirmation dialogs before destructive actions | Accidental scan stop | P2 |

**Improvements**:
```
v0.1.15: Fix Checker UI overflow (responsive grid, flexible tabs)
v0.1.16: Replace emoji in export-report.ts with SVG icons
v0.1.17: Extract useOnboarding(), useThemeEngine(), useUpdateManager() from App.tsx
v0.1.18: Add ToastProvider for error/success notifications
v0.1.19: Add ConfirmDialog component for destructive actions
v0.2.0:  Auto-theme based on OS preference (match-media)
v0.2.1:  ARIA labels + keyboard navigation (Tab, Enter, Escape)
v0.3.0:  i18n framework (react-i18next) — add .json locale files
```

**Success criteria**:
- App.tsx < 150 lines (currently 400)
- Checker UI works on 1024x768 minimum
- All user-facing text in locale files (RU + EN)
- Tab-key navigable, screen-reader friendly

### 1.5 PERFORMANCE

**Current**: No profiling. 0 optimization work done beyond basic caching (sigCache, peHeaderCache).

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No startup time measurement | Unknown how long app takes to launch | P1 |
| No memory profiling | Possible leaks in long-running scans | P1 |
| No file I/O batching | Each file is fs.statSync + fs.openSync separately | P2 |
| No result virtualization (render all findings) | 500+ results = laggy scroll | P2 |
| No lazy loading for icons/components | Everything bundled upfront | P3 |

**Improvements**:
```
v0.2.5: Startup profiling (measure main process boot time)
v0.2.6: Memory profiling (heap snapshots, find leaks)
v0.2.7: File I/O batching (readdir + stat in one pass)
v0.2.8: Virtual scrolling for scan results (react-window)
v0.2.9: Code splitting (lazy load Dashboard, ThreatMap, Settings)
```

**Success criteria**:
- App startup < 3 seconds (cold)
- 0 memory growth after 10 consecutive scans
- 500-result list renders in < 50ms
- Bundle size reduced by 30% (code splitting)

### 1.6 TESTING

**Current**: 0.3% coverage. 1 test file (heuristic.test.ts, 3 tests).

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| 0 tests for scanner core (runFullScan, runQuickScan) | Any refactoring = risk of breaking | P0 |
| 0 tests for ScanPipeline handlers | Post-scan side effects untested | P0 |
| 0 tests for Signature Registry | Data integrity not verified | P1 |
| 0 tests for heuristicFileScan | Core scoring logic untested | P1 |
| 0 E2E tests | Can't verify user flows | P2 |
| 0 integration tests (IPC bridge) | Main↔Renderer broken silently | P2 |

**Improvements**:
```
v0.1.15: Unit tests for ScanPipeline (5 handlers, 3+ test cases each)
v0.1.16: Unit tests for Signature Registry (matchKeywords, matchPatterns, data integrity)
v0.1.17: Unit tests for heuristicFileScan (known inputs -> expected scores)
v0.1.18: Unit tests for scanner modes (mock file system + process list)
v0.1.19: Integration tests for IPC bridge (main <-> renderer round-trip)
v0.2.0:  E2E tests with Playwright (full scan flow, admin login, token auth)
v0.2.5:  Snapshot tests for UI components (prevent visual regressions)
v0.3.0:  CI pipeline: run all tests on PR (GitHub Actions)
```

**Success criteria**:
- Core scanner: 80%+ branch coverage
- ScanPipeline: 100% handler coverage
- Signature Registry: 100% data integrity tests
- E2E: 10+ user flows covered

### 1.7 SECURITY & ANTI-TAMPER

**Current**: Basic. app.asar integrity check via file size. No debugger detection. No VM detection. No process hollowing detection.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No debugger detection (Cheat Engine, x64dbg, IDA) | Cheats can attach to Predator process | P0 |
| No VM/sandbox detection | Cheat devs test their bypasses in VMs | P1 |
| No process hollowing detection | Cheats can inject into Predator | P1 |
| No code signing verification for our own .exe | Tampered binary runs silently | P1 |
| No encrypted config storage | API keys, tokens in plain JSON | P1 |
| No runtime integrity (check .text section hash) | In-memory patching undetected | P2 |

**Improvements**:
```
v0.1.20: Anti-debug: check IsDebuggerPresent, NtQueryInformationProcess, PEB.BeingDebugged
v0.1.21: VM detection: check registry (VBOX, VMware), MAC prefixes, hypervisor CPUID
v0.2.0:  Code signing: verify Authenticode signature of our own .exe on startup
v0.2.1:  Encrypted config store (AES-256-GCM, key derived from machine GUID)
v0.2.5:  Anti-DLL-injection: enumerate loaded modules, check signatures
v0.3.0:  Runtime integrity: CRC32 of .text section vs known good hash
```

**Success criteria**:
- Debugger detected within 500ms of attachment
- VM detected on startup (block scan in VM)
- 0 plain-text secrets in app.asar

---

## PILLAR 2: SERVER API (Node.js + Express -> TypeScript)

**Current**: 6 JS files (~800 lines total). Express + MySQL + Socket.IO + JWT. No TypeScript. No validation. No tests. No rate limiting. No API versioning.
**Goal**: Production-grade REST API. TypeScript-first. 85%+ test coverage. 100+ concurrent users. <100ms p95 latency.

### 2.1 MIGRATION TO TYPESCRIPT

**Current**: Plain JS (server/src/). No type safety. require() based. Magic strings everywhere.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No TypeScript | Runtime type errors in production | P0 |
| require() instead of ES imports | No tree-shaking, harder refactoring | P1 |
| No shared types with desktop app | Duplicated type definitions | P1 |
| Magic strings for DB columns, statuses, roles | Typos cause silent bugs | P1 |

**Improvements**:
```
v0.1.15: Migrate to TypeScript (ts-node -> tsx for dev, tsc for build)
v0.1.16: Create shared-types/ package (ScanResult, Token, Request, Hash)
v0.1.17: Replace magic strings with const enums (RequestStatus, HashStatus, AdminRole)
v0.1.18: Add tsconfig.json with strict: true, noImplicitAny
```

**Success criteria**:
- 0 `any` types in production code
- Shared types package imported by both server + desktop
- Compile-time errors for DB column typos

### 2.2 AUTH & SECURITY

**Current**: JWT with hardcoded fallback secret (fixed). Token validation skippable via pc_username (fixed). No rate limiting. CORS open (*). No request body validation.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| token_id still optional in submit-scan/submit-hashes (bypassed via pc_username only) | Need to verify against deployed code | P0 |
| No rate limiting | Brute-force login, token guessing, spam | P1 |
| CORS: origin '*' | Any website can call API | P1 |
| No request body validation (no Zod/Joi) | Malformed data hits DB, causes crashes | P1 |
| No API key rotation mechanism | Compromised key = permanent access | P2 |
| No audit log for admin actions | Can't trace who approved what | P2 |
| JWT in localStorage (not httpOnly cookie) | XSS can steal admin token | P2 |

**Improvements**:
```
v0.1.15: Verify token_id enforcement in submit-scan + submit-hashes
v0.1.16: Add express-rate-limit: 100 req/min general, 5 req/min auth
v0.1.17: CORS: explicit origin list (admin URL, desktop app origin)
v0.1.18: Zod schemas for ALL request bodies (7 endpoints)
v0.1.19: Helmet.js for security headers (CSP, HSTS, X-Frame-Options)
v0.2.0:  Admin audit log table (who did what, when, from which IP)
v0.2.5:  httpOnly cookie for admin JWT (instead of localStorage)
```

**Success criteria**:
- 0 unvalidated request bodies
- Rate limit: 429 on 6th auth attempt in 1 min
- CORS blocks requests from unauthorized origins
- All admin actions logged and queryable

### 2.3 DATABASE

**Current**: MySQL via mysql2. 5 tables (tokens, admins, requests, scan_results, suspicious_hashes). Index on suspicious_hashes.status only. No migrations system. Raw SQL strings.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No migration system (manual SQL init) | Schema drift between dev/prod | P0 |
| No connection pooling config | Default pool (10 connections) may not be enough | P1 |
| No query timeout config | Slow queries block connections | P1 |
| No slow query logging | Unknown which queries are bottlenecks | P2 |
| No read replicas | Single DB = single point of failure | P3 |
| No data archival (scan_results grow infinitely) | DB size grows ~1GB/month | P2 |

**Improvements**:
```
v0.1.20: Add knex.js or drizzle-orm for migrations + query builder
v0.1.21: Connection pool: min=5, max=50, acquireTimeout=10000
v0.1.22: Query timeout: 30s default, 10s for GET endpoints
v0.2.0:  Slow query log (>1s) to separate file
v0.2.5:  TTL on scan_results (DELETE WHERE created_at < NOW() - INTERVAL 90 DAY)
v0.3.0:  Read replica for analytics queries (optional)
```

### 2.4 API DESIGN

**Current**: Monolithic route files (auth.js = 10 endpoints in 1 file). No versioning. Inconsistent error responses. No pagination on list endpoints.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| Monolithic route files (auth.js, admin.js) | 300+ line files, hard to navigate | P1 |
| No API versioning (/api/v1/...) | Breaking changes affect all clients | P2 |
| Inconsistent error format (some {error}, some {message}) | Client-side error parsing fragile | P1 |
| No pagination on /tokens, /suspicious-hashes, /history | Large responses, slow loading | P2 |
| No request ID (X-Request-ID) | Can't trace errors across logs | P2 |

**Improvements**:
```
v0.1.23: Split auth.js: auth/token.js, auth/request.js, auth/scan.js, auth/hash.js
v0.1.24: Split admin.js: admin/login.js, admin/requests.js, admin/tokens.js, admin/hashes.js
v0.1.25: Standardized error format: { error: { code, message, requestId } }
v0.1.26: Add X-Request-ID middleware (uuid)
v0.2.0:  Pagination: { data, meta: { page, limit, total, hasMore } }
v0.3.0:  API versioning: mount /api/v1/*, deprecate /api/* gradually
```

### 2.5 WEBSOCKET

**Current**: Socket.IO on same port. admin room for real-time events. 6 event types. No auth on WS connection. No reconnection state sync.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No auth on WebSocket connection | Anyone can join admin room | P0 |
| No reconnection state sync | Admin misses events during disconnect | P1 |
| No heartbeat monitoring | Stale connections not cleaned | P2 |
| Events not typed (magic strings) | Typos in event names = silent failure | P2 |

**Improvements**:
```
v0.1.15: WS auth middleware (verify JWT on connection, reject if invalid)
v0.1.16: Event type enum (WsEvent enum: NEW_REQUEST, SCAN_RESULT, etc.)
v0.1.17: Reconnection sync: on reconnect, send missed events backlog (last 5 min)
v0.1.18: Heartbeat: ping every 25s, disconnect if no pong in 10s
```

### 2.6 SERVER TESTING

**Current**: 0 tests. No test framework configured.

**Improvements**:
```
v0.2.0:  vitest + supertest: integration tests for all endpoints
v0.2.1:  Test DB: separate test_database, seeded before each test suite
v0.2.2:  CI: run server tests on PR (GitHub Actions)
v0.2.5:  Coverage target: 80%+ lines, 70%+ branches
```

---

## PILLAR 3: ADMIN DASHBOARD (React + TypeScript)

**Current**: 34 TSX files. Login, Dashboard, Tokens, History pages. WebSocket real-time updates. Glassmorphism UI theme.
**Goal**: Professional admin panel. RBAC. Audit trail. Analytics dashboard. Bulk operations.

### 3.1 AUTH & ACCESS CONTROL

**Current**: Single admin role. JWT in localStorage. No session timeout. No role hierarchy.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| Single role (superadmin) | Can't give limited access to moderators | P1 |
| No session timeout | Token valid for 24h even if admin left | P1 |
| No failed login tracking | Brute force undetected | P2 |
| No 2FA option | Single factor = vulnerable | P3 |

**Improvements**:
```
v0.2.0:  RBAC: superadmin, admin, moderator roles (per-endpoint permissions)
v0.2.1:  Session timeout: auto-logout after 30min inactivity
v0.2.2:  Failed login tracking: lock account after 5 failures (15 min)
v0.3.0:  TOTP 2FA for superadmin accounts
```

### 3.2 REQUEST MANAGEMENT

**Current**: Pending requests list. Approve/reject buttons. No bulk actions. No filtering. No search.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No bulk approve/reject | 50+ pending = click 50 times | P1 |
| No search by pc_username | Can't find specific user | P1 |
| No date range filter | Can't see "today's requests" | P2 |
| No request notes (why rejected) | User gets no explanation | P2 |

**Improvements**:
```
v0.1.15: Bulk select + approve/reject (checkboxes + toolbar)
v0.1.16: Search bar (pc_username, fuzzy match)
v0.1.17: Date range filter (today, last 7d, last 30d, custom)
v0.1.18: Rejection reason dropdown (suspicious, spam, duplicate, other)
```

### 3.3 TOKEN MANAGEMENT

**Current**: Generate tokens (1-10). List tokens (50). Revoke. No search. No export. No usage stats.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No batch generation (generate 100 for event) | Manual clicking | P2 |
| No token usage analytics | Don't know which tokens are active | P1 |
| No CSV export for tokens | Can't share token list externally | P2 |
| No token expiration | Tokens valid forever after use | P2 |

**Improvements**:
```
v0.1.19: Token usage dashboard (active, used, revoked counts + chart)
v0.1.20: CSV export (all tokens, filtered)
v0.2.0:  Token expiration: auto-revoke after N days if unused
v0.2.5:  Batch generation: 50, 100, 500 with progress bar
```

### 3.4 HASH REVIEW WORKFLOW

**Current**: List pending hashes. Approve/reject individually. No diff view. No bulk actions. No hash lookup.

**Gaps**:
| Gap | Impact | Priority |
|-----|--------|----------|
| No bulk confirm/reject | 100+ pending hashes = tedious | P1 |
| No hash detail view (which PCs submitted, when) | Can't assess credibility | P1 |
| No VirusTotal integration | Can't verify hash against 70+ AV engines | P2 |
| No "similar hash" detection | Duplicate cheats get separate entries | P2 |

**Improvements**:
```
v0.2.1: Hash detail panel: first seen, last seen, PC count, related scans
v0.2.2: Bulk confirm/reject with checkboxes
v0.2.5: VirusTotal API lookup (GET /api/admin/hashes/:sha256/vt)
v0.3.0: Fuzzy hash matching (ssdeep) — detect hash variants
```

### 3.5 ANALYTICS & REPORTING

**Current**: Basic scan stats (total scans, by mode, by day). No player stats. No threat trends. No export.

**Improvements**:
```
v0.2.0:  Player leaderboard (most scanned, most detections)
v0.2.1:  Threat trend chart (detections over time, 30d/90d)
v0.2.2:  Geographic map (player locations by IP geolocation)
v0.2.5:  PDF report generation (weekly summary, exportable)
v0.3.0:  Custom dashboard builder (choose widgets, arrange)
```

### 3.6 ADMIN UI/UX

**Current**: Clean but basic. No dark/light toggle. No responsive mobile view. No keyboard shortcuts.

**Improvements**:
```
v0.1.15: Responsive sidebar (collapsible, mobile hamburger)
v0.1.16: Keyboard shortcuts (A=approve, R=reject, N=next, F=search)
v0.1.17: Toast notifications for all actions (approve/reject/generate)
v0.2.0:  Dark mode toggle (sync with OS preference)
v0.2.5:  Command palette (Ctrl+K: search tokens, requests, hashes)
```

---

## PILLAR 4: PUBLIC WEBSITE (Next.js + PostgreSQL)

**Current**: Not started. 0 files.
**Goal**: Public-facing website with verified player database, statistics, and download page. SEO-optimized. Community trust builder.

### 4.1 ARCHITECTURE

```
Server API (Express) —sync—> PostgreSQL (public DB)
                                    |
                              Next.js (SSR/ISR)
                              /players
                              /players/:id
                              /stats
                              /api/docs
                              /download
```

**Stack**:
- **Next.js 14+** (App Router) — SSR + ISR for SEO
- **Tailwind CSS** — consistent with desktop app theme
- **Prisma ORM** — type-safe DB queries
- **PostgreSQL** — separate from MySQL (operational DB)
- **Vercel** — hosting (free tier for start)

### 4.2 PAGES

| Page | Content | Data Source |
|------|---------|-------------|
| `/` | Landing: what is Predator, why use it, download CTA | Static + download count API |
| `/players` | Searchable player database (verified scans only) | PostgreSQL via Prisma |
| `/players/:id` | Player profile: scan history, stats, verification badge | PostgreSQL via Prisma |
| `/stats` | Public statistics: total scans, detections, top threats | PostgreSQL via Prisma |
| `/download` | Desktop app download (latest .exe from GitHub Releases) | GitHub Releases API |
| `/api/docs` | Public API docs (for community bots: Discord, Telegram) | Static MDX |
| `/blog` | Changelog, security research, cheat analysis (optional) | MDX files |

### 4.3 DATA SYNC (Server -> PostgreSQL)

**Current**: Server writes to MySQL only. No PostgreSQL.

**Improvements**:
```
v0.3.0: Create sync service: every 5 min, copy new/modified rows to PostgreSQL
v0.3.1: Initial data migration: all approved hashes + verified scans
v0.3.2: GDPR compliance: player opt-out, data deletion request form
v0.3.3: Rate limit public API: 60 req/min per IP
```

### 4.4 PLAYER DATABASE

**Features**:
- Search by Steam ID, FiveM license, Rockstar Social Club ID
- Verification badge: "Verified by Predator — 3 scans, 0 detections"
- Risk indicators: last scan date, detection count, scan frequency
- Privacy: players can opt out (remove from public DB)
- API: JSON endpoint for Discord bots (isPlayerVerified?id=xxx)

### 4.5 COMMUNITY FEATURES (v1.0+)

- Report a cheater (submit evidence, triggers re-scan request)
- Top servers leaderboard (most verified players)
- Integration guides (how to require Predator verification on your server)
- Whitelabel: server owners can embed verification widget

---

## TIMELINE

### Phase 1: Foundation (v0.1.15 → v0.2.0) — 2-3 weeks

**Desktop EXE**:
- [x] ScanPipeline refactoring (done)
- [x] Signature Registry (done)
- [x] MASQUERADING_SYSTEM_TOOLS (done)
- [ ] Fix Checker UI overflow (responsive)
- [ ] Replace emoji in export-report.ts
- [ ] Extract hooks from App.tsx (useOnboarding, useThemeEngine)
- [ ] ToastProvider + error notifications

**Server API**:
- [ ] Verify token_id enforcement
- [ ] Rate limiting (express-rate-limit)
- [ ] CORS whitelist
- [ ] Zod validation on all endpoints
- [ ] Migrate to TypeScript

**Admin Dashboard**:
- [ ] Bulk approve/reject requests
- [ ] Search + date filters
- [ ] Responsive sidebar
- [ ] Keyboard shortcuts

**Testing**:
- [ ] ScanPipeline handler tests
- [ ] Signature Registry tests
- [ ] heuristicFileScan tests

### Phase 2: Hardening (v0.2.0 → v0.3.0) — 4-6 weeks

**Desktop EXE**:
- [ ] Parallel file scanning (worker_threads)
- [ ] Scan cancellation (AbortController)
- [ ] Incremental scan (file hash cache)
- [ ] Anti-debug + VM detection
- [ ] App.tsx < 150 lines
- [ ] Auto-theme (match-media)

**Server API**:
- [ ] Split monolithic routes
- [ ] Pagination on all list endpoints
- [ ] Admin audit log
- [ ] WebSocket auth middleware
- [ ] Test DB + integration tests

**Admin Dashboard**:
- [ ] RBAC (superadmin, admin, moderator)
- [ ] Session timeout
- [ ] Token analytics dashboard
- [ ] Hash detail panel
- [ ] CSV export

### Phase 3: Scale (v0.3.0 → v0.5.0) — 2-3 months

**Desktop EXE**:
- [ ] Scan scheduler (periodic background scans)
- [ ] Hot-reload signatures from cloud
- [ ] Runtime integrity checks
- [ ] Virtual scrolling (react-window)
- [ ] Code splitting (lazy load modules)
- [ ] i18n (react-i18next, RU + EN)

**Server API**:
- [ ] API versioning (/api/v1/)
- [ ] Prometheus metrics
- [ ] Data archival (TTL on old scans)
- [ ] Connection pooling optimization

**Admin Dashboard**:
- [ ] VirusTotal integration
- [ ] PDF report generation
- [ ] Player leaderboard
- [ ] Threat trend charts
- [ ] Command palette (Ctrl+K)

### Phase 4: Ecosystem (v0.5.0 → v1.0.0) — 3-6 months

**New: PUBLIC WEBSITE**
- [ ] Next.js project setup + Tailwind + Prisma
- [ ] Landing page
- [ ] Player database (/players, /players/:id)
- [ ] Public statistics (/stats)
- [ ] Download page (/download)
- [ ] API docs (/api/docs)
- [ ] Data sync service (MySQL -> PostgreSQL)
- [ ] Community features (report, leaderboard, integration guides)

**Desktop EXE**:
- [ ] ML-based anomaly detection (supervised: known cheat patterns)
- [ ] Community signature contributions
- [ ] Discord Rich Presence integration
- [ ] 3D Threat Map (Three.js globe)

**Server API**:
- [ ] Webhook system (Discord, Telegram notifications)
- [ ] Multi-region deployment (EU + NA)
- [ ] Read replicas for analytics

---

## RISK REGISTER

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| False positives cause user distrust | Medium | High | FP tracking dashboard, easy appeal process |
| Cheat devs bypass detection | High | Medium | ML layer, behavioral detection, frequent signature updates |
| Server downtime during tournament season | Low | High | Offline mode, multi-region failover |
| GDPR/privacy complaint | Medium | Medium | Opt-out system, data minimization, encryption at rest |
| GitHub Actions CI flakiness (seen in v0.0.19) | Medium | Low | Retry with backoff, separate typecheck from build |
| Electron security vulnerability (CVE) | Low | High | Dependabot, electron update policy, CSP headers |
| DB performance degradation (scan_results growth) | Medium | Medium | TTL archival, index optimization, query monitoring |

---

## SUCCESS METRICS (v1.0.0)

| Metric | Current | Target v1.0.0 |
|--------|---------|---------------|
| Test coverage (desktop) | 0.3% | 20%+ |
| Test coverage (server) | 0% | 80%+ |
| Test coverage (admin) | 0% | 50%+ |
| App startup time | ~5s | <3s |
| Full scan time | 5-10 min | <3 min |
| False positive rate | Unknown | <2% (tracked) |
| Crash rate | Unknown | <0.1% (monitored) |
| API p95 latency | Unknown | <100ms |
| Concurrent users (API) | 10 | 100+ |
| Signature update time | Code PR (hours) | <5 min (JSON push) |
| New language add time | N/A | <1 day (locale JSON) |

---

*Plan maintained by the Predator team. Review and update every sprint.*
*Principle: THINK FIRST → Research → Propose → Implement by stages. Never skip analysis.*
