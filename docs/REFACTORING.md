# Refactoring Plan &mdash; Predator

> **Progress:** 17 of 19 tasks completed
> **Last updated:** 2026-08-01 (v0.4.5)

## Current Code Metrics

| Metric | v0.1.14 | v0.4.3 |
|--------|---------|--------|
| Files in electron/ | 20 | 41 (+ submodules) |
| Source lines (electron) | ~15,000 | ~18,700 |
| scanner.ts | ~1,500 lines | ~100 lines (pure orchestrator) |
| `any` usage count | ~5 | ~5 (unchanged) |
| Module-level mutable state | 0 | 0 |
| `require()` CJS-style | 0 | 0 |
| `execSync` in child_process | 161 calls | 0 (all migrated to `execPowerShell`/`execWithTimeout`) |
| Tests | 165 | 387 (283 Electron + 104 server) |
| TypeScript errors | 0 | 0 |
| Structured Evidence Model | — | Implemented (stable IDs, confidence, explanations, correlations) |
| Renderer contract tests | — | 4 tests + Chrome/CDP Checker smoke |
| Renderer smoke runtime | — | Node 22+ + installed Chrome |

---

## Priority 1 &mdash; scanner.ts (God Object)

### Problem
`electron/scanner.ts` was 2,735 lines, containing 41% of all electron/ code. After decomposition:
- Types moved to `types.ts`
- Scan mode functions extracted to `scanner/full-scan.ts`, `scanner/quick-scan.ts`, `scanner/cleaner-scan.ts`
- IPC handler logic extracted to `ipc-handlers-scan.ts`
- Cloud sync moved to `cloud-sync.ts`
- Telemetry moved to `telemetry-queue.ts`

### Status: Complete

The scanner.ts is now a thin orchestrator (~100 lines) that dispatches based on mode and runs the post-scan pipeline. All heavy logic lives in dedicated modules.

---

## Priority 2 &mdash; Global State (module-level mutables)

### Solution implemented
`ScanContext` class in `electron/types.ts` provides isolated state per scan session with caching for expensive operations (digital signatures, PE headers).

**Status:** Completed in v0.0.21

---

## Priority 3 &mdash; CJS require() to ESM import

### Solution implemented
All `require()` calls replaced with standard ESM `import` statements.

**Status:** Completed in v0.0.21

---

## Priority 4 &mdash; `any` TypeScript typing

### Solution implemented
- All `any[]` replaced with generic `parsePsJson<T>()`
- `ScanOptions` interface for scan options
- Typed parameters across all modules
- ~5 `any` remain in edge cases (cheat-rules.ts return types)

**Status:** 80% complete in v0.0.21

---

## Priority 5 &mdash; PowerShell JSON Parsing

### Solution implemented
`parsePsJson<T>()` in `electron/types.ts` handles single object vs array, empty output, and parse errors. Used across all modules.

**Status:** Completed in v0.0.21

---

## Priority 6 &mdash; Config Constants (CFG)

### Solution implemented
`CFG` object in `electron/config.ts` centralizes system paths. Backward-compatible aliases in `types.ts`.

**Status:** Completed in v0.0.21

---

## Priority 7 &mdash; HTTP Client

### Problem
Scattered `http.request()` calls for cloud hash submission and fetching.

### Solution
Extract into `api-client.ts` with async/await, unified error handling, and retry logic.

**Effort:** 1 hour &middot; **Risk:** Low

---

## Priority 8 &mdash; Magic Strings

### Problem
Hardcoded strings for game platforms, risk levels, scan modes, and result types throughout the codebase.

### Solution
Replace with const enums or union types for IDE autocomplete and type safety.

**Effort:** 30 minutes &middot; **Risk:** Medium

---

## Priority 9 &mdash; execSync Migration

### Problem
161 `execSync` calls in 20+ files using raw `child_process.execSync` with manual try/catch, inconsistent timeout handling, and no process cleanup on timeout.

### Solution
Created `electron/utils/exec.ts` with three safe wrappers:

- `execWithTimeout(cmd, opts)` for non-PowerShell commands (netstat, wmic, tasklist)
- `execPowerShell(script, opts)` for PowerShell commands with auto-escaping and `-NoProfile -Command` prefix
- `execFileWithTimeout(file, args, opts)` for binary execution

All wrappers provide built-in timeout with process kill, `windowsHide` default, and return `string | null` for explicit null handling.

### Migration plan

**Phase 1** (completed by scripts): 14 simple files with single-call patterns.

**Phase 2** (completed manually): 9 complex files with multi-line PowerShell C# scripts.

**Phase 3** (cleanup): Removed 7 temporary migration scripts from `scripts/`.

Files migrated (20 total):

| Category | Files |
|----------|-------|
| Helper functions | `forensic-traces.ts`, `anti-forensic.ts`, `pc-cleaner-detection.ts` |
| PowerShell C# scripts | `anti-tamper.ts`, `rwx-scanner.ts`, `memory-dump.ts`, `disk-vs-memory.ts`, `etw-provider.ts` |
| Scan modes | `modes/dma.ts`, `modes/byovd.ts`, `modes/anti-debug.ts`, `modes/games.ts`, `modes/registry.ts` |
| Engine | `behavior-engine.ts`, `heuristic/signature-batch.ts`, `scanner/full-scan.ts` |
| Special | `types.ts` (execCmd wrapper) |
| Already completed (git) | `behavior-profile.ts`, `modes/etw-amsi.ts`, `modes/game-memory.ts`, `modes/network.ts`, `modes/network-intel.ts`, `modes/process/behavioral.ts`, `modes/process/enumeration.ts`, `modes/process/pipes-wmi.ts`, `modes/usb/anomaly.ts`, `modes/usb/bandwidth.ts`, `modes/usb/classification.ts`, `modes/usb/descriptors.ts`, `persistent-profile.ts`, `scan-scheduler.ts`, `self-integrity.ts`, `self-protect.ts`, `system-info.ts`, `modes/apc/etw-trace.ts`, `heuristic.ts` |

**Status:** Completed in v0.4.3. 0 `execSync` imports in `electron/` (except `utils/exec.ts` itself).

---

## Priority 10 &mdash; Heuristic Decomposition

### Problem
`electron/heuristic.ts` was a 400+ line barrel file with inline constants, helper functions, and 6 categories of logic.

### Solution
Extracted into `electron/heuristic/` submodules:

| Module | Purpose |
|--------|---------|
| `constants.ts` | `SUSPICIOUS_EXTENSIONS`, `SCAN_CONFIG`, `PROTECTED_PATHS`, `SYSTEM_PROC_NAMES` |
| `name-matcher.ts` | `matchKnownCheat`, `riskScoreToLevel`, `getFileRiskLevel` |
| `combo-detector.ts` | `comboScoreUnsignedBinary` |
| `signature-batch.ts` | `batchCheckSignatures`, `checkDigitalSignature` |
| `masquerading.ts` | `checkMasqueradingExecutable` |
| `archive-scan.ts` | `scanArchiveContents`, `ARCHIVE_EXTS` |
| `cheat-names.ts` | `PROC_BASES`, `FILE_NAMES`, `LUA_NAMES`, `FOLDER_NAMES` |

`heuristic.ts` is now a thin barrel re-exporting from submodules and keeping only `heuristicFileScan()` and thin helpers (`isKnownElectronDll`, `isSkippableExtension`, `calculateFileHash`).

**Status:** Completed in v0.4.3.

---

## Priority 11 &mdash; Documentation Cleanup

### Completed
- `RULES.md` updated from v0.1.14 to v0.4.3 with current structure, API endpoints, and 9 threat categories
- `ARCHITECTURE.md` created with full system architecture, dependency graph, data flows, and security model
- `README.md` rewritten for GitHub with clean formatting and up-to-date metrics
- 7 obsolete migration scripts removed from `scripts/`

**Status:** Completed in v0.4.3.

---

## Priority 12 — Evidence Model & Explainable Risk

### Solution implemented
- Added optional structured evidence to `ScanResult` with source, category, weight, confidence, explanation, raw value, timestamp, and related finding IDs.
- Added stable `findingId` and deterministic evidence IDs, including duplicate findings and repeated rescoring.
- Restricted correlations to explicit detection-layer pairs with a shared meaningful token.
- Propagated `critical` through scanner, scheduler, filtering, grouping, UI, and exports; legacy server contracts normalize it to `high` at the boundary.
- Added bounded evidence payload validation and regression coverage.

**Status:** Completed in v0.4.5.

## Priority 13 — Renderer Smoke & Contract Tests

### Solution implemented
- Added a dedicated Vitest config for `src/__tests__` renderer contract tests.
- Covered JSON/HTML/Markdown report exports, structured evidence, Finding explanations, and critical/high grouping.
- Added a dev-only `?smoke=checker` harness with stable test IDs.
- Added dependency-free Chrome/CDP smoke runner for Checker → mock scan → result → Finding modal → HTML export.
- Added `npm run test:renderer` and `npm run test:renderer:smoke`; the latter requires Node 22+ and Chrome.

**Status:** Completed in v0.4.5.

## Summary

| # | Task | Effort | Status |
|---|------|--------|--------|
| 1 | ScanContext class | 1-2h | Completed |
| 2 | TypeScript `any` reduction | 2-3h | Completed (80%) |
| 3 | require() to import | 5min | Completed |
| 4 | PowerShell JSON utility | 30min | Completed |
| 5 | Config constants (CFG) | 20min | Completed |
| 6 | Constants extraction | 15min | Completed |
| 7 | Cloud sync module | 20min | Completed |
| 8 | ScanPipeline | 1h | Completed |
| 9 | Signature Registry | 1h | Completed |
| 10 | MASQUERADING_SYSTEM_TOOLS | 30min | Completed |
| 11 | execSync migration | 3h | Completed |
| 12 | Heuristic decomposition | 1h | Completed |
| 13 | Documentation cleanup | 1h | Completed |
| 14 | RULES.md update | 30min | Completed |
| 15 | ARCHITECTURE.md creation | 1h | Completed |
| 16 | README.md rewrite | 30min | Completed |
| 17 | Evidence Model & explainable risk | 3-4h | Completed |
| &mdash; | HTTP client | 1h | Planned |
| &mdash; | Enum for types | 30min | Planned |
