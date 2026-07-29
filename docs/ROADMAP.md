# Predator — Development Roadmap v4.0 (Final)

> **Версия документа:** 4.0 | **Обновлено:** 2026-07-29
> **Текущая версия продукта:** v0.4.0
> **Принцип:** THINK FIRST → Research → Propose → Implement by stages

---

## 📊 ФИНАЛЬНАЯ СВОДКА: ВСЕ ФАЗЫ 1-7

| Метрика | До (v0.3.3) | После (v0.4.0) | Δ |
|---------|-------------|-----------------|---|
| **Electron TS-файлов** | ~68 | **92** | +24 |
| **Новых файлов (Electron)** | — | **11** | +11 |
| **Модифицировано (Electron)** | — | **7** | +7 |
| **Новых файлов (Server)** | — | **5** | +5 |
| **Новых файлов (Admin)** | — | **5** | +5 |
| **Всего новых/изменённых файлов** | — | **28** | +28 |
| **Строк кода (новые Electron)** | — | **3,665** | — |
| **Строк кода (всего изменено)** | — | **~8,366** | — |
| **Тестовых файлов** | 6 | **9** | +3 |
| **Тестов (всего)** | 165 | **243** | +78 |
| **Фаз сканирования (full scan)** | 11 | **15** | +4 |
| **Anti-debug tiers** | 2 | **7** | +5 |
| **Protection layers** | 2 | **5** | +3 |
| **Signature weight categories** | 0 | **25** | +25 |
| **Auto-YARA features** | Basic | **v2 (6 improvements)** | — |
| **Fuzzy hash DB** | In-memory | **Persistent + Prefix Trie** | — |

---

## 📋 ДЕТАЛЬНЫЙ ОТЧЁТ ПО ФАЗАМ

### ФАЗА 1: УПРОЧНЕНИЕ — 27/27 ✅

| Группа | Задачи | Строк кода | Файлы |
|--------|--------|-----------|-------|
| **EXE (E1-E10)** | Декомпозиция + тесты + ErrorBoundary + IPC + scanner | ~600 | `heuristic/`, `scanner/`, `ErrorBoundary.tsx` |
| **Сервер (S1-S8)** | Drizzle миграции + пагинация + WS auth + audit log + X-Request-ID + error format + TTL + индексы | ~445 | `drizzle/`, `db/schema.ts`, `helpers/pagination.ts`, `middleware/ws-auth.ts` |
| **Админка (A1-A7)** | Hash detail modal + session timeout + keyboard shortcuts + поиск + блокировка + RBAC + login tracking | ~909 | `HashDetailModal.tsx`, `SessionTimeoutModal.tsx`, `KeyboardShortcutsHelp.tsx`, `useSessionTimeout.ts`, `useKeyboardShortcuts.ts`, `rate-limit-login.ts`, `roles.ts` |

### ФАЗА 2: ИНТЕЛЛЕКТ — 3/21 ✅ (приоритетная выборка)

| Задача | Файл | Строк |
|--------|------|-------|
| **E11**: Инкрементальный скан | `scanner/full-scan.ts` | +30 (hasFileChanged + markFileScanned) |
| **E12**: Scan scheduler | `scan-scheduler.ts` (NEW) | 147 |
| **E13**: Hot-reload сигнатур | `cloud-sync.ts` | +50 (fetchSignatures) |

### ФАЗА 3: GAME-SPECIFIC DETECTORS — 3/3 ✅

| Задача | Файл | Строк | Ключевые техники |
|--------|------|-------|-----------------|
| **E14**: Game memory scanner | `modes/game-memory.ts` (NEW) | 344 | ReadProcessMemory, 10 byte-паттернов (aimbot/ESP/overlay), CEF debug ports |
| **E15**: Network threat intel | `modes/network-intel.ts` (NEW) | 362 | Proxy/VPN detection (20 адаптеров), C2 blacklist (35 доменов + 4 IP range), firewall rule scan |
| **E16**: USB anomaly detection | `modes/usb/anomaly.ts` (NEW) | 304 | VID/PID spoofing, cloned serials (12 known), PCIe config space scan (Xilinx/Altera) |

### ФАЗА 4: BEHAVIOR & ML — 3/3 ✅

| Задача | Файл | Строк | Ключевые техники |
|--------|------|-------|-----------------|
| **E17**: Behavior engine | `behavior-engine.ts` (NEW) | 418 | Process tree (WMI), injector-victim пары, 3 attack chain паттерна |
| **E18**: ML risk scorer | `risk-scorer.ts` (NEW) | 295 | 25 signal categories (0.15-1.0), log-scale evidence, adaptive threshold, rescoreResults |
| **E19**: Persistent profiles | `persistent-profile.ts` | +130 | Device fingerprint (SHA256 HWID), threat actor profiles, cross-scan correlation |

### ФАЗА 5: ANTI-DEBUG & SELF-PROTECTION — 3/3 ✅

| Задача | Файл | Строк | Ключевые техники |
|--------|------|-------|-----------------|
| **E20**: Anti-debug hardening | `modes/anti-debug.ts` | 688 (расширен) | 7 tiers: RE tools → DLLs → HWBP (Dr0-Dr3) → ProcessDebugPort → PEB (IsWow64Process) → parent check → QPC timing |
| **E21**: Self-integrity | `self-integrity.ts` (NEW) | 451 | SHA256 .exe baseline, VirtualQuery code section, INT3 scan (.text only), IAT DLL proxy detection |
| **E22**: Self-protection | `self-protect.ts` (NEW) | 444 | ACL Deny ACE (InitializeAcl+AddAccessDeniedAce), PROTECT_FROM_CLOSE + BreakOnTermination, SeDebugPrivilege removal, DLL injection snapshot |

### ФАЗА 6: SIGNATURE & ML — 4/4 ✅

| Задача | Файл | Строк | Ключевые техники |
|--------|------|-------|-----------------|
| **E23**: TLSH persistence | `fuzzy-hash.ts` | 346 (v2) | Persistent DB (.predator_tlsh_db.json), prefix trie, size-aware thresholds |
| **E24**: Fast-path matching | `fuzzy-hash.ts` | — | O(1) rejection via prefix trie, size-aware threshold (tiny=15, small=22, medium=30, large=35) |
| **E25**: Auto-YARA v2 | `auto-yara.ts` | 492 (v2) | In-memory cache (60s TTL), Unicode/UTF-16LE extraction, rule sharding, confidence decay, YARA 4.x export |
| **E26**: Effectiveness tracking | `signature-registry.ts` | 534 (+120) | Hit counters in matchKeywords/matchPatterns, top-N, zero-hit detection, pruneColdSignatures, getEffectivenessReport |

### ФАЗА 7: ТЕСТЫ & ДОКУМЕНТАЦИЯ — 4/4 ✅

| Задача | Файл | Строк | Тестов |
|--------|------|-------|--------|
| Fuzzy hash tests | `__tests__/fuzzy-hash.test.ts` (NEW) | 306 | 20 |
| Risk scorer tests | `__tests__/risk-scorer.test.ts` (NEW) | 373 | 30 |
| Signature effectiveness tests | `__tests__/signature-effectiveness.test.ts` (NEW) | 221 | 17 |
| ROADMAP v4.0 | `docs/ROADMAP.md` | — | Полный апдейт |

---

## 📂 ПОЛНЫЙ ИНВЕНТАРЬ НОВЫХ ФАЙЛОВ

```
ELECTRON (11 новых файлов — 3,665 строк)
├── behavior-engine.ts              (418 строк) — E17: Cross-process behavioral correlation
├── risk-scorer.ts                  (295 строк) — E18: Weighted ML-inspired scoring
├── self-integrity.ts               (451 строк) — E21: SHA256 + .text + INT3 + IAT
├── self-protect.ts                 (444 строк) — E22: ACL + handles + privilege + DLL injection
├── scan-scheduler.ts               (147 строк) — E12: Background scan scheduler
├── modes/
│   ├── game-memory.ts              (344 строк) — E14: Game memory pattern scanner
│   ├── network-intel.ts            (362 строк) — E15: Network threat intelligence
│   └── usb/anomaly.ts              (304 строк) — E16: USB anomaly detection
└── __tests__/
    ├── fuzzy-hash.test.ts          (306 строк) — E23/E24: 20 тестов
    ├── risk-scorer.test.ts         (373 строк) — E18: 30 тестов
    └── signature-effectiveness.test.ts (221 строк) — E26: 17 тестов

ELECTRON (7 модифицированных файлов — 3,347 строк итого)
├── modes/anti-debug.ts             (688 строк) — E20: +5 tiers
├── anti-tamper.ts                  (551 строк) — E20: +hypervisor API overhead
├── fuzzy-hash.ts                   (346 строк) — E23/E24: v2 persistent + prefix trie
├── auto-yara.ts                    (492 строк) — E25: v2 cache + Unicode + decay + YARA 4.x
├── signature-registry.ts           (534 строк) — E26: +hit counters + pruning
├── scanner/full-scan.ts            (309 строк) — E11+E14+E15+E17+E21+E22 integration
└── persistent-profile.ts           (427 строк) — E19: +device fingerprint + threat actors

SERVER (5 новых файлов — 445 строк)
├── drizzle/                        — S1: Drizzle ORM миграции
├── src/db/schema.ts                (172 строк) — S1: Drizzle schema
├── src/db/index.ts                 (51 строк) — S1: DB инициализация
├── src/helpers/pagination.ts       (96 строк) — S2: Пагинация
├── src/middleware/
│   ├── rate-limit-login.ts         (78 строк) — A5: Brute-force защита
│   └── roles.ts                    (48 строк) — A6: RBAC (admin/superadmin/moderator)
└── src/__tests__/                  — +3 тестовых файла (admin, auth-extra, v1)

ADMIN (5 новых файлов — 909 строк)
├── src/components/
│   ├── HashDetailModal.tsx         (372 строк) — A1: Hash detail panel
│   ├── SessionTimeoutModal.tsx     (146 строк) — A2: Session timeout
│   └── KeyboardShortcutsHelp.tsx   (138 строк) — A3: Keyboard shortcuts
└── src/hooks/
    ├── useSessionTimeout.ts        (114 строк) — A2: Session timeout hook
    └── useKeyboardShortcuts.ts     (139 строк) — A3: Navigation shortcuts hook

ИТОГО: 28 новых/модифицированных файлов, ~8,366 строк кода
```

---

## 📈 МЕТРИКИ ДО/ПОСЛЕ

| Метрика | v0.3.3 (до) | v0.4.0 (после) |
|---------|-------------|-----------------|
| **Electron файлов** | ~68 | **92** |
| **Строк кода (Electron)** | ~15,000 | **~18,700** |
| **Тестовых файлов** | 6 | **9** |
| **Тестов** | 165 | **243** |
| **Full scan фаз** | 11 | **15** |
| **Anti-debug tiers** | 2 (RE tools, DLLs) | **7** (+HWBP, DebugPort, PEB, parent, timing) |
| **Protection layers** | 2 (anti-tamper, anti-debug) | **5** (+self-integrity, self-protect, ACL) |
| **Signal weight categories** | 0 | **25** |
| **Fuzzy hash DB** | Memory-only | **Persistent + Prefix Trie** |
| **Auto-YARA** | Basic (disk read per check) | **v2** (cache, Unicode, decay, YARA 4.x) |
| **Signature effectiveness** | Не отслеживалось | **Hit counters + pruning + report** |
| **Серверные миграции** | init.ts (сырой SQL) | **Drizzle ORM** |
| **Server auth** | JWT only | **JWT + RBAC + brute-force + audit log** |
| **Admin UI** | Базовый | **Hash modal + session timeout + shortcuts + поиск** |
| **TypeScript ошибок** | 0 | **0** |
| **Test pass rate** | 100% (165/165) | **100% (243/243)** |

---

## 🐛 ИСПРАВЛЕННЫЕ БАГИ (все фазы)

| # | Баг | Где | Исправление |
|---|-----|-----|------------|
| 1 | `hardenProcessAcl` был no-op (pDacl=null) | self-protect.ts | InitializeAcl + AddAccessDeniedAce с CreateWellKnownSid |
| 2 | DebugObject 0x1F — per-boot type index | anti-debug.ts | NtQueryInformationProcess(ProcessDebugPort=7) |
| 3 | PEB NtGlobalFlag только для x64 (offset 0xBC) | anti-debug.ts | IsWow64Process → 0xBC (x64) / 0x68 (x86) |
| 4 | GetTickCount64 granularity (10-16ms) | anti-debug.ts | QueryPerformanceCounter (μs) |
| 5 | INT3 сканировал весь файл (не только .text) | self-integrity.ts | PE parser → только .text секция |
| 6 | `checkCodeSectionProtection` проверял PE header | self-integrity.ts | VirtualQuery walk по адресному пространству |
| 7 | `require('child_process')` inline | self-integrity.ts | top-level `import { execSync }` |
| 8 | `loadDb()` до `app.whenReady()` | fuzzy-hash.ts | initFuzzyHashDb() в main.ts |
| 9 | `_bucketedHashes` мёртвый код | fuzzy-hash.ts | Удалён полностью |
| 10 | Hit counters никогда не вызывались | signature-registry.ts | recordKeywordHit/PatternHit в matchKeywords/Patterns |
| 11 | `nocase wide ascii` невалидный YARA | auto-yara.ts | `nocase wide` |
| 12 | Дублирующий `filter(r => r.weight >= 0.2)` | auto-yara.ts | Удалён |
| 13 | `pruneColdSignatures` уничтожал все keywords | signature-registry.ts | Добавлена защита (хиты перед prune) |
| 14 | `SIGNAL_WEIGHTS`/`classifySignal` не экспортировались | risk-scorer.ts | `export const`/`export function` |
| 15 | WS без JWT auth → scanner-комната открыта | main.ts | `auth: { token }` в Socket.IO |

---

## 🗺️ ОСТАВШИЕСЯ ЗАДАЧИ

| # | Задача | Приоритет | Сложность |
|---|--------|-----------|-----------|
| E14 | Community JSON формат сигнатур | 🟡 P1 | 🟡 4ч |
| E19 | Code splitting (lazy load) | 🟢 P2 | 🟢 2ч |
| E21 | i18n: react-i18next (RU/EN) | 🟡 P1 | 🟡 6ч |
| E22 | E2E Playwright тесты | 🔴 P0 | 🔴 8ч |
| S9 | HTTP-only cookie для JWT | 🟡 P1 | 🟢 2ч |
| A8 | VirusTotal интеграция | 🟡 P1 | 🟡 3ч |
| A9 | Player leaderboard | 🟢 P2 | 🟡 6ч |

---

## ⚠️ РИСКИ

| Риск | Вероятность | Влияние | Митигация |
|------|-----------|--------|-----------|
| False positives | 🟡 Средняя | 🔴 Высокое | Shadow-mode, FP dashboard |
| Cheat devs bypass | 🔴 Высокая | 🟡 Среднее | ML + behavioral + hot-reload sigs |
| Server downtime | 🟢 Низкая | 🔴 Высокое | Оффлайн-режим |
| DB degradation | 🔴 Высокая | 🟡 Среднее | TTL archival (90д), индексы |
| Token abuse | 🟡 Средняя | 🔴 Высокое | Device fingerprinting |

---

*План поддерживается командой Predator. Обновляется каждый спринт.*
*Принцип: THINK FIRST → Research → Propose → Implement by stages.*
