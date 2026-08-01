# Changelog

## v0.5.0 — Аудит безопасности: integrity baseline, серверные хеши, evidence model (2026-08-01)

### 🔐 Аудит безопасности сканера

**C1 — Серверная проверка baseline (critical)**
- Таблица `client_hashes` добавлена в `server/src/index.ts` (init) + миграция `server/drizzle/0001_client_hashes.sql` (включая journal)
- Admin POST `/api/admin/client-hash` — superadmin-only, zod-схема, upsert, аудит через `client_hash_register`
- `scripts/register-client-hash.js` — регистрация sha256 exe после релизной сборки
- Опциональный шаг регистрации хеша в `scripts/release.js` (срабатывает при наличии ADMIN-кредов)
- Раньше `CLIENT_HASHES` был пуст и таблица отсутствовала в миграциях → TOFU-режим работал всегда

**C4 — Легальное автообновление больше не даёт ложный «high: tampering»**
- Ветка различает: bump версии + сервер подтверждает → rebase baseline; сервер MISMATCH → critical + tamper response; downgrade → high
- TOFU-базлайн перепроверяется против сервера на поздних запусках (самолечение отравленного baseline)
- 24h-троттлинг перепроверки ключуется на `lastServerCheck` (не `lastVerified`) — закрыт starvation для активных пользователей
- Severity-эскалация до `critical` при повторах во всех ветках
- `compareVersions` экспортирован; `IntegrityState.source: 'server' | 'tofu'`

**H1 — `criticalTamperResponse()` подключён (был мёртвым кодом)**
- Server-verified mismatch (первый запуск/смена версии/TOFU-перепроверка) → немедленный отклик
- Повторные локальные mismatch/downgrade (tamperCount ≥ 2) → critical + отклик

**H2 — Integrity проверяется во всех режимах скана**
- `runSelfIntegrityScan` добавлен в quick-scan и cleaner-scan (раньше только full-scan)

**M2 — Убран синхронный ввод-вывод из main-процесса**
- `verifySelfExeIntegrity` + `scanForInt3Patches` переведены на async `readFileRange` (чанки 1 МБ)

### 🧪 Тесты
- **19 новых unit-тестов** `electron/__tests__/self-integrity.test.ts`: semver, first-run, update-rebase, downgrade, TOFU self-heal, throttle, starvation-регрессия
- Итого: **302 electron + 104 server + 4 renderer** тестов, typecheck всех 5 проектов чистый, lint 0 ошибок
- 3 раунда код-ревью от deepseek-flash — все замечания закрыты

### 📝 Документация
- `docs/REFACTORING.md` — прогресс 17/19, evidence model и renderer-контракты отмечены готовыми
- `docs/ROADMAP.md` — v0.6, P0-пункты evidence model/explainable risk отмечены готовыми
- `docs/CHANGELOG.md` — актуальные записи

### ⚠️ Открытые рекомендации (вне скоупа)
- **C2**: подпись кода отсутствует (`signAndEditExecutable: false`) — нужен сертификат + `publisherName` для Authenticode-проверки обновлений
- **C3**: `fetchExpectedHash` доверяет локально настраиваемому `apiUrl` — локальный процесс может поднять фейковый сервер на :3001
- **M1**: баг приоритетов в PowerShell `verifyImportTable` (`.node`-модули всегда скипаются)

---

## v0.4.5 — Релизный пайплайн: автообновление, NSIS, надёжность (2026-07-31)

### 🐛 Исправление провального релиза
- Релиз v0.4.5 перевыпущен: ассеты `Predator-0.4.5.exe` + `latest.yml` загружены (были пустыми — workflow падал из-за релиза, созданного вручную через веб-интерфейс)

### 🔧 Релизный пайплайн
- **`.github/workflows/release.yml`** — удаляет устаревший релиз перед `gh release create` (фикс ошибки 422 «already exists», когда релиз уже создан вручную)
- **`scripts/release.js`**:
  - загрузка `.blockmap` — дифференциальные обновления через `electron-updater`
  - `process.exit(1)` при неудачной загрузке любого ассета (раньше скрипт молча печатал «✅ Релиз готов»)
  - исправлен текст релиза (потерянный перенос строки и `:3001`)

### 🚀 Автообновление (electron-updater)
- `win.target`: **portable → nsis** — portable-сборки не поддерживают автообновление (не встраивается `app-update.yml`, exe не может заменить сам себя)
- Удалён сломанный `include: resources/installer.nsh` (переопределял `MUI_HEADERIMAGE`, который electron-builder передаёт сам); файл удалён как мёртвый код
- `app-update.yml` теперь встраивается в сборку (owner lumatones / repo Predator / releaseType release)

### ⚠️ Для пользователей portable-версии
- Ранее скачанные portable-версии не могут обновиться автоматически — нужно один раз скачать новый NSIS-установщик вручную

---

## v0.4.4

### Project Cleanup and Housekeeping (2026-07-30)

**Documentation (6 files updated)**
- CHANGELOG.md updated with v0.4.1, v0.4.2, v0.4.3 entries
- ARCHITECTURE.md created with full system architecture
- RULES.md updated from v0.1.14 to v0.4.3 with current structure and endpoints
- REFACTORING.md updated with execSync migration and heuristic decomposition
- DEV.md rewritten with current commands and project structure
- README.md rewritten for GitHub with clean formatting

**Project Cleanup (16 items removed)**
- Root junk: Code.zip, Command Prompt.lnk, desktop.ini, nul
- Alien projects: Eye-Animation-Enhancer, .remotion-skill-temp, promo
- Debug artifacts: .freebuff with internal scripts and DB files
- Design briefs: DESIGN_FOR_KIMI, DESIGN_PLAN, VISUAL_DESIGN, VISUAL_FOR_KIMI
- Stale notes: SCANNER_IMPROVEMENTS, CONTEXT
- Duplicate: root RULES.md (kept docs/RULES.md)
- Runtime data: .predator_tlsh_db.json

**execSync Migration (161 calls)**
- Created electron/utils/exec.ts with execPowerShell, execWithTimeout, execFileWithTimeout
- All execSync calls migrated across 20 files
- Removed 7 migration scripts from scripts/
- 0 remaining child_process execSync imports in electron/

**Heuristic Decomposition**
- heuristic.ts barrel decomposed into 7 submodules
- Constants extracted to heuristic/constants.ts
- Name matcher to heuristic/name-matcher.ts

**Server Fix**
- ws-auth.ts SocketData type fixed for Socket.IO v4.8

---

## v0.4.3 — Code Quality, Music Player, Finding Explainer, Documentation (2026-07-30)

**Code Cleanup**
- Dead code removed: `riskClass()`, `calcScanPercent()`, `serverMsg`, `streamActive`, `riskLevels`
- `let` changed to `const` across multiple files
- Removed unused import `useCallback` from PredatorLogo3D.tsx
- Removed unused export `setKnownTlshHashes` from cloud-sync.ts
- Removed unused function `inferFindingKindFromResult` from Checker.tsx
- Removed eslint-disable comments from ApcDashboard.tsx and ScanTerminal.tsx

**Lint and TypeScript Fixes**
- All `require()` calls replaced with ES imports across Electron
- ESLint config updated: `no-unused-vars: off`, `no-empty` with allowEmptyCatch, `no-control-regex: off`
- YARA string escaping fixed in auto-yara.ts
- PowerShell string escaping fixed in pc-cleaner-detection.ts and pipes-wmi.ts

**New npm Scripts**
- `npm test`, `npm run test:electron`, `npm run test:renderer`
- `npm run typecheck:renderer`, `npm run lint:fix`
- `npm run typecheck` now includes renderer + electron + admin

**Music Player Upgrade**
- iTunes Preview source added as primary (free, no API key)
- Demo fallback when all remote sources are unavailable
- 7-second AbortController timeout on all fetch requests
- Invidious instances list updated
- Typed API responses replacing `any`

**FileDetailModal Rewrite**
- New `finding-explainer.ts` module for real explanations
- Automatic finding classification (dma, process, registry, browser, cleaner, file, software, system)
- Verdict section with description, whyDangerous, recommendation, confidenceNote
- Evidence model with source, weight, confidence per signal
- Full SHA256 displayed in modal

**execSync Migration (161 calls)**
- Created `electron/utils/exec.ts` with `execPowerShell`, `execWithTimeout`, `execFileWithTimeout`
- All 161 `execSync` calls migrated across 20 files
- Built-in timeout with process kill, null-safe return types
- Multi-line PowerShell C# scripts use `collapseLines` option

**Heuristic Decomposition**
- `heuristic.ts` barrel decomposed into 7 submodules under `heuristic/`
- Constants extracted to `heuristic/constants.ts`
- `name-matcher.ts`, `combo-detector.ts`, `signature-batch.ts`, `masquerading.ts`, `archive-scan.ts`, `cheat-names.ts`

**Documentation**
- `ARCHITECTURE.md` created with full system architecture
- `RULES.md` updated from v0.1.14 to v0.4.3
- `README.md` rewritten for GitHub with clean formatting
- `REFACTORING.md` updated with execSync and heuristic decomposition
- `DEV.md` rewritten with current commands and structure
- 7 obsolete migration scripts removed from `scripts/`

**Server Fix**
- `ws-auth.ts` SocketData type fixed for Socket.IO v4.8 compatibility

**Other Fixes**
- Electron config types updated
- `(cfg as any)` removed from Checker.tsx
- `IS_DEBUG_BUILD` uses top-level imports
- `connectCloudWebSocket` made async

---

## v0.4.2 — Eye Animations, Terminal Removal (2026-07-29)

**UI Improvements**
- Simplified eye animations in PredatorLogo3D
- Removed CMD-style terminal in favor of cleaner scan UI

---

## v0.4.1 — Music Player, Server Hash Verify, API Fix (2026-07-28)

**Music Player**
- Integrated music player with multiple sources
- MiniPlayer component for compact mode
- `useMusicPlayer` hook for playback control

**Server**
- Server-side hash verification endpoint
- API response format fix

### 🔧 Safe-Files Deadlock Fix
- **`refreshSafeFilesDb()`** — новая функция обновляет confirmCount для ВСЕХ существующих safe-файлов при каждом сканировании
- **Порог загрузки 3→1** — safe-файлы отправляются на сервер сразу после первого скана
- **`autoWhitelistLowRisk()`** теперь вызывает `refreshSafeFilesDb()` — confirmCount растёт на каждом скане

### 📡 Полная data pipeline (hash + signature + size + name → server)
- **`partialHash`** (первые 64KB SHA256) вычисляется для ВСЕХ результатов хьюристики, а не только high-risk
- **`hasValidSignature`** — цифровая подпись (сертификат) теперь отправляется на сервер для каждого .exe/.dll/.sys
- **`submitAllFindings()`** заменяет `submitHighRiskHashes()` — отправляет ВСЕ file-type результаты
- **ScanResult.size** исправлен с 0 на реальный размер файла

### 🗄 Серверные изменения
- `suspicious_hashes` — новые колонки: `partial_hash`, `file_path`, `risk`, `matches`, `has_valid_signature`
- `submit-hashes` — INSERT ON DUPLICATE KEY UPDATE с fallback sha256=partialHash
- `submit-scan` — передаёт `partialHash` в классификатор (был `undefined`)
- `sha256` в схеме теперь optional — low/medium-risk файлы используют partialHash

### ♻ Рефакторинг
- `submitHighRiskHashes()` → `submitAllFindings()` в DEFAULT_PIPELINE
- Тесты обновлены под новую сигнатуру
- 500 лимит в `submitAllFindings()` для защиты серверной валидации

---

## v0.3.0 — AI Scanner Intelligence + DMA/Hardware/RE Detection (2026-07-27)

### 🧠 Auto-Scan Intelligence
- **Server-side auto-classifier** (`server/src/services/classifier.ts`) — автоматическая классификация результатов
- **Telemetry Queue** (`electron/telemetry-queue.ts`) — надёжная очередь загрузки с ретраями
- **Result Grouper** — группировка/фильтрация результатов (реальные читы vs шум)
- **Noise filter** — UI показывает только реальные угрозы, не миллионы файлов
- **Safe-files auto-whitelist**: сервер автоматически добавляет проверенные файлы в вайтлист

### 🔌 USB/PCI Device Intelligence
- **USB Device Inventory** (`electron/modes/usb-devices.ts`) — полный инвентарь устройств
- **Device Classification**: телефон/флешка/DMA-карта/клавиатура/вебкамера/хаб — с иконками
- **USB Descriptor Reading** — точное определение MTP/ADB/PTP режима, производитель, серийный номер
- **DMA Device History** — детект ОТКЛЮЧЁННЫХ DMA-карт через реестр и setupapi.dev.log
- **Driver Signature Verification** — проверка подписи FTDI/FPGA драйверов
- **USB Bandwidth Monitor** — детект АКТИВНЫХ DMA-карт по USB-трафику (>150 MB/s = high risk)

### 🎯 Hardware Cheat Detection
- **HW Cheat VIDs** — Arduino Leonardo (2341), Teensy (16C0), Titan Two (2508), Cronus Zen (0C12)
- Автоматический high-risk флаг при обнаружении hardware aimbot устройств

### 🛡️ BYOVD Scanner
- **`electron/modes/byovd.ts`** — 3-тирный сканер уязвимых драйверов
- 9 драйверов: gdrv.sys, RTCore64.sys, Capcom.sys, kprocesshacker.sys, winio64.sys, phymem.sys, dbk64.sys, cpuz*.sys, interception.sys
- Тиры: файлы в System32\drivers + WMI-сервисы + реестр

### 🔍 Anti-Debug / R.E. Scanner
- **`electron/modes/anti-debug.ts`** — детект реверс-инжиниринг тулов
- 12 тулов: x64dbg, Cheat Engine, IDA Pro, Ghidra, Process Hacker, WinDbg, dnSpy, OllyDbg, Binary Ninja, ReClass, HxD, DLL Injectors
- Детект anti-debug DLL (scyllahide, titanhide, hyperhide)

### 📦 Интеграция
- BYOVD → Phase 5c (IPC & persistence)
- Anti-Debug → Phase 1a (process scanning)
- Hardware Cheat VIDs → Phase 1b (USB device scan)

---

## v0.1.14 — Архитектурный рефакторинг (2026-07-27)

### 🏗 Архитектура

**ScanPipeline** — композируемая цепочка пост-скановых обработчиков:
- `electron/scan-pipeline.ts` — 5 изолированных handler'ов (SessionRecorder, ShadowSubmitter, AutoWhitelister, HashSubmitter, ResultUploader)
- IPC handler сокращён с 200 строк до 20
- Отказ одного handler'а не влияет на остальные

**Signature Registry** — единый источник данных для сигнатур:
- `electron/signature-registry.ts` — ALL_CHEAT_KEYWORDS, SUSPICIOUS_PATTERNS, SUSPICIOUS_CATEGORIES
- Query API: `matchKeywords()`, `matchPatterns()`, `getCategory()`
- `heuristic.ts`: -200 строк inline-данных, только scoring logic

**MASQUERADING_SYSTEM_TOOLS** — подмножество для поведенческого детекта:
- Исключены браузеры (chrome/edge/firefox) и приложения (discord/steam)
- Только инсталляторы и утилиты: dxwebsetup.exe, vcredist.exe, notepad.exe, vanguard.exe
- 3 сигнала: память >200MB, множественные экземпляры, VMProtect-паттерн

### 🔬 Поведенческий детект

**Falcon Sandbox анализ dxwebsetup.exe:**
- CrowdStrike 100% malicious, VMProtect, Barys family
- Добавлен `B('barys')` в KNOWN_BINARY_SIGNATURES
- Интегрирован в runProcessScan() и runQuickScan()

### 📄 Документация

- Architecture Review Report (HTML + Mermaid-диаграммы)
- Полная инвентаризация архитектуры: 130+ файлов, 5 deepening opportunities

---

## v0.0.21 — Рефакторинг, типизация, новый релизный скрипт (2026-07-26)

### 🧹 Рефакторинг

**ScanContext класс** — изоляция состояния между сканированиями:
- `ctx.findingDedup`, `ctx.sigCache`, `ctx.peHeaderCache`, `ctx.cheatNameCache`
- Метод `ctx.clear()` для сброса всех кешей
- Глобальный `ctx` — единая точка доступа

**parsePsJson<T>()** — безопасный парсинг PowerShell JSON:
- Обрабатывает одиночный объект и массив
- Защита от пустого вывода и ошибок парсинга
- Применён в dma.ts, games.ts, processes.ts, disk-vs-memory.ts, scanner.ts

**CFG конфиг** — единый источник системных путей:
- `PF`, `PF86`, `WR`, `HOME`, `PD`
- Используется в cheats-db.ts, browser-history.ts

**Константы вынесены** в `constants.ts`:
- `CHEAT_SOFTWARE_NAMES`, `EXTENDED_CHEAT_KEYWORDS`, `EXTENDED_SCAN_PATHS`

**Cloud sync вынесен** в `cloud-sync.ts`:
- `fetchCheatHashes()`, `startCloudSync()`, `stopCloudSync()`

**Типизация улучшена**:
- Убраны `any` в scanner.ts, disk-vs-memory.ts, rwx-scanner.ts
- Добавлен интерфейс `ScanOptions`

### 🔧 Новый скрипт релиза
- `npm run release` — полный цикл: typecheck → build → latest.yml → GitHub Release
- Автоматическое чтение `GITHUB_TOKEN` из `.env`

### 🎨 UI
- Обновлён тёмный интерфейс, добавлен hero-блок

---

## v0.0.20 — CI typecheck fix (2026-07-25)

### 🔧 Исправления
- 10 typecheck ошибок в `tsconfig.electron.json`

---

## v0.0.19 — Тесты Vitest + API_BASE env + Сканер модулей (2026-07-25)

### ✨ Новые возможности
- **Vitest** — тестовый фреймворк (`heuristic.test.ts`)
- **API_BASE** — переменная окружения для настройки URL сервера
- Удалена **Statistics** страница

---

## v0.0.18 — Layout fix + ErrorBoundary (2026-07-25)

### 🔧 Исправления
- Фикс лейаута
- Удалена Statistics
- Добавлен ErrorBoundary компонент

---

## v0.0.17 — Layout fix + ErrorBoundary (2026-07-25)

(См. v0.0.18)

---

## v0.0.16 — Баг-фиксы + UI улучшения (2026-07-25)

### 🔧 Исправления
- `safeSpread` — защита от «a is not iterable»
- try-catch в сканере

### 🎨 UI
- Группы риска (CRITICAL / HIGH / MEDIUM / WARNING)
- Анимация строк результатов

---

## v0.0.15 — SVG-дизайн-система (2026-07-25)

### 🎨 UI
- 14 векторных иконок (`src/icons/`)
- Idle-анимации
- Полная замена эмодзи на SVG-иконки

---

## v0.0.14 — React UI fixes + Server security (2026-07-25)

### 🔧 Исправления
- Фиксы React UI
- Усиление безопасности сервера

---

## v0.0.13 — RWX scanner fixes (2026-07-25)

### 🔧 Исправления
- `rwx-scanner` template inside function
- Add-Type PowerShell guard
- PID scope fix
- tsconfig.electron fix
- IPC try-catch

---

## v0.0.12 — Auto-YARA, Memory Dumper, ETW/AMSI, Дизайн-система (2026-07-24)

### ✨ Новые возможности
- **Auto-YARA** (`auto-yara.ts`) — самообучающиеся YARA-правила
- **Memory Dumper** (`memory-dump.ts`) — MiniDumpWriteDump + анализ строк
- **ETW/AMSI Patch Detector** (`etw-amsi-patch.ts`) — обнаружение обхода защит
- **Дизайн-система** — иконки и компоненты

---

## v0.0.11 — WebSocket + JWT-защита + Графики (2026-07-24)

### ✨ Новые возможности

**🌐 Browser History Parser (sql.js)**
- Структурированный парсер истории Chromium-браузеров (Chrome, Edge, Brave, Yandex, Opera, Opera GX)
- Использует `sql.js` (WASM — не требует нативной компиляции)
- Каждый результат: URL, заголовок, количество посещений, дата визита
- Singleton-инициализация WASM (один раз, переиспользуется)

**📤 Отправка результатов на сервер**
- После каждого сканирования результаты автоматически отправляются на бэкенд
- Новая таблица `scan_results` в MySQL
- `POST /api/auth/submit-scan` — сохранение результатов
- `GET /api/admin/scan-stats` — статистика всех сканирований
- Индикатор `✓ Server` в интерфейсе

**📊 Графики в админ-панели (Chart.js)**
- Dashboard полностью переписан с `chart.js` + `react-chartjs-2`
- Doughnut-чарт: распределение по режимам сканирования
- Bar-чарт: сканирования и угрозы по дням
- Карточки статистики: токены, запросы, сканирования, угрозы
- Таблица последних сканирований

**🔌 WebSocket (Socket.IO) — Real-time обновления**
- Сервер: `socket.io` на порту 3001 (тот же HTTP-сервер)
- Админ-панель: подключение по WebSocket, комната `admin`
- События: `new-request`, `request-update`, `token-generated`, `scan-result`
- Toast-уведомления при каждом событии
- Статус `● Real-time` / `● Disconnected` в хедере
- WebSocket URL динамический: `http://${hostname}:3001`

**📡 IPC Streaming (системный Dashboard)**
- Замена polling на непрерывный IPC push из main process
- `startSystemStream()` / `stopSystemStream()` — управление стримингом
- `onSystemUpdate()` — получение данных в реальном времени
- Fallback на mock polling для dev mode

**🔒 JWT-защита submit-scan**
- Эндпоинт проверяет `token_id` в БД перед сохранением
- Токен должен существовать, быть активированным и использованным
- Валидация типа: `Number.isInteger`
- Полный lifecycle: validate → use → store token_id → submit with token_id

### 🔧 Исправления

- `initSqlJs()` вызывался при каждом сканировании → Singleton `getSqlJs()`
- `webkitTimeToDate(0)` → `Date(-11644473600000)` → Guard: `lastVisitTime > 0`
- `serverMsg` не рендерился → зелёный `✓ Server` в UI
- Мёртвый код `_BROWSER_SCANNER_ACTIVE` + пустой fallback-цикл → удалён
- Doughnut-чарт показывал все угрозы как "High" → распределение по режимам
- `TS2774` condition always true → `typeof` guard
- Нет WS события для новых запросов → `new-request` в auth.js
- `WS_BASE` hardcoded → динамический `window.location.hostname`
- `token_id` не сохранялся после авторизации → добавлено состояние `tokenId`

## v0.0.10 — Сканер v3.0, YARA, PE-анализ, экспорт (2026-07-22)

### ✨ Новые возможности

- **Сканер v3.0** — YARA-правила (8 правил), PE-анализ (MZ/PE-сигнатуры, секции, entry point, relocation), энтропия Шеннона O(n)
- **Whitelist** — 27 доверенных компаний + 16 системных путей (-30 к score для системных файлов)
- **Экспорт отчётов** — HTML с Chart.js + JSON
- **Winlogon пути реестра** — доп. проверка автозагрузки
- **Кнопки экспорта** в интерфейсе

## v0.0.9 — Улучшения UI/UX (2026-07-22)

- Анимации: staggered rows, tab transitions, icon bounce, glow, pulse
- Detail-панели при клике на строку результатов
- Микро-анимации на все UI-элементы

## v0.0.8 — Дашборд, статистика, сетевой режим (2026-07-22)

- Дашборд системы: CPU/RAM/температура/процессы (Gauges)
- Статистика сканирований: графики по дням, топ читов, горячие директории
- Режим «Сеть»: DNS-кеш, hosts файл, активные подключения, подозрительные IP
- Фильтр поиска по результатам
- Периодическая проверка обновлений (каждые 5 минут)
- Индикатор обновления в футере

## v0.0.7 — Полный переезд на backend (2026-07-22)

- Backend API: Express + MySQL, JWT + bcrypt
- Система токенов (32 символа): генерация, валидация, использование, отзыв
- Запросы на доступ: создание, одобрение/отклонение админом, polling статуса
- Admin Site: Login, Dashboard, Pending, Tokens, History
- Интеграция приложения с бэкендом

## v0.0.6 — Начало разработки бэкенда (2026-07-22)

- Базовая структура сервера (Express + MySQL)
- Прототип авторизации
- Первые эндпоинты API

## v0.0.5 — Система чекера (2026-07-22)

- 4 режима сканирования: Файлы, Процессы, Читы, DMA
- Микро-анимации, тёмная тема, стеклянный UI
- Интеграция с базами сигнатур

## v0.0.4 — Онбординг + установщик (2026-07-22)

- Glassmorphism установщик
- Онбординг: язык, тема, авторизация
- Auto-updater

## v0.0.3 — Первый прототип (2026-07-22)

- Electron + Vite + React структура
- Базовый UI с тёмной темой
- Прототип установщика

## v0.0.2 — Настройка проекта (2026-07-22)

- Настройка сборки
- Базовая конфигурация
- Эксперименты с установщиком

## v0.0.1 — Инициализация (2026-07-22)

- Создание репозитория
- Базовая структура проекта
- README и документация
