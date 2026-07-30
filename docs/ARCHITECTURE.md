# Predator — Архитектура проекта 🦅

> **Версия**: v0.4.3 | **Последнее обновление**: 2026-07-30

## 🗺 Обзор системы

Predator состоит из трёх независимых компонентов, связанных через HTTP API и WebSocket:

```
┌──────────────────────────┐     HTTP + WS      ┌──────────────────────┐
│   DESKTOP APP (Electron) │◄──────────────────►│   BACKEND API        │
│   Windows 10/11 x64      │                    │   Express + MySQL    │
│   ~18,700 строк кода     │                    │   :3001              │
│   41 main-process файлов  │                    │   Drizzle ORM + JWT  │
└──────────┬───────────────┘                    └──────────┬───────────┘
           │                                               │
           │ IPC (contextBridge)                           │ HTTP + WS
           ▼                                               ▼
┌──────────────────────────┐                    ┌──────────────────────┐
│   RENDERER (React 19)    │                    │   ADMIN PANEL        │
│   Vite + Framer Motion   │                    │   React 19 + Vite    │
│   Three.js + Particles   │                    │   :5173              │
└──────────────────────────┘                    └──────────────────────┘
```

---

## 1. Desktop App — Архитектура Electron

### 1.1 Главный процесс (Main Process)

```
electron/main.ts
  ├── createWindow()              # BrowserWindow с contextIsolation
  ├── autoUpdater                 # electron-updater → GitHub Releases
  ├── Tray                        # Системный трей с меню
  ├── Crash Log                   # crash.log для отладки
  ├── IPC Handlers                # 15+ обработчиков
  └── Bootstrap (app.whenReady):
       ├── initSafeFilesDb()      # Загрузка комьюнити-whitelist
       ├── initializeSelfProtection()  # ACL hardening + SeDebugPrivilege
       ├── initFuzzyHashDb()      # TLSH persistent DB
       ├── initTelemetry()        # Очередь отправки результатов
       ├── registerScanHandlers() # IPC: start-scan, cancel-scan
       ├── startCloudSync()       # HTTP polling + WebSocket
       ├── startSignatureWatcher()# File watcher для сигнатур
       └── startScanScheduler()   # Периодические + инкрементальные сканы
```

**IPC-интерфейс** (preload.ts → contextBridge):

| Канал | Направление | Назначение |
|-------|------------|------------|
| `start-scan` | renderer → main | Запуск сканирования (mode, tokenId) |
| `cancel-scan` | renderer → main | Отмена активного скана |
| `scan-progress` | main → renderer | Прогресс сканирования (фаза, директория, счётчики) |
| `get-system-snapshot` | renderer → main | Системный дашборд (CPU/RAM/GPU) |
| `system-snapshot` | main → renderer | Стриминг системной информации |
| `get-config` / `save-config` | renderer → main | Чтение/запись конфигурации |
| `update-available` | main → renderer | Уведомление об обновлении |
| `crash-event` | main → renderer | Критический сбой в main-процессе |

### 1.2 Сканер — Ядро системы

```
electron/scanner.ts (оркестратор)
  │
  ├── registerScanHandlers()
  │     ├── ipcMain.handle('start-scan')  → dispatch по режиму
  │     └── ipcMain.handle('cancel-scan') → abortController.abort()
  │
  └── dispatch:
        ├── 'full'    → scanner/full-scan.ts    (15 фаз)
        ├── 'quick'   → scanner/quick-scan.ts   (6 фаз)
        ├── 'dma'     → modes/dma.ts            (PCI+USB)
        └── 'cleaner' → scanner/cleaner-scan.ts (4 фазы)
```

**4 режима сканирования:**

| Режим | Фазы | Время | Что проверяет |
|-------|------|-------|---------------|
| **Full** | 15 | ~2-5 мин | Всё: процессы, файлы, реестр, сеть, DMA, браузер, память, поведение, анти-отладка |
| **Quick** | 6 | ~30 сек | Процессы, Prefetch, реестр, pipes, сеть, браузер |
| **DMA** | 1 | ~10 сек | PCI-устройства, FPGA, драйверы, реестр |
| **Cleaner** | 4 | ~15 сек | USN Journal, Timestomping, ShellBags, HWID |

**15 фаз Full Scan:**

```
1.  Self-Integrity       SHA256 .exe baseline, INT3 patch scan, IAT DLL proxy
2.  Process Scanning     DLL modules, cheat signatures, masquerading detection
3.  Heuristic Analysis   Shannon entropy, YARA (13 правил), PE headers, TLSH, API hashing
4.  Registry Deep Scan   Run/RunOnce, Services, Winlogon — 9 категорий угроз
5.  Prefetch Analysis    .pf файлы — история запуска исполняемых файлов
6.  System Integration   Network + Game integrity + Masquerading + Pipes + WMI + AMSI/ETW
7.  Game Memory          ReadProcessMemory hooks, CEF debug ports, aimbot/ESP patterns
8.  Network Intel        C2 patterns, proxy/VPN detection, suspicious DNS
9.  DMA Detection        PCI devices, firmware fingerprinting, USB anomaly
10. Registry Cheat Scan  8 специфичных путей реестра
11. Browser History      SQLite: Chrome, Edge, Brave, Yandex, Opera, Opera GX
12. Behavior Analysis    Cross-process correlation, attack chain detection
13. Anti-Debug           7 уровней: RE tools → HWBP → ProcessDebugPort → PEB → QPC timing
14. Anti-Tamper          Integrity verification, VM/Sandbox detection
15. Cloud Submission     SHA256 + TLSH hashes → backend API
```

### 1.3 Post-Scan Pipeline

После завершения сканирования результаты проходят через цепочку обработчиков:

```
ScanResults[]
  │
  ├── 1. SessionRecorder    Запись результатов в лог сканирования
  ├── 2. ShadowSubmitter    Отправка shadow-mode телеметрии на сервер
  ├── 3. AutoWhitelister    Фильтрация через safe-files-db (комьюнити-whitelist)
  ├── 4. HashSubmitter      Отправка SHA256/TLSH хешей подозрительных файлов
  └── 5. ResultUploader     Отправка полного JSON результатов сканирования
```

**Shared ScanContext (`ctx`):**

```
electron/types.ts → ScanContext
  ├── findingDedup: Set<string>     Дедупликация находок между фазами
  ├── sigCache: Map<string, bool>   Кеш цифровых подписей (2s экономии на файл)
  ├── peHeaderCache: Map<>          Кеш PE-заголовков
  ├── cheatNameCache: Map<>         Кеш совпадений имён читов
  ├── shadowFindings: ScanResult[]  Теневые находки (телеметрия)
  ├── escalationBonus: number       Бонус эскалации из persistent-profile
  └── abortController              Контроллер отмены скана
```

### 1.4 Слои детекции

```
                    ┌───────────────────────────────────┐
                    │        СЛОИ ДЕТЕКЦИИ               │
                    ├───────────────────────────────────┤
  Уровень 1:        │ SIGNATURES (точные совпадения)    │
  ─────────         │ • SHA256 хеши (>250 известных)    │
                    │ • TLSH fuzzy хеши (persistent DB) │
                    │ • Имена процессов/файлов/папок     │
                    │ • Бинарные сигнатуры (строки)      │
                    ├───────────────────────────────────┤
  Уровень 2:        │ HEURISTICS (вероятностный анализ)  │
  ─────────         │ • Shannon Entropy (порог 7.5)     │
                    │ • YARA-правила (13 шт.)           │
                    │ • PE-анализ (секции, заголовки)    │
                    │ • Цифровые подписи (Authenticode) │
                    │ • Combo-детектор (unsigned binary) │
                    │ • Masquerading detection           │
                    ├───────────────────────────────────┤
  Уровень 3:        │ BEHAVIORAL (поведенческий)        │
  ─────────         │ • Process tree analysis            │
                    │ • Injection pair detection         │
                    │ • Attack chain detection           │
                    │ • Cross-process correlation        │
                    │ • Thread injection patterns        │
                    ├───────────────────────────────────┤
  Уровень 4:        │ MEMORY (анализ памяти)            │
  ─────────         │ • RWX region scanner              │
                    │ • Disk-vs-Memory (.text compare)  │
                    │ • MiniDump + string extraction    │
                    │ • Thread start address anomalies  │
                    ├───────────────────────────────────┤
  Уровень 5:        │ ANTI-TAMPER (защита сканера)      │
  ─────────         │ • Anti-Debug (7 tiers)            │
                    │ • Self-Integrity (SHA256 + INT3)  │
                    │ • Self-Protect (ACL Deny ACE)     │
                    │ • VM/Sandbox detection            │
                    │ • Hypervisor fingerprinting       │
                    └───────────────────────────────────┘
```

**9 категорий угроз** (из `signature-registry.ts`):

| Категория | Описание | Риск | Сигнатуры |
|-----------|----------|------|-----------|
| `injector` | DLL-инжекторы | CRITICAL | `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx` |
| `debugger` | Отладчики | CRITICAL | `IsDebuggerPresent`, `NtQueryInformationProcess` |
| `hook` | Хуки функций | HIGH | `SetWindowsHookEx`, `DetourAttach`, `MinHook` |
| `driver` | Kernel-драйверы | CRITICAL | `IoCreateDevice`, `PsSetCreateProcessNotifyRoutine` |
| `spoofer` | Подмена HWID | HIGH | `HardwareID`, `SMBIOS`, `MACAddress` |
| `bypass` | Обход защит | CRITICAL | `bypass`, `evade`, `anti-cheat` |
| `menu` | Игровые меню | HIGH | `ImGui`, `Direct3D`, `overlay`, `aimbot` |
| `network` | Прокси/VPN | MEDIUM | `WSASocket`, `socks`, `proxy` |
| `obfuscator` | Упаковщики | HIGH | `VMProtect`, `Themida`, `Enigma` |

### 1.5 Risk Scorer — 25 взвешенных сигналов

Модуль `risk-scorer.ts` принимает 25 категорий сигналов (веса 0.1–0.95), накапливает их по логарифмической шкале, применяет device fingerprint и бонус эскалации из `persistent-profile.ts`.

```
Risk Score = Σ(signal_weight × log₁₀(evidence_count + 1)) + escalationBonus
```

---

## 2. Backend API — Архитектура сервера

### 2.1 Структура

```
server/src/
  ├── index.ts                # Express + Socket.IO + graceful shutdown
  ├── config/database.ts      # MySQL connection pool
  ├── db/                     # Drizzle ORM
  │   ├── schema.ts           # Type-safe schema
  │   ├── init.ts             # Database initializer
  │   └── schema.sql          # Raw SQL
  ├── middleware/              # 7 middleware-модулей
  ├── routes/                 # 3 роутера
  ├── services/               # 3 сервиса
  ├── helpers/                # pagination, errors
  └── __tests__/              # 5 тестовых файлов
```

### 2.2 Middleware Stack (порядок выполнения)

```
Request → helmet → CORS → express.json → requestId → metrics → rateLimit → route handler
                                                                          ↓
                                                                     auth (JWT)
                                                                     roles (RBAC)
                                                                     audit-log
```

| Middleware | Порядок | Назначение |
|------------|---------|------------|
| `helmet` | 1 | HTTP-заголовки безопасности |
| `cors` | 2 | Разрешённые источники (CLIENT_URL) |
| `express.json` | 3 | Парсинг JSON (лимит 5 МБ) |
| `request-id` | 4 | X-Request-ID propagation |
| `metrics` | 5 | Prometheus-метрики |
| `rate-limit` | 6 | 100 req/min (глобально) |
| `auth.ts` | route | JWT-верификация (admin-роуты) |
| `roles.ts` | route | RBAC: admin / operator / viewer |
| `rate-limit-login.ts` | route | 5 попыток / 15 мин, блокировка после 10 |
| `ws-auth.ts` | WS | JWT + connection rate limiting для Socket.IO |

### 2.3 API Endpoints

**Auth (публичные):**

| Метод | Путь | Тело/Auth |
|-------|------|-----------|
| POST | `/api/auth/token` | `{ token }` |
| POST | `/api/auth/token/use` | `{ token, pc_username }` |
| POST | `/api/auth/request` | `{ pc_username }` |
| GET | `/api/auth/status/:id` | — |
| POST | `/api/auth/submit-scan` | `{ token_id, results[], summary }` |
| POST | `/api/auth/submit-hashes` | `{ token_id, hashes[] }` |
| POST | `/api/auth/submit-safe-files` | `{ entries[] }` |
| POST | `/api/auth/submit-shadow` | `{ token_id, findings[] }` |
| GET | `/api/auth/fetch-hashes` | `?after=ISO_DATE` |
| GET | `/api/auth/safe-files` | `?since=ISO_DATE` |

**Admin (JWT):**

| Метод | Путь | Роль |
|-------|------|------|
| POST | `/api/admin/login` | — |
| GET | `/api/admin/pending` | admin |
| POST | `/api/admin/approve/:id` | admin |
| POST | `/api/admin/approve-batch` | admin |
| POST | `/api/admin/reject/:id` | admin |
| POST | `/api/admin/reject-batch` | admin |
| POST | `/api/admin/tokens/generate` | superadmin |
| GET | `/api/admin/tokens` | admin |
| POST | `/api/admin/tokens/revoke/:id` | admin |
| GET | `/api/admin/history` | admin |
| GET | `/api/admin/scan-stats` | admin |
| GET | `/api/admin/suspicious-hashes` | admin |
| POST | `/api/admin/hashes/approve/:id` | admin |
| POST | `/api/admin/hashes/reject/:id` | admin |
| POST | `/api/admin/hashes/confirm-from-scan` | admin |
| GET | `/api/admin/scan-result-hashes` | admin |
| GET | `/api/admin/safe-files-stats` | admin |
| GET | `/api/admin/shadow-findings` | admin |
| POST | `/api/admin/shadow/promote` | superadmin |

### 2.4 Сервисы

```
server/src/services/
  ├── classifier.ts       # Auto-Classifier (rule engine + crowdsourcing)
  │   ├── classifyBatch()          # Классификация находок скана
  │   ├── autoPromoteShadowRules() # Авто-продвижение shadow-правил
  │   └── Статистика: autoSafe, autoMalicious, pending
  │
  ├── tlsh-matcher.ts     # TLSH matching engine
  │   ├── Prefix trie (O(1) rejection для 99%+ запросов)
  │   └── Пороги: tiny=15, small=22, medium=30, large=35
  │
  └── cheat-knowledge.ts  # Cheat knowledge base
      └── Crowdsourced intelligence aggregation
```

### 2.5 База данных (MySQL 8 + Drizzle ORM)

```
Таблицы:
  ├── tokens              # Токены доступа (32-char hex)
  ├── requests            # Запросы на доступ (pending/approved/rejected)
  ├── admins              # Администраторы (bcrypt passwords)
  ├── scan_results        # Результаты сканирований (JSON)
  ├── suspicious_hashes   # Хеши подозрительных файлов (SHA256 + TLSH)
  ├── safe_files          # Комьюнити-whitelist (partialHash + confirmCount)
  └── shadow_findings     # Shadow-mode телеметрия (rule_name + occurrence_count)

Индексы:
  ├── idx_sr_token ON scan_results(token_id)
  └── idx_req_username ON requests(pc_username)

TTL Cleanup:
  └── scan_results старше 90 дней → автоудаление (каждые 6 часов)
```

### 2.6 WebSocket (Socket.IO)

```
Комнаты:
  ├── 'scanner'  — клиенты сканера (опциональная JWT-аутентификация)
  │   События:
  │     ← hash-update (новые подтверждённые хеши)
  │     ← rule-update (shadow-правила продвинуты в production)
  │
  └── 'admin'    — админ-панель (обязательная JWT-аутентификация)
      События:
        ← new-request (новая заявка на доступ)
        ← request-update (approve/reject/batch)
        ← new-hashes (новые хеши от сканера)
        ← hash-update (подтверждение/отклонение хеша)
        ← token-generated (сгенерированы новые токены)
        ← shadow-update (промоция/отклонение shadow-правила)

Connection Limits:
  ├── 200 max всего
  ├── 10 на IP
  └── 5 новых соединений/IP/мин

JWT Expiry Check:
  └── Каждые 60 сек — проверка exp у admin-сокетов
```

---

## 3. Admin Panel — Архитектура

```
admin/src/
  ├── App.tsx               # AuthContext + Router
  ├── api.ts                # HTTP client (JWT в заголовке)
  ├── components/
  │   ├── Layout.tsx        # Sidebar (иконки + навигация)
  │   ├── CommandPalette.tsx # Ctrl+K — быстрое действие
  │   ├── HashDetailModal.tsx# Детальный просмотр хеша
  │   ├── AnimatedNumber.tsx # Анимированные счётчики
  │   └── KeyboardShortcutsHelp.tsx # ? — справка по клавишам
  ├── hooks/
  │   ├── useSessionTimeout.ts  # Авто-логаут через 30 мин
  │   ├── useKeyboardShortcuts.ts # 1-6 навигация, A/R approve/reject
  │   └── useFocusTrap.ts       # Захват фокуса в модалках
  └── pages/
      ├── Login.tsx             # JWT-аутентификация
      ├── Dashboard.tsx         # Статистика + графики
      ├── Pending.tsx           # Заявки на доступ (approve/reject)
      ├── Tokens.tsx            # Управление токенами
      ├── History.tsx           # История событий
      ├── SafeFiles.tsx         # Комьюнити-whitelist
      └── SuspiciousHashes.tsx  # База хешей (подтверждение/отклонение)

WebSocket:
  └── При логине: socket.emit('join-admin') → комната 'admin'
      Real-time уведомления: новые заявки, хеши, изменения статусов
```

---

## 4. Потоки данных (Data Flows)

### 4.1 Сканирование (полный цикл)

```
User clicks "Start Scan"
  │
  ├── 1. Checker.tsx → window.electronAPI.startScan(mode, tokenId)
  │     └── IPC: 'start-scan'
  │
  ├── 2. scanner.ts → registerScanHandlers()
  │     ├── ctx.resetScan()              # Очистка dedup, новый abortController
  │     ├── escalationBonus = getProfile()# Накопительный риск из прошлых сессий
  │     └── dispatch(mode):
  │           ├── full → runFullScan(win)
  │           ├── quick → runQuickScan(win)
  │           ├── dma → runDmaScan(win)
  │           └── cleaner → runCleanerScan(win)
  │
  ├── 3. scan-progress events → renderer (live terminal)
  │
  ├── 4. Post-Scan Pipeline:
  │     ├── rescoreResults()             # Risk Scorer (25 сигналов)
  │     ├── filterNoiseFindings()        # Фильтр шума
  │     └── runPostScanPipeline():
  │           ├── SessionRecorder
  │           ├── ShadowSubmitter → POST /api/auth/submit-shadow
  │           ├── AutoWhitelister
  │           ├── HashSubmitter → POST /api/auth/submit-hashes
  │           └── ResultUploader → POST /api/auth/submit-scan
  │
  └── 5. ScanResponse → renderer
        └── Checker.tsx: groupedResults, ThreatMap, ApcDashboard
```

### 4.2 Жизненный цикл токена

```
Admin generates tokens
  │  POST /api/admin/tokens/generate
  │  → crypto.randomBytes(16) → 32-char hex
  │
User enters token in app
  │  POST /api/auth/token → { valid: true, token_id }
  │  POST /api/auth/token/use → binds to PC name, sets is_active=FALSE
  │
App performs scans
  │  POST /api/auth/submit-scan  (requires activated token)
  │  POST /api/auth/submit-hashes (requires activated token)
  │
Admin reviews results
  │  suspicious_hashes → approve/reject
  │  shadow_findings → promote/reject
```

### 4.3 Cloud Sync (хеши читов)

```
┌────────────────────┐         ┌────────────────────┐
│   Desktop App      │         │   Backend API      │
│                    │         │                    │
│  cloud-sync.ts     │  HTTP   │  GET /auth/fetch-  │
│  ┌──────────────┐  │◄────────│  hashes?after=...  │
│  │ fetchCheat-  │  │         │                    │
│  │ Hashes()     │  │  WS     │  scanner room      │
│  │              │  │◄────────│  'hash-update'     │
│  │ every 30min  │  │         │  event             │
│  └──────────────┘  │         └────────────────────┘
│                    │
│  signature-watcher │  File watcher → горячая
│  ┌──────────────┐  │  перезагрузка сигнатур
│  │ watch()      │  │  без перезапуска
│  └──────────────┘  │
└────────────────────┘
```

---

## 5. Модульная карта (Dependency Graph)

```
electron/main.ts
  ├── scanner.ts ◄────────── Главный оркестратор
  │     ├── scan-pipeline.ts
  │     ├── risk-scorer.ts
  │     ├── result-grouper.ts (filterNoiseFindings)
  │     ├── cloud-sync.ts
  │     ├── telemetry-queue.ts
  │     ├── signature-watcher.ts
  │     ├── scan-scheduler.ts
  │     └── persistent-profile.ts
  │
  ├── scanner/full-scan.ts
  │     ├── modes/processes.ts
  │     │     ├── modes/process/enumeration.ts
  │     │     ├── modes/process/behavioral.ts
  │     │     └── modes/process/pipes-wmi.ts
  │     ├── heuristic.ts (barrel)
  │     │     ├── heuristic/constants.ts
  │     │     ├── heuristic/name-matcher.ts
  │     │     ├── heuristic/combo-detector.ts
  │     │     ├── heuristic/signature-batch.ts
  │     │     ├── heuristic/masquerading.ts
  │     │     ├── heuristic/archive-scan.ts
  │     │     └── heuristic/cheat-names.ts
  │     ├── signature-registry.ts
  │     ├── cheats-db.ts
  │     ├── cheat-rules.ts (YARA)
  │     ├── auto-yara.ts
  │     ├── fuzzy-hash.ts
  │     ├── modes/registry.ts
  │     ├── modes/network.ts
  │     ├── modes/network-intel.ts
  │     ├── modes/games.ts
  │     ├── modes/game-memory.ts
  │     ├── modes/dma.ts
  │     ├── modes/usb-devices.ts
  │     │     ├── modes/usb/anomaly.ts
  │     │     ├── modes/usb/bandwidth.ts
  │     │     ├── modes/usb/classification.ts
  │     │     └── modes/usb/descriptors.ts
  │     ├── modes/browser.ts
  │     │     └── browser-history.ts (sql.js)
│     ├── modes/etw-amsi.ts
│     │     ├── etw-amsi-patch.ts
│     │     └── etw-provider.ts
  │     ├── modes/anti-debug.ts
  │     ├── modes/byovd.ts
  │     ├── modes/apc-detector.ts
  │     │     └── modes/apc/*.ts (7 файлов)
  │     ├── self-integrity.ts
  │     ├── self-protect.ts
  │     ├── anti-tamper.ts
  │     ├── anti-forensic.ts
  │     ├── forensic-traces.ts
  │     ├── pc-cleaner-detection.ts
  │     ├── behavior-engine.ts
  │     ├── behavior-profile.ts
  │     ├── memory-dump.ts
  │     ├── rwx-scanner.ts
  │     ├── disk-vs-memory.ts
  │     └── safe-files-db.ts
  │
  ├── system-info.ts
  ├── config.ts
  └── types.ts (ScanContext, ScanResult, утилиты)
```

---

## 6. Безопасность (Security Model)

```
Слой                     Механизм
────────────────────────────────────────────────
Транспорт        →  CORS (allowed origins) + Helmet (secure headers)
Аутентификация   →  JWT (24h expiry, HS256) + bcrypt passwords
Авторизация      →  RBAC (admin/operator/viewer) + role hierarchy
Rate Limiting    →  100 req/min global, 5 auth/15 min, WS connection limits
API Validation   →  Zod schemas (input validation на всех эндпоинтах)
SQL Injection    →  Drizzle ORM (parameterized queries)
Аудит            →  Structured audit log (X-Request-ID + admin actions)
Self-Protect     →  ACL Deny ACE, SeDebugPrivilege removal, DLL injection monitor
Anti-Debug       →  7 tiers: RE tools, HWBP, PEB scan, QPC timing
Anti-Tamper      →  SHA256 integrity baseline, INT3 patch scan, IAT DLL proxy
```

---

## 7. Ключевые метрики

| Метрика | Значение |
|---------|----------|
| Файлов (Electron main) | 41 + подмодули |
| Строк кода (Electron) | ~18,700 |
| Файлов (React renderer) | 25+ |
| Файлов (Server) | 20+ |
| Файлов (Admin) | 15+ |
| Сканер: фаз (Full) | 15 |
| Сканер: категорий угроз | 9 |
| Сканер: YARA-правил | 13 |
| Risk Scorer: сигналов | 25 |
| Anti-Debug: уровней | 7 |
| API: эндпоинтов | 30+ |
| База данных: таблиц | 7 |
| Middleware: модулей | 7 |
| Тестов (Vitest) | 243 |
| TypeScript: компонентов с 0 ошибок | 4/4 |
