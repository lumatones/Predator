# Правила разработки Predator 🦅

> **Роль AI-агента**: Senior Software Engineer (10+ лет опыта), Security Analyst, Motion Designer, Researcher.

## 🧠 ПРИНЦИПЫ РАБОТЫ

### 1. THINK FIRST (ОБЯЗАТЕЛЬНО)
Перед каждым действием:
- Проанализируй задачу
- Определи риски
- Подумай о лучших практиках
- Только потом предлагай решение

**Никогда не пиши код сразу.**

### 2. РАБОТА ПО ЭТАПАМ (СТРОГО)
- Нельзя перескакивать этапы
- Каждый этап: доводится до идеала → проверяется → оптимизируется → документируется
- Если задача большая: разбей на подзадачи, делай по шагам, жди подтверждения

### 3. ИССЛЕДОВАНИЕ (CRITICAL)
Перед реализацией:
- Изучи документацию
- Найди лучшие практики
- Сравни подходы
- Обоснуй выбор

---

## О проекте

**Predator** — система проверки безопасности для GTA 5 RP (Majestic). Состоит из трёх компонентов:
- **Десктопное приложение** (Electron + React) — сканирует ПК пользователя в 4 режимах: Full, Quick, DMA, Cleaner
- **Backend API** (TypeScript: Node.js + Express + MySQL + Drizzle ORM) — авторизация, токены, классификация, WebSocket
- **Admin Panel** (Vite + React) — панель администратора: логин, заявки, токены, хеши, история

---

## 🧩 ТЕХНОЛОГИЧЕСКИЙ СТЕК

| Компонент          | Технология                                                     |
|-------------------|----------------------------------------------------------------|
| Desktop Frontend  | Vite + React 19 + TypeScript 5.7 + Framer Motion + Three.js (@react-three/fiber + drei) |
| Desktop Shell     | Electron 33 + Vite Plugin Electron                             |
| Backend           | Node.js + Express 4 + MySQL 8 + Drizzle ORM + JWT + bcrypt + Socket.IO + Zod |
| Admin Panel       | Vite + React 19 + TypeScript + Recharts + Radix UI             |
| Bundling          | electron-builder (portable .exe / NSIS) + GitHub Releases      |
| Auto-Updater      | electron-updater + GitHub Releases + latest.yml                |
| Scanner Engine    | 15 фаз: Processes, Heuristic, Registry, Prefetch, Network, Games, GameMemory, NetworkIntel, DMA, Browser, Behavior, AntiDebug, SelfIntegrity, RiskScorer, CloudSubmit |
| Heuristic Engine  | Shannon Entropy, YARA (13 правил), PE-анализ, TLSH fuzzy hash, API Hashing, Digital Signatures, Combo Detector |
| Memory Analysis   | MiniDumpWriteDump, RWX scanner, Disk-vs-Memory, ReadProcessMemory hooks |
| Browser History   | sql.js (WASM) — Chrome, Edge, Brave, Yandex, Opera, Opera GX   |
| Cloud Sync        | HTTP polling + WebSocket (хеши читов, safe-files whitelist)     |
| Server Services   | Auto-Classifier (rule engine + crowdsourcing), TLSH Matcher, Cheat Knowledge DB |
| Testing           | Vitest (243 теста, 9 файлов) + TypeScript strict mode           |
| Export            | HTML (Chart.js) + JSON + Markdown + PDF + Telegram             |
| UI Effects        | Particles (tsparticles), Glassmorphism, Matrix Rain, 3D (Three.js), Magnetic, Theme Engine |

---

## 📋 Процесс разработки

### 1. Сначала думаем, потом делаем
- Перед любыми изменениями — **обсуждение и согласование** с пользователем.
- Сначала предлагаю архитектуру, план, список задач.
- Только после одобрения — реализация.

### 2. Идём медленно, но верно
- Один шаг за раз. Никаких глобальных изменений без согласования.
- Каждый шаг должен быть завершён, протестирован и задокументирован.
- Если что-то пошло не так — откатываемся и обсуждаем.

### 3. Версионирование
- Текущая версия: **0.4.3**.
- После каждого завершённого блока работ → увеличение на **0.0.1**.
- Формат: `v0.0.1` → `v0.0.2` → `v0.1.0` → `v0.1.1` и т.д.
- После крупных milestone'ов → `v0.2.0`, `v1.0.0`.

### 4. Документирование
- **RULES.md** — этот файл (правила и процесс).
- **CHANGELOG.md** — краткий журнал изменений по версиям.
- **README.md** — описание проекта, инструкции.
- **DEV.md** — гайд для разработчиков.
- **REFACTORING.md** — план и прогресс рефакторинга.
- **CONTEXT.md** — предметный словарь (domain glossary).
- Каждый коммит — осмысленное сообщение на русском или английском.

### 5. Версия — в коде
- Файл `package.json` → поле `version`.
- Версия отображается в футере UI приложения.

### 6. Git-процесс
- Коммиты через пользователя (я подготавливаю, пользователь решает когда пушить).
- Сообщения коммитов: кратко, суть изменений.
- Пример: `feat: v0.4.3 — Code quality, Music Player upgrade, Finding Explainer`.

---

## 🧪 Тестирование и проверка

- TypeScript-проверка: `npm run typecheck` (electron + renderer + admin)
- Тесты: `npx vitest run` (243 теста)
- Линт: `npm run lint`
- Для UI-изменений — browser_check (если запущен dev-сервер).
- Код-ревью через code-reviewer-deepseek после значимых изменений.
- Pre-commit hook: lint-staged + tsc на staged-файлах + полный typecheck electron/server.

---

## 🎯 Принципы кода

- **Чистота**: минимум лишнего кода, переиспользование компонентов.
- **Типизация**: строгий TypeScript, без `any` без крайней необходимости.
- **UI/UX**: красивый, современный интерфейс. hover-эффекты, переходы, микроанимации.
- **Безопасность**: никаких секретов в коде, env-файлы, .gitignore, parameterized SQL queries (Drizzle ORM).
- **Модульность**: shallow modules — интерфейс ~ такой же простой как реализация.

---

## 🗺 Архитектура системы

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│                  │     │                  │     │                  │
│  PREDATOR APP    │     │   BACKEND API    │     │   ADMIN PANEL    │
│  (Electron)      │◄───►│  localhost:3001  │◄───►│  localhost:5173  │
│                  │     │                  │     │                  │
│  ┌──────────┐    │     │  ┌────────────┐  │     │  ┌──────────┐   │
│  │Токен/Запрос│   │     │  │Express 4   │  │     │  │Логин    │   │
│  │Сканер 4 мод│   │     │  │MySQL 8     │  │     │  │Dashboard│   │
│  │Auto-Updater│   │     │  │Drizzle ORM │  │     │  │Запросы  │   │
│  │Dashboard   │   │     │  │JWT + RBAC  │  │     │  │Токены   │   │
│  │Cloud Sync  │   │     │  │Socket.IO   │  │     │  │Хеши     │   │
│  │Risk Scorer │   │     │  │Classifier  │  │     │  │История  │   │
│  │Self-Protect│   │     └──────────────┘  │     └──────────┘   │
│  └──────────┘    │                              └──────────────┘
└──────────────────┘

                   ┌──────────────────────────────────────┐
                   │        SCANNER — 4 РЕЖИМА             │
                   ├────────────┬────────────┬────────────┤
                   │   FULL     │   QUICK    │    DMA     │
                   │  (15 фаз)  │  (6 фаз)   │  (PCI+HW)  │
                   │ Processes  │ Processes  │ PCI scan   │
                   │ Heuristic  │ Prefetch   │ FPGA det.  │
                   │ Registry   │ Registry   │ Drivers    │
                   │ Prefetch   │ Pipes/WMI  │ Registry   │
                   │ Network    │ Network    │ Sched.Tasks│
                   │ Games      │ Browser    │            │
                   │ GameMemory ├────────────┤            │
                   │ NetIntel   │  CLEANER   │            │
                   │ DMA        │  (4 фазы)  │            │
                   │ Browser    │ USN Journal│            │
                   │ Behavior   │ Timestomp  │            │
                   │ Anti-Debug │ ShellBags  │            │
                   │ SelfInteg. │ HWID check │            │
                   │ RiskScorer │            │            │
                   │ CloudSubmit│            │            │
                   └────────────┴────────────┴────────────┘

Desktop App Internal:
  scanner.ts ──► ScanPipeline (5 handlers)
       │              ├── SessionRecorder
       │              ├── ShadowSubmitter
       │              ├── AutoWhitelister
       │              ├── HashSubmitter
       │              └── ResultUploader
       │
       ├──► Signature Registry (data + hit counters + pruning)
       │       ├── SUSPICIOUS_CATEGORIES (9)
       │       ├── ALL_CHEAT_KEYWORDS (~200)
       │       └── SUSPICIOUS_PATTERNS (60+ regex)
       │
       ├──► Behavior Engine (cross-process correlation, attack chains)
       ├──► Risk Scorer (25 signals, log-scale, device fingerprint)
       ├──► Anti-Debug (7 tiers) + Self-Protect + Self-Integrity
       ├──► Game Memory + Network Intel + USB Anomaly
       └──► Scan Scheduler (incremental + periodic)
```

---

## 🔌 API Endpoints

### Auth (публичные, без JWT)

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/auth/token` | Проверить 32-символьный токен |
| POST | `/api/auth/token/use` | Активировать токен (привязка к ПК) |
| POST | `/api/auth/request` | Создать запрос на доступ |
| GET | `/api/auth/status/:id` | Статус запроса (polling) |
| POST | `/api/auth/submit-scan` | Отправить результаты сканирования |
| POST | `/api/auth/submit-hashes` | Отправить SHA256/TLSH хеши файлов |
| POST | `/api/auth/submit-safe-files` | Отправить safe-file записи (комьюнити) |
| POST | `/api/auth/submit-shadow` | Отправить shadow-mode телеметрию |
| GET | `/api/auth/fetch-hashes` | Облачная синхронизация хешей читов |
| GET | `/api/auth/safe-hashes` | Список подтверждённых безопасных хешей |
| GET | `/api/auth/safe-files` | Комьюнити-whitelist (safe_files) |
| GET | `/api/health` | Health check |

### Admin (требуется JWT + RBAC)

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/admin/login` | Вход администратора (rate-limited: 5/15min) |
| GET | `/api/admin/pending` | Ожидающие запросы (пагинация) |
| POST | `/api/admin/approve/:id` | Одобрить запрос |
| POST | `/api/admin/approve-batch` | Массовое одобрение (до 100) |
| POST | `/api/admin/reject/:id` | Отклонить запрос |
| POST | `/api/admin/reject-batch` | Массовое отклонение (до 100) |
| POST | `/api/admin/tokens/generate` | Создать токены (1–10) |
| GET | `/api/admin/tokens` | Список токенов |
| POST | `/api/admin/tokens/revoke/:id` | Отозвать токен |
| GET | `/api/admin/history` | История событий (пагинация) |
| GET | `/api/admin/scan-stats` | Статистика сканирований |
| GET | `/api/admin/suspicious-hashes` | База подозрительных хешей |
| POST | `/api/admin/hashes/approve/:id` | Подтвердить хеш как чит |
| POST | `/api/admin/hashes/reject/:id` | Отклонить хеш |
| POST | `/api/admin/hashes/confirm-from-scan` | Подтвердить хеш из результатов скана |
| GET | `/api/admin/scan-result-hashes` | Хеши из JSON результатов сканов |
| GET | `/api/admin/safe-files-stats` | Статистика комьюнити-whitelist |
| GET | `/api/admin/shadow-findings` | Shadow-mode находки (телеметрия) |
| POST | `/api/admin/shadow/promote` | Продвинуть shadow-правило в production |

### API v1 (рекомендуемые)

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/signatures` | Горячая загрузка сигнатур читов |
| GET | `/api/v1/stats` | Публичная статистика |
| POST | `/api/v1/signatures/refresh` | Принудительный bump версии сигнатур |

### WebSocket

| Комната | Аутентификация | Назначение |
|---------|---------------|------------|
| `scanner` | Токен (опционально) | Real-time обновления для сканера |
| `admin` | JWT (обязательно) | Real-time админ-уведомления |

### Server Middleware

| Middleware | Назначение |
|------------|------------|
| `auth.ts` | JWT-верификация для админ-роутов |
| `roles.ts` | RBAC: admin / operator / viewer |
| `rate-limit-login.ts` | 5 попыток / 15 мин, блокировка после 10 |
| `request-id.ts` | X-Request-ID propagation |
| `audit-log.ts` | Структурированное логирование действий |
| `metrics.ts` | Prometheus-метрики (сканы, хеши, токены) |
| `ws-auth.ts` | JWT + connection rate limiting для WebSocket |

---

## 📁 Структура проекта

```
Predator/
├── package.json              # Основное приложение (Electron + React)
├── vite.config.ts            # Vite + electron плагины
├── tsconfig.json             # TypeScript конфиг (renderer)
├── tsconfig.electron.json    # TypeScript конфиг (main process)
├── vitest.config.ts          # Vitest конфиг
├── index.html                # HTML entry
│
├── electron/                 # Electron main process (41 файл + подмодули)
│   ├── main.ts               # Главный процесс + auto-updater + IPC + tray
│   ├── preload.ts            # contextBridge API
│   ├── config.ts             # Конфиг (API URL, CFG пути, тема, язык)
│   ├── constants.ts          # Константы (игровые пути, модули, платформы)
│   ├── types.ts              # ScanContext, ScanResult, ScanProgress, parsePsJson, execCmd
│   ├── scanner.ts            # Оркестратор + IPC handlers (start-scan, cancel-scan)
│   ├── heuristic.ts          # Эвристический barrel: entropy, PE, сигнатуры, YARA
│   ├── heuristic/            # Декомпозированные модули эвристики (7 файлов)
│   │   ├── constants.ts      # SUSPICIOUS_EXTENSIONS, SCAN_CONFIG, PROTECTED_PATHS
│   │   ├── name-matcher.ts   # matchKnownCheat, riskScoreToLevel, getFileRiskLevel
│   │   ├── combo-detector.ts # comboScoreUnsignedBinary
│   │   ├── signature-batch.ts # batchCheckSignatures, checkDigitalSignature
│   │   ├── masquerading.ts   # checkMasqueradingExecutable
│   │   ├── archive-scan.ts   # scanArchiveContents
│   │   └── cheat-names.ts    # PROC_BASES, FILE_NAMES, LUA_NAMES, FOLDER_NAMES
│   ├── cheat-rules.ts        # YARA-правила (13) + Whitelist + PE-анализ
│   ├── cheats-db.ts          # База сигнатур читов + MASQUERADING_SYSTEM_TOOLS
│   ├── signature-registry.ts # Единый источник сигнатур + hit counters + pruning
│   ├── auto-yara.ts          # Самообучающиеся YARA-правила v2 (Unicode/TLSH/decay)
│   ├── fuzzy-hash.ts         # TLSH fuzzy hash DB (persistent + prefix trie)
│   ├── risk-scorer.ts        # 25 взвешенных категорий, лог-шкала, эскалация
│   ├── behavior-engine.ts    # Кросс-процессная корреляция, цепочки атак
│   ├── behavior-profile.ts   # Поведенческое профилирование процессов
│   ├── scan-pipeline.ts      # Композируемые post-scan handler'ы (5 этапов)
│   ├── scan-scheduler.ts     # Периодические + инкрементальные сканы
│   ├── cloud-sync.ts         # HTTP polling + WebSocket синхронизация хешей
│   ├── telemetry-queue.ts    # Надёжная очередь доставки результатов
│   ├── persistent-profile.ts # Накопительный скоринг между сессиями
│   ├── safe-files-db.ts      # Локальная БД безопасных файлов + синхронизация
│   ├── signature-watcher.ts  # File watcher для горячей перезагрузки сигнатур
│   ├── result-grouper.ts     # Группировка результатов + фильтр шума
│   ├── self-integrity.ts     # SHA256 baseline, INT3 patch scan, IAT proxy
│   ├── self-protect.ts       # ACL Deny ACE, BreakOnTermination, SeDebugPrivilege
│   ├── memory-dump.ts        # MiniDumpWriteDump + анализ строк
│   ├── api-hashing.ts        # API Hashing / PEB walking detection
│   ├── etw-amsi-patch.ts     # AMSI/ETW tampering detection
│   ├── etw-provider.ts       # ETW kernel provider
│   ├── rwx-scanner.ts        # RWX memory regions + thread analysis
│   ├── disk-vs-memory.ts     # Inline hook detection (disk vs memory)
│   ├── anti-tamper.ts        # Anti-tampering checks
│   ├── anti-forensic.ts      # Anti-forensic detection (очистка логов)
│   ├── forensic-traces.ts    # Prefetch, Amcache, BAM, UserAssist
│   ├── browser-history.ts    # SQLite парсер: Chrome, Edge, Brave, Yandex, Opera, Opera GX
│   ├── system-info.ts        # Системный дашборд (CPU/RAM/процессы)
│   ├── native-hv-detect.ts   # Обнаружение гипервизоров
│   ├── pc-cleaner-detection.ts # Обнаружение чистильщиков ПК
│   ├── ipc-handlers.ts       # IPC handlers: config, PC name, tray
│   ├── ipc-handlers-scan.ts  # IPC handler: cancel-scan
│   ├── analysis/             # Аналитические утилиты
│   │   ├── entropy.ts        # Shannon entropy calculation
│   │   └── strings.ts        # String extraction
│   ├── modes/                # Режимы сканирования
│   │   ├── anti-debug.ts     # 7 уровней анти-отладки
│   │   ├── browser.ts        # История браузера
│   │   ├── byovd.ts          # BYOVD driver detection
│   │   ├── dma.ts            # DMA/FPGA устройства
│   │   ├── etw-amsi.ts       # ETW/AMSI hooks
│   │   ├── files.ts          # Сканирование файлов
│   │   ├── game-memory.ts    # ReadProcessMemory + CEF debug ports
│   │   ├── games.ts          # Игровые процессы + модули
│   │   ├── network.ts        # Netstat, DNS, hosts
│   │   ├── network-intel.ts  # C2 patterns, VPN/proxy, suspicious DNS
│   │   ├── processes.ts      # Процессы + WMI persistence
│   │   ├── registry.ts       # Реестр (9 категорий)
│   │   ├── usb-devices.ts    # USB устройства
│   │   ├── apc-detector.ts   # APC injection detection
│   │   ├── apc/              # APC sub-modules (7 файлов)
│   │   ├── process/          # Process sub-modules (behavioral, enumeration, pipes-wmi)
│   │   └── usb/              # USB sub-modules (anomaly, bandwidth, classification, descriptors)
│   ├── scanner/              # Scan mode functions
│   │   ├── full-scan.ts      # runFullScan (15 фаз)
│   │   ├── quick-scan.ts     # runQuickScan (6 фаз)
│   │   └── cleaner-scan.ts   # runCleanerScan (4 фазы)
│   ├── utils/                # Утилиты
│   │   ├── exec.ts           # execPowerShell, execWithTimeout (безопасные обёртки)
│   │   └── safe-spread.ts    # Безопасный спред массивов
│   ├── workers/              # Worker pool
│   │   └── worker-pool.ts
│   └── __tests__/            # Тесты (9 файлов, 243 теста)
│       ├── heuristic.test.ts
│       ├── heuristic-extended.test.ts
│       ├── heuristic-file-scan.test.ts
│       ├── fuzzy-hash.test.ts
│       ├── ipc-handlers.test.ts
│       ├── risk-scorer.test.ts
│       ├── scan-pipeline.test.ts
│       ├── signature-effectiveness.test.ts
│       └── signature-registry.test.ts
│
├── src/                      # React-фронтенд (renderer)
│   ├── main.tsx              # React entry
│   ├── App.tsx               # Онбординг, авторизация, маршрутизация
│   ├── App.css               # Стили (тёмная тема, анимации, glassmorphism)
│   ├── api.ts                # HTTP клиент + offline queue + retry
│   ├── pages/
│   │   ├── Checker.tsx       # Экран сканирования (4 таба, live terminal, grouped results)
│   │   └── Dashboard.tsx     # Системный дашборд (CPU/RAM/GPU/процессы)
│   ├── components/
│   │   ├── ErrorBoundary.tsx # Обработка ошибок React
│   │   ├── ServerStatus.tsx  # Индикатор сервера
│   │   ├── onboarding/       # Онбординг flow (Welcome, DemoScan)
│   │   └── ui/               # UI-компоненты (20+ файлов)
│   │       ├── Button.tsx, Tooltip.tsx, Toast.tsx, ToastProvider.tsx
│   │       ├── Skeleton.tsx, Magnetic.tsx, GlassEye.tsx
│   │       ├── PredatorLogo3D.tsx, ParticleBackground.tsx, MatrixRain.tsx
│   │       ├── ScanTerminal.tsx, CompactScanOverlay.tsx, FileDetailModal.tsx
│   │       ├── ThreatMap.tsx, ApcDashboard.tsx, SettingsPanel.tsx
│   │       ├── MusicPlayer.tsx, MiniPlayer.tsx, AnimatedIcons.tsx
│   │       ├── ThemeBurnTransition.tsx, UpdateModal.tsx, ServerStatus.tsx
│   ├── hooks/                # React hooks
│   │   ├── useAuth.ts, useScan.ts, useSound.ts, useToast.ts
│   │   ├── useThemeEngine.ts, useMusicPlayer.ts, useMagnetic.ts
│   │   ├── useOnboarding.ts, useUpdateManager.ts
│   ├── icons/                # 14 SVG-иконок (IconShield, IconFolder, etc.)
│   ├── styles/               # CSS-стили (checker, components, dashboard, layout, tokens)
│   ├── services/             # Сервисы (music-sources.ts)
│   ├── utils/                # Утилиты (export-report, result-grouper, finding-explainer, webgl)
│   └── types/                # Типы (electron.d.ts, music.ts)
│
├── admin/                    # Админ-панель (Vite + React)
│   ├── package.json
│   └── src/
│       ├── App.tsx           # AuthContext + Router
│       ├── api.ts            # HTTP клиент
│       ├── components/       # Layout, AnimatedNumber, CommandPalette, Confetti и др.
│       ├── hooks/            # useFocusTrap, useKeyboardShortcuts, useSessionTimeout
│       └── pages/            # Login, Dashboard, Pending, Tokens, History, SafeFiles, SuspiciousHashes
│
├── server/                   # Backend API (Express + MySQL + Drizzle ORM)
│   ├── package.json
│   └── src/
│       ├── index.ts          # Express сервер (:3001) + Socket.IO + graceful shutdown
│       ├── config/
│       │   └── database.ts   # MySQL connection pool + testConnection
│       ├── db/
│       │   ├── schema.ts     # Drizzle ORM schema
│       │   ├── init.ts       # Database initializer
│       │   └── schema.sql    # Raw SQL schema
│       ├── middleware/
│       │   ├── auth.ts       # JWT verification
│       │   ├── roles.ts      # RBAC: admin/operator/viewer
│       │   ├── rate-limit-login.ts # 5/15min + account lockout
│       │   ├── request-id.ts # X-Request-ID propagation
│       │   ├── audit-log.ts  # Structured audit logging
│       │   ├── metrics.ts    # Prometheus metrics
│       │   └── ws-auth.ts    # WebSocket JWT auth + connection limiting
│       ├── routes/
│       │   ├── auth.ts       # Token, request, submit-scan/hashes/shadow/safe-files
│       │   ├── admin.ts      # Login, pending, tokens, hashes, stats
│       │   └── v1.ts         # API v1: signatures, stats, health
│       ├── services/
│       │   ├── classifier.ts # Auto-classifier (rule engine + crowdsourcing)
│       │   ├── tlsh-matcher.ts # TLSH matching engine
│       │   └── cheat-knowledge.ts # Cheat knowledge base
│       ├── helpers/
│       │   ├── errors.ts     # Error codes
│       │   └── pagination.ts # Cursor-based + offset pagination
│       ├── shared-types.ts   # Zod schemas + TypeScript types
│       └── __tests__/        # Тесты (5 файлов)
│
├── installer/                # Установщик (Electron + glassmorphism)
├── scripts/                  # Вспомогательные скрипты
│   ├── release.js            # Единый скрипт релиза (typecheck→build→yml→upload)
│   ├── generate-latest-yml.js
│   ├── upload-release.js
│   ├── generate-resources.js
│   ├── test-cheat-detect.ts
│   └── monitor-cheat.ps1
│
└── .github/workflows/
    ├── ci.yml                # CI: typecheck + build + lint
    └── release.yml           # Auto-release при пуше тега v*
```

---

## 🗺 Текущий статус

**Версия:** 0.4.3
**Релиз:** v0.4.3 на GitHub

### ✅ Что сделано (ключевые вехи)

| Версия | Что добавлено |
|--------|--------------|
| 0.0.1–0.0.10 | Vite + React + Electron, базовый UI, установщик, бэкенд, GitHub Actions, сетевой режим, автоапдейт, сканер v3.0 (YARA + PE + whitelist) |
| 0.0.11–0.0.15 | WebSocket, JWT-защита, browser history (sql.js), Auto-YARA, Memory Dumper, ETW/AMSI Patch, SVG-дизайн-система (14 иконок) |
| 0.0.16–0.0.21 | Группы риска, ErrorBoundary, Vitest тесты, рефакторинг (ScanContext, parsePsJson, CFG, cloud-sync), CI fix |
| 0.1.14 | ScanPipeline (5 handlers), Signature Registry (единый источник + hit counters), MASQUERADING_SYSTEM_TOOLS |
| 0.4.0 | **Massive update**: 43 задачи, 7 фаз, 28 файлов, 243 теста. Anti-Debug (7 tiers), Self-Protect/Self-Integrity, Game Memory, Network Intel, USB Anomaly, Behavior Engine, Risk Scorer (25 сигналов), Persistent Profiles, Fuzzy Hash v2 (persistent TLSH DB), Auto-YARA v2, Signature Effectiveness, Incremental Scan, Scan Scheduler, Hot-Reload Signatures, Admin Upgrades (Hash Detail, Session Timeout, Keyboard Shortcuts, WebSocket Auth), Server Hardening (Drizzle ORM, RBAC, Rate-Limit, Request ID, Audit Log, Pagination) |
| 0.4.1 | Music Player, Server-side Hash Verify, API fix |
| 0.4.2 | Eye animations, CMD terminal removal |
| 0.4.3 | Code quality, Music Player upgrade, Finding Explainer, Cheat Grouping v2 |

### 🔬 Сканер (4 режима)

**Full Scan — 15 фаз:**
1. Self-integrity (SHA256 baseline, INT3 patch scan, IAT DLL proxy)
2. Process scanning (DLL modules, cheat signatures, masquerading)
3. Heuristic file analysis (entropy, YARA, PE headers, digital signatures, TLSH, API hashing)
4. Registry deep scan (Run/RunOnce, Services, Winlogon — 9 категорий)
5. Prefetch analysis (execution history)
6. System integration (network, game integrity, masquerading, pipes, WMI, AMSI/ETW, behavior, RWX, disk-vs-memory)
7. Game memory (ReadProcessMemory hooks, CEF debug ports, aimbot/ESP patterns)
8. Network intel (C2 patterns, proxy/VPN detection, suspicious DNS)
9. DMA detection (PCI devices, firmware fingerprinting, USB anomaly)
10. Registry cheat scan (8 registry paths)
11. Browser history (SQLite: Chrome, Edge, Brave, Yandex, Opera, Opera GX)
12. Behavior analysis (cross-process correlation, attack chain detection)
13. Anti-debug (7 tiers: RE tools, HWBP, ProcessDebugPort, PEB, parent, QPC timing)
14. Anti-tamper (integrity verification, debugger detection)
15. Cloud submission (SHA256 + TLSH hashes → backend)

**Quick Scan — 6 фаз:** Processes, Prefetch, Registry, Named Pipes, Network, Browser History

**DMA Devices — PCI + FPGA:** PCI hardware, drivers, USB-FPGA bridges, registry, scheduled tasks

**Cleaner Detection — 4 фазы:** USN Journal, Timestomping, ShellBags, HWID changes

### 🎯 Категории подозрительного ПО (9 категорий)

Движок сигнатур (`signature-registry.ts`) классифицирует находки по 9 категориям:

| Категория | Описание | Риск | Примеры сигнатур |
|-----------|----------|------|------------------|
| **injector** | DLL-инжекторы, code injection | 🔴 CRITICAL | `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx` |
| **debugger** | Отладчики / Cheat Engine / x64dbg | 🔴 CRITICAL | `IsDebuggerPresent`, `NtQueryInformationProcess` |
| **hook** | Хуки системных функций | 🟠 HIGH | `SetWindowsHookEx`, `DetourAttach`, `MinHook` |
| **driver** | Kernel-драйверы | 🔴 CRITICAL | `IoCreateDevice`, `PsSetCreateProcessNotifyRoutine` |
| **spoofer** | Подмена HWID/MAC/DiskSerial | 🟠 HIGH | `HardwareID`, `SMBIOS`, `MACAddress` |
| **bypass** | Обход античит-защит | 🔴 CRITICAL | `bypass`, `evade`, `anti-cheat` |
| **menu** | Игровые меню/оверлеи | 🟠 HIGH | `ImGui`, `Direct3D`, `overlay`, `aimbot` |
| **network** | Прокси/VPN/снифферы | 🟡 MEDIUM | `WSASocket`, `socks`, `proxy` |
| **obfuscator** | Упаковщики (VMProtect, Themida) | 🟠 HIGH | `VMProtect`, `Themida`, `Enigma`, `Obsidium` |

### 🔧 Технические компоненты

- ✅ **ScanContext (`ctx`)** — изолированное состояние между сканами (кеши, dedup)
- ✅ **ScanPipeline** — композируемые post-scan handler'ы (5 этапов)
- ✅ **Signature Registry** — единый источник сигнатур + hit counters + pruning
- ✅ **parsePsJson<T>()** — безопасный парсинг PowerShell JSON
- ✅ **execPowerShell / execWithTimeout** — типобезопасные обёртки над child_process
- ✅ **Cloud Sync** — HTTP polling + WebSocket, горячая загрузка сигнатур
- ✅ **Auto-Updater** — проверка при запуске + каждые 5 мин
- ✅ **Экспорт отчётов** — HTML + JSON + Markdown + PDF + Telegram
- ✅ **System Dashboard** — CPU, RAM, GPU, процессы (streaming)
- ✅ **Фильтр результатов** — поиск в реальном времени + группы риска
- ✅ **Staggered анимации** — Framer Motion, строки, бейджи, иконки
- ✅ **Backend** — Express + MySQL + Drizzle ORM, JWT + RBAC, bcrypt, Socket.IO, Zod
- ✅ **Admin Panel** — логин, заявки, токены, хеши, история, статистика, safe-files
- ✅ **Browser History** — sql.js парсер: Chrome, Edge, Brave, Yandex, Opera, Opera GX
- ✅ **Heuristic Engine** — 7 модулей: entropy, name-match, combo, signature, masquerading, archive, constants
- ✅ **Memory Analysis** — MiniDump, RWX scanner, Disk-vs-Memory
- ✅ **Auto-YARA v2** — Unicode/UTF-16LE, TLSH clustering, Jaccard, confidence decay
- ✅ **ETW/AMSI Detection** — byte pattern search в process memory
- ✅ **SVG Icon System** — 14 иконок с idle-анимациями
- ✅ **Vitest** — 243 теста в 9 файлах
- ✅ **Risk Scorer** — 25 взвешенных сигналов, лог-шкала, device fingerprint
- ✅ **Persistent Profiles** — кросс-сессионная эскалация риска
- ✅ **Server Auto-Classifier** — rule engine + crowdsourcing
- ✅ **TLSH Matcher** — prefix trie, размерозависимые пороги
- ✅ **Shadow Rules** — тихий режим для новых сигнатур (телеметрия без флагов)
- ✅ **Offline Queue** — telemetry-queue для надёжной доставки
- ✅ **Self-Protect** — ACL Deny ACE, BreakOnTermination, SeDebugPrivilege removal

### 📋 В планах

- 🧪 Расширение тестового покрытия (интеграционные тесты)
- 📊 Больше графиков в Dashboard админ-панели
- 🌍 Локализация (RU/EN) — в процессе
- 🔄 Завершение миграции execSync → execPowerShell во всех модулях
- 📝 Актуализация docs/DEV.md и docs/REFACTORING.md
