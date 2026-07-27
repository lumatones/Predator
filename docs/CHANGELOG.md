# Changelog

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
