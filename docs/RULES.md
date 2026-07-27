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

**Predator** — система проверки безопасности для GTA 5 RP (Majestic). Состоит из четырёх компонентов:
- **Десктопное приложение** (Electron + React) — сканирует ПК пользователя (6 режимов), проверяет файлы, процессы, реестр, DMA, сеть, Prefetch, историю браузера
- **Installer** (Electron) — премиальный установщик с glassmorphism-дизайном
- **Backend API** (ES Module: Node.js + Express + MySQL) — авторизация, управление токенами, запросы на доступ
- **Admin Site** (Vite + React) — панель администратора: логин, заявки, токены, история

---

## 🧩 ТЕХНОЛОГИЧЕСКИЙ СТЕК

| Компонент          | Технология                                                    |
|-------------------|----------------------------------------------------------------|
| Desktop Frontend  | Vite + React 19 + TypeScript 5.7 + Framer Motion + Three.js    |
| Desktop Shell     | Electron 33 + Vite Plugin Electron                             |
| Backend           | Node.js + Express 4 + MySQL 8 + JWT + bcrypt + Socket.IO       |
| Admin Site        | Vite + React 19 + React Router 7 + TypeScript + Chart.js       |
| Bundling          | electron-builder (portable .exe) + GitHub Releases             |
| Auto-Updater      | electron-updater + GitHub Releases + latest.yml                |
| Scanner Engine    | 9 категорий угроз, YARA, PE-анализ, энтропия Шеннона, TLSH     |
| Heuristic Engine  | API Hashing, PEB Walking, Masquerading, Behavioral detection   |
| Memory Analysis   | MiniDumpWriteDump, RWX scanner, Disk-vs-Memory                 |
| Browser History   | sql.js (WASM) — Chrome, Edge, Brave, Yandex, Opera, Opera GX  |
| Cloud Sync        | HTTP polling + WebSocket fallback (хеши читов)                 |
| Testing           | Vitest (unit) + TypeScript strict mode                         |
| Export            | HTML (Chart.js) + JSON + Markdown + Telegram                   |
| UI Effects        | Particles (tsparticles), Glassmorphism, Matrix Rain, 3D (Three.js) |

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
- Текущая версия: **0.1.14**.
- После каждого завершённого блока работ → увеличение на **0.0.1**.
- Формат: `v0.0.1` → `v0.0.2` → `v0.1.0` → `v0.1.1` и т.д.
- После крупных milestone'ов → `v0.2.0`, `v1.0.0`.

### 4. Документирование
- **RULES.md** — этот файл (правила и процесс).
- **CHANGELOG.md** — краткий журнал изменений по версиям.
- **README.md** — описание проекта, инструкции.
- **DEV.md** — гайд для разработчиков.
- **REFACTORING.md** — план и прогресс рефакторинга.
- Каждый коммит — осмысленное сообщение на русском или английском.

### 5. Версия — в коде
- Файл `package.json` → поле `version`.
- Версия отображается в футере UI приложения.

### 6. Git-процесс
- Коммиты через пользователя (я подготавливаю, пользователь решает когда пушить).
- Сообщения коммитов: кратко, суть изменений.
- Пример: `v0.0.21 — Рефакторинг, типизация, новый релизный скрипт`.

---

## 🧪 Тестирование и проверка

- После каждого изменения запускаю TypeScript-проверку (`npx tsc --noEmit`) или сборку (`npm run build`).
- Тесты: `npx vitest run`
- Для UI-изменений — browser_check (если запущен dev-сервер).
- Код-ревью через code-reviewer-deepseek после значимых изменений.

---

## 🎯 Принципы кода

- **Чистота**: минимум лишнего кода, переиспользование компонентов.
- **Типизация**: строгий TypeScript, без `any` без крайней необходимости.
- **UI/UX**: красивый, современный интерфейс. hover-эффекты, переходы, микроанимации.
- **Безопасность**: никаких секретов в коде, env-файлы, .gitignore, parameterized SQL queries.

---

## 🗺 Архитектура системы

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│                  │     │                  │     │                  │
│  PREDATOR APP    │     │   BACKEND API    │     │   ADMIN SITE     │
│  (Electron)      │◄───►│  localhost:3001  │◄───►│  localhost:5173  │
│                  │     │                  │     │                  │
│  ┌──────────┐    │     │  ┌────────────┐  │     │  ┌──────────┐   │
│  │Токен/Запрос│   │     │  │Express 4   │  │     │  │Логин    │   │
│  │Сканер     │    │     │  │MySQL 8     │  │     │  │Dashboard│   │
│  │Auto-Updater│   │     │  │JWT Auth    │  │     │  │Запросы  │   │
│  │Дашборд    │    │     │  │bcrypt      │  │     │  │Токены   │   │
│  │Cloud Sync │    │     │  │Socket.IO   │  │     │  │История  │   │
│  └──────────┘    │     └──────────────┘  │     └──────────┘   │
└──────────────────┘                              └──────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     SCANNER — 6 РЕЖИМОВ                          │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│  Файлы   │Процессы  │  Читы    │   DMA    │Расширен.│   Сеть   │
│  📁      │   ⚙️     │   🎯     │   🔌     │   🛡️    │   🌐     │
│ .exe/.dll│ tasklist │Nightfall │ Xilinx   │YARA+PE+ │ DNS-кеш  │
│ .asi/.lua│ Prefetch │0XCheat   │ Altera   │Энтропия │ hosts    │
│ .js/.ahk │ Browser  │1337 Cheat│ FTDI     │+Подпись │ netstat  │
│ .sys/.drv│ Registry │Noleet    │ Leechеch │+Реестр  │ IP-пат-  │
│  ...     │ AMSI/ETW │          │          │+Prefetch│ терны    │
└──────────┴──────────┴──────────┴──────────┴──────────┴──────────┘
```

---

## 🔌 API Endpoints

### Auth (публичные, без JWT)
| Метод | Путь | Описание |
|-------|------|----------|
| POST  | `/api/auth/token` | Проверить 32-символьный токен |
| POST  | `/api/auth/token/use` | Проверить и использовать токен |
| POST  | `/api/auth/request` | Создать запрос на доступ (имя ПК) |
| GET   | `/api/auth/status/:id` | Статус запроса (polling) |
| POST  | `/api/auth/submit-scan` | Отправить результаты сканирования |
| GET   | `/api/auth/fetch-hashes` | Облачная синхронизация хешей читов |
| GET   | `/api/health` | Health check |

### Admin (требуется JWT)
| Метод | Путь | Описание |
|-------|------|----------|
| POST  | `/api/admin/login` | Вход администратора |
| GET   | `/api/admin/pending` | Ожидающие запросы |
| POST  | `/api/admin/approve/:id` | Одобрить запрос |
| POST  | `/api/admin/reject/:id` | Отклонить |
| POST  | `/api/admin/tokens/generate` | Создать токены (1–10) |
| GET   | `/api/admin/tokens` | Список токенов |
| POST  | `/api/admin/tokens/revoke/:id` | Отозвать токен |
| GET   | `/api/admin/history` | История событий |
| GET   | `/api/admin/scan-stats` | Статистика сканирований |

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
├── electron/                 # Electron main process (20 файлов)
│   ├── main.ts               # Главный процесс + auto-updater + IPC
│   ├── preload.ts            # contextBridge API
│   ├── config.ts             # Конфиг (API URL, CFG пути, тема, язык)
│   ├── constants.ts          # Константы (чит-неймы, ключевые слова, пути)
│   ├── cloud-sync.ts         # Облачная синхронизация хешей читов
│   ├── scanner.ts            # Оркестратор сканирования + IPC handlers
│   ├── types.ts              # Типы + ScanContext + parsePsJson + утилиты
│   ├── heuristic.ts          # Эвристический анализ: PE, энтропия, сигнатуры, YARA
│   ├── cheat-rules.ts        # YARA-правила + Whitelist + PE-анализ
│   ├── cheats-db.ts          # База сигнатур читов (процессы, файлы, lua, папки, хеши)
│   ├── auto-yara.ts          # Самообучающиеся YARA-правила
│   ├── memory-dump.ts        # MiniDumpWriteDump + анализ строк
│   ├── api-hashing.ts        # API Hashing / PEB walking detection
│   ├── etw-amsi-patch.ts     # AMSI/ETW tampering detection
│   ├── rwx-scanner.ts        # RWX memory regions + thread analysis
│   ├── disk-vs-memory.ts     # Inline hook detection (disk vs memory)
│   ├── behavior-profile.ts   # Process behavior profiling
│   ├── browser-history.ts    # SQLite парсер истории браузера
│   ├── system-info.ts        # Системный дашборд (CPU/RAM)
│   ├── modes/                # Режимы сканирования
│   │   ├── browser.ts        # История браузера
│   │   ├── dma.ts            # DMA-устройства + scheduled tasks
│   │   ├── files.ts          # Сканирование файлов
│   │   ├── games.ts          # Игровые процессы + модули
│   │   ├── network.ts        # Сетевые соединения
│   │   ├── processes.ts      # Процессы + WMI persistence
│   │   └── registry.ts       # Реестр
│   └── __tests__/
│       └── heuristic.test.ts # Тесты эвристики
│
├── src/                      # React-фронтенд
│   ├── main.tsx              # React entry
│   ├── App.tsx               # Онбординг, авторизация, маршрутизация
│   ├── App.css               # Стили (тёмная тема, анимации, glassmorphism)
│   ├── api.ts                # HTTP клиент для бэкенда
│   ├── pages/
│   │   ├── Checker.tsx       # Экран сканирования (6 табов, анимации, фильтр, экспорт)
│   │   └── Dashboard.tsx     # Дашборд системы (CPU/RAM/процессы)
│   ├── components/
│   │   ├── ErrorBoundary.tsx # Обработка ошибок React
│   │   └── ServerStatus.tsx  # Индикатор сервера
│   ├── utils/
│   │   └── export-report.ts  # Экспорт HTML (Chart.js) + JSON отчётов
│   └── icons/                # 14 SVG-иконок
│
├── admin/                    # Админ-панель (Vite + React)
│   ├── package.json
│   └── src/
│       ├── App.tsx           # AuthContext + Router
│       ├── api.ts            # HTTP клиент
│       ├── components/
│       │   └── Layout.tsx    # Sidebar навигация
│       └── pages/
│           ├── Login.tsx, Dashboard.tsx, Pending.tsx,
│           ├── Tokens.tsx, History.tsx, SuspiciousHashes.tsx
│
├── server/                   # Backend API (Express + MySQL)
│   ├── package.json
│   └── src/
│       ├── index.js          # Express сервер (:3001) + Socket.IO
│       ├── config/database.js
│       ├── db/init.js + schema.sql
│       ├── middleware/auth.js
│       └── routes/auth.js + admin.js
│
├── installer/                # Установщик (Electron + glassmorphism)
├── scripts/                  # Вспомогательные скрипты
│   ├── release.js            # Единый скрипт релиза (typecheck→build→yml→upload)
│   ├── generate-latest-yml.js
│   ├── upload-release.js
│   ├── generate-resources.js
│   └── monitor-cheat.ps1
│
└── .github/workflows/
    ├── ci.yml                # CI: typecheck + build + lint
    └── release.yml           # Auto-release при пуше тега v*
```

---

## 🗺 Текущий статус

**Версия:** 0.1.14
**Релиз:** v0.1.14 на GitHub

### ✅ Что сделано

| Версия | Что добавлено |
|--------|--------------|
| 0.0.1–0.0.3 | Vite + React + Electron, базовый UI, установщик, бэкенд |
| 0.0.4–0.0.5 | Интеграция с бэкендом, чекер, GitHub Actions |
| 0.0.6–0.0.7 | Системный дашборд, статистика |
| 0.0.8–0.0.10 | Сетевой режим, автоапдейт, сканер v3.0 (YARA + PE + whitelist) |
| 0.0.11 | WebSocket, JWT-защита submit-scan, графики, browser history (sql.js) |
| 0.0.12 | Auto-YARA, Memory Dumper, ETW/AMSI Patch Detector |
| 0.0.13 | Фиксы rwx-scanner, tsconfig, IPC |
| 0.0.14 | React UI fixes + server security hardening |
| 0.0.15 | SVG-дизайн-система (14 иконок, idle-анимации) |
| 0.0.16 | Баг-фиксы (safeSpread), группы риска, анимация строк |
| 0.0.17–0.0.18 | Layout fix, ErrorBoundary, удаление Statistics |
| 0.0.19 | Vitest тесты, API_BASE env var, сканер на модули |
| 0.0.20 | CI typecheck fix (10 ошибок) |
| 0.0.21 | Рефакторинг: ScanContext, parsePsJson, CFG, constants, cloud-sync, типизация |
| 0.1.14 | **ScanPipeline** (композируемые post-scan handler'ы), **Signature Registry** (единый источник сигнатур), **MASQUERADING_SYSTEM_TOOLS** (поведенческий детект без FP), Falcon Sandbox интеграция |

### 🔬 Сканер (6 режимов)

**9 категорий подозрительного ПО:**
| Категория | Описание | Риск |
|-----------|----------|------|
| injector | DLL-инжекторы | 🔴 CRITICAL |
| debugger | Отладчики / Cheat Engine | 🔴 CRITICAL |
| hook | Хуки системных функций | 🟠 HIGH |
| driver | Kernel-драйверы | 🔴 CRITICAL |
| spoofer | Подмена HWID/MAC | 🟠 HIGH |
| bypass | Обход защит | 🔴 CRITICAL |
| menu | Игровые меню/оверлеи | 🟠 HIGH |
| network | Прокси/VPN/снифферы | 🟡 MEDIUM |
| obfuscator | Упаковщики (VMProtect и др.) | 🟠 HIGH |

### 🔧 Технические компоненты

- ✅ **ScanContext** — изолированное состояние между сканами (`ctx`)
- ✅ **parsePsJson<T>()** — безопасный парсинг PowerShell JSON
- ✅ **CFG** — единый источник системных путей
- ✅ **Cloud Sync** — синхронизация хешей читов с бэкенда
- ✅ **Auto-Updater** — проверка при запуске + каждые 5 мин
- ✅ **Экспорт отчётов** — HTML (Chart.js) + JSON
- ✅ **Дашборд** — CPU, RAM, процессы
- ✅ **Фильтр результатов** — поиск в реальном времени
- ✅ **Staggered анимации** — строки, бейджи, иконки
- ✅ **Backend** — Express + MySQL, JWT, bcrypt, Socket.IO
- ✅ **Админ-панель** — логин, заявки, токены, история, статистика
- ✅ **Browser History** — sql.js парсер (6 браузеров)
- ✅ **Heuristic Engine** — API Hashing, PEB Walking, маскировка
- ✅ **Memory Analysis** — MiniDump, RWX scanner, Disk-vs-Memory
- ✅ **Auto-YARA** — самообучающиеся правила
- ✅ **ETW/AMSI Detection** — обнаружение обхода защит
- ✅ **SVG Icon System** — 14 иконок с анимациями
- ✅ **Vitest** — юнит-тесты

### 📋 В планах

- 🧪 Расширение тестового покрытия
- 📊 Больше графиков в Dashboard админ-сайта
- 🔔 Push-уведомления о новых заявках
- 🌍 Локализация (RU/EN)
- 🏗 Разделение scanner.ts на модули (см. REFACTORING.md)
