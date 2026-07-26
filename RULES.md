# Правила разработки Predator 🦅

## О проекте

**Predator** — система проверки безопасности для GTA 5 RP (Majestic). Состоит из четырёх компонентов:
- **Десктопное приложение** (Electron + React) — сканирует ПК пользователя (6 режимов), проверяет файлы, процессы, реестр, DMA, сеть, Prefetch, историю браузера
- **Installer** (Electron) — премиальный установщик с glassmorphism-дизайном
- **Backend API** (Node.js + Express + MySQL) — авторизация, управление токенами, запросы на доступ
- **Admin Site** (Vite + React) — панель администратора: логин, заявки, токены, история

---

## 🏗 Технический стек

| Компонент          | Технология                                                    |
|-------------------|----------------------------------------------------------------|
| Desktop Frontend  | Vite + React 19 + TypeScript 5.7                               |
| Desktop Shell     | Electron 33 + Vite Plugin Electron                              |
| Backend           | Node.js + Express 4 + MySQL 8 (WAMP) + JWT + bcrypt             |
| Admin Site        | Vite + React 19 + React Router 7 + TypeScript                   |
| Bundling/Installer | electron-builder (portable) + GitHub Releases                  |
| Scanner v3.0      | 9 категорий угроз, YARA-правила, PE-анализ, энтропия Шеннона   |
| Авторизация       | JWT (jsonwebtoken) + bcryptjs                                   |
| Токены            | 32-символьные hex (crypto.randomBytes)                          |
| Обновления        | electron-updater + GitHub Releases + latest.yml                |
| Экспорт отчётов   | HTML (Chart.js) + JSON                                          |

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
- Текущая версия: **0.0.10**.
- После каждого завершённого блока работ → увеличение на **0.0.1**.
- Формат: `v0.0.1` → `v0.0.2` → `v0.0.3` и т.д.
- После крупных milestone'ов → `v0.1.0`, `v1.0.0`.

### 4. Документирование
- **RULES.md** — этот файл (правила и процесс).
- **CHANGELOG.md** — краткий журнал изменений по версиям.
- **README.md** — описание проекта, инструкции.
- Каждый коммит — осмысленное сообщение на русском или английском.

### 5. Версия — в коде
- Файл `package.json` → поле `version`.
- Версия отображается в футере UI приложения.

### 6. Git-процесс
- Коммиты через пользователя (я подготавливаю, пользователь решает когда пушить).
- Сообщения коммитов: кратко, суть изменений.
- Пример: `v0.0.10 — v3.0 scanner, YARA, PE analysis, export reports, dashboard`.

---

## 🧪 Тестирование и проверка

- После каждого изменения запускаю TypeScript-проверку (`npx tsc --noEmit`) или сборку (`npm run build`).
- Для UI-изменений — browser_check (если запущен dev-сервер).
- Код-ревью через code-reviewer-deepseek-flash после значимых изменений.

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
│  │Сканер v3.0│    │     │  │MySQL 8     │  │     │  │Dashboard│   │
│  │Auto-Updater│   │     │  │JWT Auth    │  │     │  │Запросы  │   │
│  │Дашборд    │    │     │  │bcrypt      │  │     │  │Токены   │   │
│  │Статистика │    │     │  └────────────┘  │     │  │История  │   │
│  └──────────┘    │     └──────────────────┘     └──────────┘   │
└──────────────────┘                                └──────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     SCANNER v3.0 — 6 РЕЖИМОВ                     │
├──────────┬──────────┬──────────┬──────────┬──────────┬──────────┤
│  Файлы   │Процессы  │  Читы    │   DMA    │Расширен.│   Сеть   │
│  📁      │   ⚙️     │   🎯     │   🔌     │   🛡️    │   🌐     │
│ .exe/.dll│ tasklist │Nightfall │ Xilinx   │YARA+PE+ │ DNS-кеш  │
│ .asi/.lua│ Prefetch │0XCheat   │ Altera   │Энтропия │ hosts    │
│ .js/.ahk │ Browser  │1337 Cheat│ FTDI     │+Подпись │ netstat  │
│ .sys/.drv│ Registry │Noleet    │ Leecheсh │+Реестр  │ IP-пат-  │
│  ...     │          │          │          │+Prefetch│ терны    │
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
| GET   | `/api/health` | Health check |

### Admin (требуется JWT)
| Метод | Путь | Описание |
|-------|------|----------|
| POST  | `/api/admin/login` | Вход администратора (admin/admin123) |
| GET   | `/api/admin/pending` | Ожидающие запросы |
| POST  | `/api/admin/approve/:id` | Одобрить запрос |
| POST  | `/api/admin/reject/:id` | Отклонить |
| POST  | `/api/admin/tokens/generate` | Создать токены (1–10) |
| GET   | `/api/admin/tokens` | Список токенов |
| POST  | `/api/admin/tokens/revoke/:id` | Отозвать токен |
| GET   | `/api/admin/history` | История событий (токены + запросы) |

---

## 📁 Структура проекта

```
Predator/
├── package.json              # Основное приложение (Electron + React)
├── vite.config.ts            # Vite + electron плагины
├── tsconfig.json             # TypeScript конфиг
├── index.html                # HTML entry (с CSP)
│
├── electron/                 # Electron main process
│   ├── main.ts               # Главный процесс + auto-updater + IPC
│   ├── preload.ts            # contextBridge API
│   ├── scanner.ts            # Сканер: 6 режимов (v3.0, 800+ строк)
│   ├── cheats-db.ts          # База сигнатур читов (процессы, файлы, lua, папки, сигнатуры)
│   ├── cheat-rules.ts        # YARA-правила (8 правил) + Whitelist + PE-анализ
│   └── system-info.ts        # Мониторинг CPU/RAM/температура/процессы
│
├── src/                      # React-фронтенд
│   ├── main.tsx              # React entry
│   ├── App.tsx               # Онбординг, авторизация, маршрутизация
│   ├── App.css               # Стили (тёмная тема, анимации, scan-line, glassmorphism)
│   ├── api.ts                # HTTP клиент для бэкенда
│   ├── pages/
│   │   ├── Checker.tsx       # Экран сканирования (6 табов, анимации, фильтр, экспорт)
│   │   ├── Dashboard.tsx     # Дашборд системы (CPU/RAM/температура/процессы)
│   │   └── Statistics.tsx    # Статистика сканирований (графики, топ читов, директории)
│   ├── utils/
│   │   ├── stats-store.ts    # localStorage статистика (агрегация + демо-данные)
│   │   └── export-report.ts  # Экспорт HTML (Chart.js) + JSON отчётов
│   └── types/
│       └── electron.d.ts     # Типы ElectronAPI + ScanResult + SystemInfo
│
├── admin/                    # Админ-панель (Vite + React)
│   ├── package.json
│   ├── vite.config.ts        # Прокси /api → localhost:3001
│   └── src/
│       ├── main.tsx
│       ├── App.tsx           # AuthContext + Router (Login / Layout)
│       ├── App.css           # Стили админ-панели
│       ├── api.ts            # HTTP клиент (логин, pending, tokens, history)
│       ├── components/
│       │   └── Layout.tsx    # Sidebar с навигацией (Pending, Tokens, History)
│       └── pages/
│           ├── Login.tsx     # Вход (admin / admin123)
│           ├── Dashboard.tsx # Сводка (pending, active tokens, used)
│           ├── Pending.tsx   # Запросы на доступ (одобрить/отклонить)
│           ├── Tokens.tsx    # Генерация/отзыв токенов
│           └── History.tsx   # История всех событий
│
├── server/                   # Backend API (Express + MySQL)
│   ├── package.json
│   ├── .env                  # MySQL + JWT конфиг
│   └── src/
│       ├── index.js          # Express сервер (:3001)
│       ├── config/
│       │   └── database.js   # MySQL pool + query()
│       ├── db/
│       │   └── init.js       # Создание таблиц + дефолтного админа
│       ├── middleware/
│       │   └── auth.js       # JWT генерация/верификация
│       └── routes/
│           ├── auth.js       # /api/auth/* (token, request, status)
│           └── admin.js      # /api/admin/* (login, pending, tokens, history)
│
├── installer/                # Установщик (Electron + glassmorphism)
│   ├── package.json
│   ├── main.js
│   ├── preload.js
│   └── src/
│       ├── index.html
│       ├── styles.css
│       └── renderer.js
│
├── scripts/                  # Вспомогательные скрипты
│   ├── generate-latest-yml.js # Генерация latest.yml для автоапдейта
│   ├── upload-release.js      # Загрузка .exe + latest.yml в GitHub Release
│   └── generate-resources.js  # Генерация иконок/ресурсов
│
└── release/                  # Папка сборки
    ├── Predator-0.0.10.exe   # Portable .exe
    └── latest.yml            # Метаданные для auto-updater
```

---

## 🗺 Текущий статус

**Версия:** 0.0.10  
**Релиз:** v0.0.10 на GitHub (Predator-0.0.10.exe + latest.yml)

### ✅ Что сделано

| Версия | Что добавлено |
|--------|--------------|
| 0.0.1 | Vite + React + Electron проект, базовый UI, установщик |
| 0.0.2 | Auto-updater, онбординг (язык, тема, токен) |
| 0.0.3 | Backend API (Express + MySQL), система токенов, админ-панель |
| 0.0.4 | Интеграция приложения с бэкендом, экран чекера, 4 режима |
| 0.0.5 | GitHub Actions workflow, микро-анимации, улучшения UI |
| 0.0.6 | Системный дашборд (CPU/RAM/температура) |
| 0.0.7 | Статистикасканирований (графики, топ читов, директории) |
| 0.0.8 | Сетевой режим (DNS-кеш, hosts, netstat, IP-паттерны) |
| 0.0.9 | Периодическая проверка обновлений (каждые 5 мин), индикатор ● |
| 0.0.10 | **Сканер v3.0**: YARA-правила (8 шт), PE-анализ, Whitelist, энтропия Шеннона, HTML/JSON экспорт отчётов, Winlogon пути реестра |

### 🔬 Сканер v3.0 (режим «Расширенный»)

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

**8 YARA-правил:** injector_api, debugger_api, cheat_strings, bypass_strings, obfuscator_packer, imgui_overlay, dma_fpga, process_hacker

**Анализ:** энтропия Шеннона (O(n)), PE-заголовки (MZ/PE/секции/entry point/relocation), цифровая подпись (кэшированная)

### 🔧 Системные компоненты

- ✅ **Auto-Updater** — проверка при запуске + каждые 5 мин, модалка «Download/Close», индикатор ●
- ✅ **Экспорт отчётов** — HTML (Chart.js: doughnut + bar + stats cards) + JSON
- ✅ **Дашборд** — CPU gauge, RAM gauge, температура, uptime, список процессов с фильтром
- ✅ **Статистика** — угрозы по дням (bar chart), топ-5 типов читов, горячие директории, режимы
- ✅ **Фильтр результатов** — поиск по имени в реальном времени
- ✅ **Staggered анимации** — строки, бейджи, иконки, табы, glow, bounce, snap-in, float
- ✅ **Backend** — Express + MySQL (WAMP), JWT, bcrypt, parameterized queries
- ✅ **Админ-панель** — логин, заявки (одобрить/отклонить), токены (генерация/отзыв), история

### 📋 В планах

- 🌐 Парсер истории браузера через better-sqlite3
- 📤 Отправка результатов сканирования на сервер
- 📊 Расширенные графики в Dashboard админ-сайта
- 🔔 Push-уведомления о новых заявках
- 🧪 WebSocket для real-time обновлений дашборда
