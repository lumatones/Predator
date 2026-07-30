# Predator - Гайд для разработчиков

> Версия 0.4.4 · Обновлено 2026-07-30

## Структура проекта

```
Predator/
├── electron/            # Electron main process - 41 модуль + подмодули
│   ├── main.ts          # Точка входа, окно, трей, автообновление
│   ├── preload.ts       # contextBridge API (15 IPC-каналов)
│   ├── scanner.ts       # Оркестратор сканирования
│   ├── types.ts         # ScanContext, ScanResult, parsePsJson
│   ├── heuristic/       # Эвристический движок (7 подмодулей)
│   ├── modes/           # Режимы детекции (14 файлов + apc/process/usb)
│   ├── utils/exec.ts    # Безопасные обёртки execPowerShell/execWithTimeout
│   ├── scan-pipeline.ts # 5 пост-скан обработчиков
│   ├── risk-scorer.ts   # 25 взвешенных категорий сигналов
│   └── __tests__/       # 9 файлов, 243 теста
│
├── src/                 # React рендерер (Vite + React 19 + TS 5.7)
│   ├── pages/           # Checker.tsx, Dashboard.tsx
│   ├── components/ui/   # 20+ UI-компонентов
│   ├── hooks/           # useAuth, useScan, useThemeEngine, useMusicPlayer
│   └── styles/          # CSS-модули
│
├── server/              # Бэкенд API (Express 4 + MySQL 8 + Drizzle ORM)
│   └── src/
│       ├── middleware/  # 7 middleware-модулей
│       ├── routes/      # auth.ts, admin.ts, v1.ts
│       └── services/    # classifier.ts, tlsh-matcher.ts, cheat-knowledge.ts
│
├── admin/               # Админ-панель (React 19)
│   └── src/pages/       # 8 страниц (Login, Dashboard, Pending, Tokens, etc.)
│
├── scripts/             # Релизные скрипты
├── docs/                # Документация
│   ├── ARCHITECTURE.md  # Архитектура системы
│   ├── CHANGELOG.md     # История версий
│   ├── DEV.md           # Этот файл
│   ├── REFACTORING.md   # Прогресс рефакторинга
│   ├── ROADMAP.md       # Планы
│   └── RULES.md         # Правила разработки
│
├── resources/           # Иконки, ассеты установщика
└── .github/workflows/   # CI (ci.yml) + авто-релиз (release.yml)
```

## Быстрый старт

```bash
git clone https://github.com/lumatones/Predator.git
cd Predator

# Установка зависимостей
npm install

# Настройка сервера
cp server/.env.example server/.env
# Отредактируй server/.env: JWT_SECRET и DB-доступы

# Инициализация БД
cd server && npm run db:push
```

## Команды разработки

```bash
# Десктоп - только рендерер (Vite dev server)
npm run dev

# Десктоп - Electron + Vite (hot reload)
npm run electron:dev

# Сервер - watch mode
cd server && npm run dev

# Админ-панель
cd admin && npm run dev
```

## TypeScript

Четыре tsconfig-файла, каждый на свой компонент:

| Конфиг | Область | Команда |
|--------|---------|---------|
| `tsconfig.json` | `src/` (рендерер) | `npm run typecheck:renderer` |
| `tsconfig.electron.json` | `electron/` (main process) | `npm run typecheck:electron` |
| `admin/tsconfig.json` | `admin/` | `cd admin && npx tsc --noEmit` |
| `server/tsconfig.json` | `server/` | `cd server && npm run typecheck` |

Всё сразу:

```bash
npm run typecheck
```

## Тесты

Vitest, тесты в `electron/__tests__/` (9 файлов, 243 теста).

```bash
# Все тесты
npx vitest run

# Только electron
npx vitest run electron

# Watch mode
npx vitest

# Серверные тесты
cd server && npx vitest run
```

## Качество кода

### Pre-commit хук

Husky запускает перед каждым коммитом:

```
lint-staged (eslint: electron + src, tsc: server + admin)
  ↓
Полный typecheck (electron)
  ↓
Полный typecheck (server)
```

### Линтинг

```bash
npm run lint        # Проверка
npm run lint:fix    # Авто-фикс
npm run format      # Prettier
npm run format:check
```

### Стиль кода

- Отступы: 2 пробела (`.editorconfig`)
- TypeScript: strict mode, избегать `any`
- Именование: camelCase (переменные/функции), PascalCase (типы/интерфейсы)
- Импорты: внешние первыми, внутренние вторыми, по алфавиту
- `execPowerShell`/`execWithTimeout` возвращают `string | null`, всегда добавляй `|| ''`

## Сборка

```bash
npm run typecheck            # Проверка типов
npm run build                # Сборка фронтенда + electron
npm run electron:build:win   # Упаковка в portable .exe
npm run clean                # Очистка артефактов
npm run build:all            # Всё (десктоп + админка)
```

## Релиз

### Автоматический

```bash
npm run release
```

Цикл: typecheck → clean → build .exe → latest.yml → GitHub Release.

Требуется `GITHUB_TOKEN` в `.env`.

### Через CI

Пуш тега запускает GitHub Actions:

```bash
git tag v0.4.4
git push origin v0.4.4
```

Workflow `release.yml` собирает `.exe` и публикует в GitHub Releases.

## Сервер

### Переменные окружения

Файл `server/.env`:

```env
PORT=3001
CLIENT_URL=http://localhost:5173,http://localhost:3000
JWT_SECRET=your-secret-here-at-least-32-chars

DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your-password
DB_NAME=predator

REQUEST_EXPIRY_MINUTES=30
```

### База данных

```bash
cd server

npm run db:push      # Применить схему к MySQL
npm run db:generate  # Сгенерировать миграции
npm run db:migrate   # Запустить миграции
npm run db:studio    # Drizzle Studio (визуальный браузер БД)
```

### Команды сервера

```bash
cd server

npm start            # Продакшн
npm run dev          # Dev с hot reload
npm run typecheck    # Проверка типов
npm test             # Тесты
```

## Ключевые архитектурные решения

### execSync заменён на безопасные обёртки

Все вызовы `child_process.execSync` перенесены в `electron/utils/exec.ts`. Три обёртки:

- `execPowerShell(script, opts)` для PowerShell-команд
- `execWithTimeout(cmd, opts)` для обычных команд (netstat, wmic, tasklist, reg query)
- `execFileWithTimeout(file, args, opts)` для запуска бинарников

Возвращают `string | null`. Всегда обрабатывай null через `|| ''`.

### ScanContext

Глобальное состояние в `electron/types.ts` через класс `ScanContext`. Единый экземпляр `ctx` для всех модулей сканирования. Вызывай `ctx.resetScan()` перед каждым новым сканом.

### Scan Pipeline

Пост-скан обработчики в `electron/scan-pipeline.ts`:

SessionRecorder → ShadowSubmitter → AutoWhitelister → HashSubmitter → ResultUploader

Каждый обработчик независим. Отказ одного не блокирует остальные.
