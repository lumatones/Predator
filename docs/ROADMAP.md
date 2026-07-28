# Predator — Professional Development Roadmap v2.0

> **Версия документа**: 2.0 | **Обновлено**: 2026-07-28
> **Текущая версия продукта**: v0.3.1
> **Принцип**: THINK FIRST → Research → Propose → Implement by stages

---

## 📊 СВОДКА: ЧТО УЖЕ СДЕЛАНО (от v0.1.14 до v0.3.1)

### EXE-приложение
- ✅ ScanPipeline — 5-step post-scan цепочка (SessionRecorder → ShadowSubmitter → AutoWhitelister → HashSubmitter → ResultUploader)
- ✅ Signature Registry — единый источник сигнатур (9 категорий, 200+ keywords, 60+ regex)
- ✅ Parallel file scanning — worker_threads pool (4 воркера) с runParallel()
- ✅ Scan cancellation — AbortController + ctx.abortController
- ✅ Anti-tamper (anti-tamper.ts) + Anti-debug (modes/anti-debug.ts)
- ✅ TelemetryQueue — надёжная очередь с retry + persistence
- ✅ Persistent Profiles — эскалация риска при повторных подозрительных сканах
- ✅ Safe-files DB — локальная БД + синхронизация с серверным community whitelist
- ✅ Shadow findings — silent telemetry для rule discovery без FP у пользователя
- ✅ GlassEye Easter egg — RPG-диалоги, пиксельная озвучка, Cheshire-cat улыбка, красный экран смерти + joke-screen
- ✅ 14 SVG-иконок (все emoji заменены)
- ✅ Onboarding flow (WelcomeStep → DemoScanStep → язык → тема → авторизация)
- ✅ Husky pre-commit (tsc --noEmit)
- ✅ 4 тестовых файла (heuristic, heuristic-extended, scan-pipeline, signature-registry)

### Сервер
- ✅ TypeScript миграция (JS → TS)
- ✅ Zod валидация на ВСЕХ эндпоинтах (shared-types.ts)
- ✅ Rate limiting (general 100/min, authWrite 10/min)
- ✅ CORS whitelist (ALLOWED_ORIGINS из .env)
- ✅ Helmet security headers
- ✅ Prometheus метрики (middleware/metrics.ts)
- ✅ API v1 с версионированием (routes/v1.ts)
- ✅ Auto-classifier (services/classifier.ts)
- ✅ Shadow findings pipeline (submit → collect → promote/reject)
- ✅ Safe-files community whitelist (submit → aggregate → distribute)
- ✅ WebSocket (Socket.IO) — комнаты admin + scanner, 7 типов событий
- ✅ JWT auth (ленивая загрузка JWT_SECRET — фикс dotenv)
- ✅ Server bind к 0.0.0.0:3001 (внешний IP)

### Админ-дашборд
- ✅ 8 страниц (HomePage, Dashboard, History, Login, Pending, SafeFiles, SuspiciousHashes, Tokens)
- ✅ WebSocket real-time обновления
- ✅ 14 компонентов (AnimatedNumber, CommandPalette, Confetti, HashRow, Layout, MatrixRain, ParticleBackground, PredatorLogo3D, Skeleton, SpeedometerGauge, Toast, TypewriterText, CountdownCircle, CommandPalette.css)
- ✅ Glassmorphism UI theme

---

## 🏗️ МОДУЛЬ 1: EXE-ПРИЛОЖЕНИЕ (Electron + React + TypeScript)

**Текущий размер**: 60+ файлов (electron 32 + src 30+). Ядро сканера — глубокое (11 фаз full scan).
**Цель**: Industrial-grade anti-cheat client. Flawless UI/UX. 20%+ test coverage. 99.9% crash-free.

### 1.1 СКАНЕР-ДВИЖОК (electron/)

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 1.1 | **Дедупликация ALL_CHEAT_KEYWORDS** — убрать дубликаты через `[...new Set(array)]` | 🔴 P0 | 30 мин | ~30% CPU уходит на повторный matching |
| 1.2 | **PowerShell executor с таймаутом + CircuitBreaker** — обёртка над execSync с retry (3 попытки, exponential backoff) | 🔴 P0 | 2ч | При locked-файлах PowerShell виснет на 8с, блокируя весь pipeline |
| 1.3 | **Инкрементальный скан** — fileMtimeCache уже есть в ScanContext. Добавить проверку `hasFileChanged()` перед heuristicFileScan | 🟡 P1 | 3ч | Повторные сканы тратят 5+ минут на неизменённые файлы |
| 1.4 | **Scan scheduler** — cron-подобный (каждые 6h, при старте, при запуске игры). IPC handler `schedule-scan` + `setInterval` в main | 🟡 P1 | 4ч | Пользователи забывают сканироваться. Автоматизация = защита |
| 1.5 | **Унифицированный отчёт** — все 7+ scan modes → единый risk assessment (low/medium/high + итоговый score) | 🟡 P1 | 5ч | Пользователь видит разрозненные результаты. Нужен единый вердикт |
| 1.6 | **Process tree detection** — анализ parent-child связей процессов (explorer.exe → подозрительный.exe) | 🟡 P1 | 4ч | Cheat-лоадеры маскируются под дочерние процессы легитимных приложений |
| 1.7 | **Enhanced network scan** — DNS tunneling detection, known C2 IPs, bad ASN lookup | 🟢 P2 | 6ч | Текущий netstat grep ловит только прямые соединения |
| 1.8 | **DMA firmware fingerprint DB** — хэши известных cheat FPGA bitstreams (Screamer, CaptainDMA, LeetDMA) | 🟢 P2 | 4ч | DMA-читы обходят софтверные проверки. Нужны хардверные сигнатуры |
| 1.9 | **ML-based anomaly detection** — обучить модель на известных cheat-паттернах (supervised: random forest / XGBoost) | 🔵 P3 | 3 нед | Долгосрочная защита от полиморфных читов |

### 1.2 БАЗА СИГНАТУР (signature-registry.ts + cheats-db.ts)

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 2.1 | **Версионирование сигнатур** — `sig-version.json` с semantic version. Клиент проверяет версию при старте | 🟡 P1 | 2ч | Нельзя откатить плохие сигнатуры |
| 2.2 | **Hot-reload из облака** — клиент уже получает сигнатуры через `/api/v1/signatures` (v1.ts). Нужно применить их БЕЗ перезапуска | 🟡 P1 | 3ч | API v1 уже возвращает сигнатуры. Клиент их игнорирует — не применяет |
| 2.3 | **Community JSON формат** — `cheats.json` (валидируется Zod) → парсится при старте. Админы могут добавлять читы без кода | 🟢 P2 | 4ч | Новый чит требует PR в репозиторий. Это часы, а не минуты |
| 2.4 | **Сигнатурная телеметрия** — отслеживать какие сигнатуры реально срабатывают (hit rate) | 🟢 P2 | 3ч | Не знаем, какие правила эффективны, а какие — мусор |
| 2.5 | **Метаданные сигнатур** — date_added, source, false_positive_rate, last_hit | 🔵 P3 | 2ч | Без метаданных невозможно чистить устаревшие правила |

### 1.3 REACT UI (src/)

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 3.1 | **Декомпозиция App.tsx** — вынести useOnboarding(), useThemeEngine(), useUpdateManager(), useEasterEgg() в отдельные хуки | 🔴 P0 | 3ч | App.tsx ~400 строк, 10+ state vars. Любое изменение рискует сломать онбординг/темы/авторизацию |
| 3.2 | **Фикс Checker UI overflow** — responsive grid, гибкие табы (4 колонки на весь экран, 2 на среднем, 1 на узком) | 🔴 P0 | 2ч | Текущий UI выходит за край экрана на <1200px. Кнопки скрыты |
| 3.3 | **Виртуальный скролл результатов** — react-window для списка находок (500+ results → lag) | 🟡 P1 | 3ч | 500+ результатов = лагает скролл. Каждый результат рендерит div целиком |
| 3.4 | **Code splitting** — lazy load Dashboard, ThreatMap, Settings, Onboarding | 🟡 P1 | 2ч | Весь бандл грузится upfront. Тяжёлые компоненты (Three.js) не нужны при старте |
| 3.5 | **i18n фреймворк** — react-i18next + JSON locale файлы (RU, EN). Заменить ручной объект T | 🟢 P2 | 6ч | Текущий T-объект (ручной) — невозможно добавить новый язык без правки кода |
| 3.6 | **ARIA accessibility** — labels, keyboard nav (Tab/Enter/Escape), screen-reader friendly | 🟢 P2 | 4ч | Приложение непригодно для слабовидящих |
| 3.7 | **Error Boundary на каждый page** — сейчас ErrorBoundary только на одном уровне | 🟡 P1 | 1ч | Крэш в Checker роняет всё приложение |
| 3.8 | **ConfirmDialog перед деструктивными действиями** — остановка скана, сброс настроек | 🟢 P2 | 1ч | Случайный клик = потеря прогресса скана |
| 3.9 | **export-report.ts — заменить emoji на SVG** | 🔴 P0 | 30 мин | Единственное место, где ещё остались Unicode emoji. Бренд- inconsistency |
| 3.10| **PWA/оффлайн-режим** — Service Worker для кэширования UI | 🔵 P3 | 4ч | Приложение полностью зависит от сети для первого запуска |

### 1.4 ПРОИЗВОДИТЕЛЬНОСТЬ

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 4.1 | **Стартап-профилирование** — замер времени от app.whenReady() до ready-to-show | 🟡 P1 | 1ч | Не знаем реальное время запуска приложения |
| 4.2 | **Memory profiling** — heap snapshots до/после 10 последовательных full scan | 🟡 P1 | 2ч | Возможны memory leaks при долгой работе |
| 4.3 | **File I/O batching** — readdir + stat за один проход вместо отдельных statSync на каждый файл | 🟢 P2 | 3ч | Каждый файл = отдельный fs.statSync. Двойная работа |
| 4.4 | **Image lazy loading** — иконки грузятся по требованию, а не все сразу | 🔵 P3 | 2ч | 14 SVG иконок = 14 отдельных файлов в бандле |

### 1.5 ТЕСТИРОВАНИЕ

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 5.1 | **Тесты scanner core** — runFullScan/runQuickScan с замоканными модулями (файловая система + процесс-лист) | 🔴 P0 | 6ч | 0 тестов для главной функции приложения |
| 5.2 | **Тесты для всех 5 ScanPipeline handlers** — recordScanSession, submitShadowFindings, autoWhitelistLowRisk, submitAllFindings, uploadScanResults | 🔴 P0 | 3ч | Post-scan side effects не тестируются совсем |
| 5.3 | **E2E тесты с Playwright** — полный флоу: открытие → онбординг → авторизация → full scan → просмотр результатов | 🟡 P1 | 8ч | Невозможно проверить пользовательские сценарии |
| 5.4 | **Integration тесты IPC bridge** — main ↔ renderer round-trip (get-config, start-scan, cancel-scan) | 🟡 P1 | 4ч | IPC сломается — никто не узнает до продакшена |
| 5.5 | **CI: все тесты на PR** — GitHub Actions запускает vitest + Playwright при каждом PR | 🟡 P1 | 2ч | Тесты есть, но в CI не запускаются |
| 5.6 | **Тесты для всех scan modes** — processes, games, network, registry, browser, dma | 🟢 P2 | 6ч | Каждый mode ~100-300 строк, 0 тестов |
| **Цель покрытия**: | Core scanner 80%+ | ScanPipeline 100% | Signature Registry 100% | Всего: 20%+ строк |

### 1.6 БЕЗОПАСНОСТЬ

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 6.1 | **Шифрованное хранение конфига** — AES-256-GCM, ключ из machine GUID | 🟡 P1 | 3ч | API ключи, токены в plain JSON. Любой читатель asar увидит |
| 6.2 | **Code signing verification** — проверять Authenticode подпись своего .exe при старте | 🟡 P1 | 2ч | Подменённый бинарник запустится молча |
| 6.3 | **Runtime integrity** — CRC32 секции .text vs известный хэш | 🟢 P2 | 4ч | In-memory patching не детектится |
| 6.4 | **Anti-DLL-injection** — перечислять загруженные модули, проверять подписи | 🟢 P2 | 3ч | Читы могут инжектиться в процесс Predator |

---

## 🖥️ МОДУЛЬ 2: СЕРВЕР (Express + TypeScript + MySQL)

**Текущее состояние**: TypeScript, Zod, rate limiting, helmet, Prometheus, API v1, WebSocket, auto-classifier, shadow findings, safe-files. ~1400 строк кода.

### 2.1 БАЗА ДАННЫХ

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 7.1 | **Миграции (Knex или Drizzle)** — заменить ручной `init.ts` + `schema.sql` на программные миграции | 🔴 P0 | 4ч | Schema drift между dev/prod. Ручной SQL init — ошибки ждут |
| 7.2 | **TTL на scan_results** — `DELETE WHERE created_at < NOW() - INTERVAL 90 DAY` | 🟡 P1 | 1ч | Таблица растёт на ~1GB/месяц. Через год будет 12GB |
| 7.3 | **Connection pooling config** — min=5, max=50, acquireTimeout=10000 | 🟡 P1 | 30 мин | Дефолтный пул (10 коннектов) — узкое горлышко |
| 7.4 | **Slow query log** — запросы >1с в отдельный файл | 🟢 P2 | 30 мин | Не знаем какие запросы тормозят |
| 7.5 | **Индексы на часто-запрашиваемые колонки** — scan_results.token_id, suspicious_hashes.partial_hash, shadow_findings.rule_name | 🟡 P1 | 1ч | Без индексов — full table scan на каждый запрос |
| 7.6 | **Репликация (read replica)** — для аналитических запросов | 🔵 P3 | 2 нед | Production-требование для масштабирования |

### 2.2 АУДИТ И БЕЗОПАСНОСТЬ

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 8.1 | **Admin audit log** — таблица `admin_actions` (admin_id, action, target_type, target_id, ip, timestamp) | 🟡 P1 | 3ч | Невозможно отследить кто одобрил/отклонил конкретный запрос через месяц |
| 8.2 | **WebSocket auth middleware** — проверять JWT при подключении к комнате admin/scanner | 🟡 P1 | 2ч | Любой может подключиться к WebSocket и слушать админские события |
| 8.3 | **httpOnly cookie для admin JWT** — вместо localStorage | 🟢 P2 | 2ч | XSS может украсть admin токен |
| 8.4 | **API key rotation** — механизм ротации для компрометированных ключей | 🟢 P2 | 2ч | Скомпрометированный ключ = перманентный доступ |

### 2.3 API ДИЗАЙН

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 9.1 | **Пагинация на всех list-эндпоинтах** — `/tokens`, `/suspicious-hashes`, `/history`, `/pending`, `/safe-files` | 🟡 P1 | 3ч | Без пагинации ответы растут бесконечно |
| 9.2 | **Стандартизированный формат ошибок** — `{ error: { code, message, requestId } }` на ВСЕХ эндпоинтах | 🟡 P1 | 2ч | Часть эндпоинтов возвращает `{error: "..."}`, часть `{valid: false, error: "..."}` |
| 9.3 | **X-Request-ID middleware** — uuid на каждый запрос | 🟢 P2 | 30 мин | Невозможно trace'ить ошибки по логам |
| 9.4 | **Разделение монолитных роутов** — auth.ts (250 строк) → auth/token.ts + auth/request.ts + auth/scan.ts + auth/hash.ts | 🟢 P2 | 3ч | 250-строчный файл — тяжело навигировать |

### 2.4 ТЕСТИРОВАНИЕ

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 10.1 | **Интеграционные тесты API** — vitest + supertest: все 24 эндпоинта × 2 случая (успех + ошибка) | 🔴 P0 | 6ч | 0 тестов на сервере. Любой рефакторинг = риск продакшен-сбоя |
| 10.2 | **Test DB** — отдельная `test_predator` база, seeded перед каждым suite | 🟡 P1 | 2ч | Без тестовой БД нельзя тестировать эндпоинты |
| 10.3 | **CI для серверных тестов** — GitHub Actions запускает тесты при PR | 🟡 P1 | 1ч | Тесты будут написаны, но не будут запускаться |
| **Цель покрытия**: | 80%+ lines | 70%+ branches | Все 24 эндпоинта покрыты |

### 2.5 МОНИТОРИНГ И OPS

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 11.1 | **Grafana dashboard** — визуализация Prometheus метрик (latency, requests/sec, active users, scan modes) | 🟢 P2 | 3ч | Метрики собираются, но не визуализированы |
| 11.2 | **Alerting** — алерты на: 500 errors > 5%, latency p95 > 500ms, DB connection lost | 🟢 P2 | 2ч | Никто не узнает о падении сервера |
| 11.3 | **Health check endpoint для мониторинга** — `/api/health` проверяет DB + Redis (если будет) | 🟢 P2 | 1ч | Текущий health check не проверяет зависимости |
| 11.4 | **Graceful shutdown** — дообработка pending запросов при SIGTERM | 🟢 P2 | 2ч | При деплое теряются in-flight запросы |

---

## 🎛️ МОДУЛЬ 3: АДМИН-ДАШБОРД (React + TypeScript)

**Текущее состояние**: 8 страниц, 14 компонентов, WebSocket real-time, чистый glassmorphism UI.
**Цель**: Профессиональная админ-панель. RBAC. Аудитория. Bulk-операции. Аналитика.

### 3.1 УПРАВЛЕНИЕ ЗАПРОСАМИ (Pending.tsx)

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 12.1 | **Bulk approve/reject** — чекбоксы + тулбар с кнопками «Одобрить всё» / «Отклонить всё» | 🔴 P0 | 3ч | 50+ pending = 50 кликов. Админы тратят часы |
| 12.2 | **Поиск по pc_username** — fuzzy search + debounce | 🟡 P1 | 1ч | Нельзя найти конкретного пользователя среди сотен запросов |
| 12.3 | **Фильтр по дате** — сегодня / 7 дней / 30 дней / свой период | 🟡 P1 | 2ч | Не видно «свежих» запросов — всё вперемешку |
| 12.4 | **Причина отказа** — dropdown (spam / suspicious / duplicate / other) при reject | 🟢 P2 | 1ч | Пользователь не получает объяснения почему отказано |

### 3.2 УПРАВЛЕНИЕ ТОКЕНАМИ (Tokens.tsx)

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 13.1 | **Bulk-генерация** — 50, 100, 500 токенов с прогресс-баром | 🟡 P1 | 2ч | Текущий лимит — 10 за раз. Для ивентов нужно 100+ |
| 13.2 | **CSV экспорт** — выгрузка списка токенов в CSV | 🟢 P2 | 1ч | Нельзя поделиться списком токенов с организаторами серверов |
| 13.3 | **Дашборд использования токенов** — active / used / revoked counts + круговая диаграмма | 🟢 P2 | 3ч | Не видно общей картины использования токенов |
| 13.4 | **Авто-отзыв неиспользованных токенов** — через N дней, конфигурируемо | 🔵 P3 | 2ч | Токены висят вечно даже если не используются |

### 3.3 РЕВЬЮ ХЭШЕЙ (SuspiciousHashes.tsx + SafeFiles.tsx)

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 14.1 | **Bulk confirm/reject хэшей** — чекбоксы + batch-операции | 🔴 P0 | 2ч | 100+ pending-хэшей = 100 кликов |
| 14.2 | **Детальная панель хэша** — first seen, last seen, PC count, related scans, VirusTotal lookup | 🟡 P1 | 4ч | Админ не видит контекст хэша — только sha256 + file_name |
| 14.3 | **VirusTotal интеграция** — `GET /api/admin/hashes/:sha256/vt` → данные от 70+ AV | 🟢 P2 | 3ч | Ручная проверка хэша на VirusTotal замедляет ревью |
| 14.4 | **Fuzzy hash matching (ssdeep)** — детектить варианты одного чита | 🔵 P3 | 6ч | Один и тот же чит с разными хэшами = N записей |

### 3.4 БЕЗОПАСНОСТЬ АДМИНКИ

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 15.1 | **RBAC (роли)** — superadmin / admin / moderator с per-endpoint permissions | 🟡 P1 | 5ч | Все админы имеют полный доступ. Модератор не должен генерировать токены |
| 15.2 | **Session timeout** — авто-логаут через 30 мин неактивности | 🟡 P1 | 2ч | Токен JWT валиден 24ч. Админ ушёл — панель открыта |
| 15.3 | **Failed login tracking** — блокировка после 5 неудачных попыток (на 15 мин) | 🟢 P2 | 2ч | Брутфорс админского пароля не детектится |
| 15.4 | **2FA (TOTP)** — для superadmin аккаунтов | 🔵 P3 | 4ч | Однофакторная аутентификация — уязвимость |

### 3.5 АНАЛИТИКА

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 16.1 | **Player leaderboard** — топ игроков по сканам/детектам | 🟢 P2 | 3ч | Интересно для комьюнити, но не критично |
| 16.2 | **Threat trend chart** — детекты по времени (30d/90d), line chart | 🟢 P2 | 3ч | Не видно трендов — растёт ли количество читеров |
| 16.3 | **PDF report generation** — еженедельный отчёт, экспортируемый | 🔵 P3 | 6ч | Для стейкхолдеров / server owners |
| 16.4 | **Custom dashboard builder** — drag-and-drop виджетов | 🔵 P3 | 2 нед | Долгосрочная фича для кастомизации |

### 3.6 UI/UX АДМИНКИ

| # | Задача | Приоритет | Сложность | Срок | Почему важно |
|---|--------|-----------|-----------|------|-------------|
| 17.1 | **Keyboard shortcuts** — A=approve, R=reject, N=next, F=search, Esc=close | 🟢 P2 | 2ч | Без клавиатуры админы кликают мышкой сотни раз |
| 17.2 | **Toast notifications** — для approve/reject/generate действий (сейчас есть toast, но не везде используется) | 🟡 P1 | 1ч | Не все действия показывают подтверждение |
| 17.3 | **Responsive mobile view** — sidebar → hamburger, таблицы →卡片 | 🔵 P3 | 4ч | Админка только для десктопа. Мобильная версия = must-have для оперативного ревью |

---

## 📅 TIMELINE: ФАЗЫ ПО СПРИНТАМ

### 🔥 SPRINT 1: CRITICAL FIXES (v0.3.2 → v0.4.0) — 1-2 недели

**EXE (4 задачи, P0):**
- [ ] 1.1 Дедупликация ALL_CHEAT_KEYWORDS (30 мин)
- [ ] 1.2 PowerShell executor с таймаутом + CircuitBreaker (2ч)
- [ ] 3.1 Декомпозиция App.tsx на хуки (3ч)
- [ ] 3.2 Фикс Checker UI overflow (2ч)
- [ ] 3.9 export-report.ts — emoji → SVG (30 мин)

**Сервер (3 задачи, P0):**
- [ ] 7.1 Миграции (Knex или Drizzle) (4ч)
- [ ] 10.1 Интеграционные тесты API — supertest для всех 24 эндпоинтов (6ч)
- [ ] 10.2 Test DB (2ч)

**Админка (2 задачи, P0):**
- [ ] 12.1 Bulk approve/reject запросов (3ч)
- [ ] 14.1 Bulk confirm/reject хэшей (2ч)

**Итого**: ~30 часов работы. 11 задач.

### ⚡ SPRINT 2: HARDENING (v0.4.0 → v0.5.0) — 2-3 недели

**EXE (6 задач, P1):**
- [ ] 1.3 Инкрементальный скан (3ч)
- [ ] 2.2 Hot-reload сигнатур из облака (3ч)
- [ ] 3.3 Виртуальный скролл результатов — react-window (3ч)
- [ ] 3.5 i18n — react-i18next (6ч)
- [ ] 5.1 Тесты scanner core (6ч)
- [ ] 5.2 Тесты ScanPipeline handlers (3ч)
- [ ] 6.1 Шифрованное хранение конфига (3ч)

**Сервер (4 задачи, P1):**
- [ ] 7.5 Индексы на часто-запрашиваемые колонки (1ч)
- [ ] 8.1 Admin audit log (3ч)
- [ ] 8.2 WebSocket auth middleware (2ч)
- [ ] 9.1 Пагинация на list-эндпоинтах (3ч)

**Админка (4 задачи, P1):**
- [ ] 13.1 Bulk-генерация токенов (2ч)
- [ ] 14.2 Hash detail panel (4ч)
- [ ] 15.1 RBAC роли (5ч)
- [ ] 15.2 Session timeout (2ч)

**Итого**: ~49 часов. 15 задач.

### 🚀 SPRINT 3: SCALE (v0.5.0 → v0.6.0) — 3-4 недели

**EXE (5 задач, P1/P2):**
- [ ] 1.4 Scan scheduler (4ч)
- [ ] 1.5 Унифицированный отчёт (5ч)
- [ ] 2.3 Community JSON формат (4ч)
- [ ] 3.4 Code splitting (2ч)
- [ ] 5.3 E2E тесты Playwright (8ч)

**Сервер (3 задачи, P2):**
- [ ] 7.2 TTL на scan_results (1ч)
- [ ] 9.4 Разделение монолитных роутов (3ч)
- [ ] 11.1 Grafana dashboard (3ч)

**Админка (3 задачи, P2):**
- [ ] 14.3 VirusTotal интеграция (3ч)
- [ ] 16.1 Player leaderboard (3ч)
- [ ] 16.2 Threat trend chart (3ч)

**Итого**: ~39 часов. 11 задач.

### 🏁 SPRINT 4: ECOSYSTEM (v0.6.0 → v1.0.0) — 2-3 месяца

**EXE:**
- [ ] 1.9 ML-based anomaly detection (3 нед)
- [ ] 3.6 ARIA accessibility (4ч)
- [ ] 3.10 PWA/оффлайн-режим (4ч)
- [ ] 6.3 Runtime integrity checks (4ч)

**Сервер:**
- [ ] 7.6 Репликация (read replica) (2 нед)
- [ ] 8.3 httpOnly cookie для JWT (2ч)
- [ ] 9.4 Health check с проверкой зависимостей (1ч)
- [ ] 11.2 Alerting (2ч)
- [ ] 11.4 Graceful shutdown (2ч)

**Админка:**
- [ ] 15.4 2FA TOTP (4ч)
- [ ] 16.3 PDF reports (6ч)
- [ ] 16.4 Custom dashboard (2 нед)
- [ ] 17.3 Responsive mobile (4ч)

**Новое — ПУБЛИЧНЫЙ САЙТ (Next.js):**
- [ ] Landing page с download CTA
- [ ] Player database (/players, /players/:id)
- [ ] Public stats (/stats)
- [ ] API docs для комьюнити-ботов
- [ ] Data sync: MySQL → PostgreSQL

---

## ⚠️ РИСКИ

| Риск | Вероятность | Влияние | Митигация |
|------|-----------|--------|-----------|
| False positives → user distrust | Средняя | Высокое | FP tracking dashboard, лёгкий appeal process |
| Cheat devs bypass detection | Высокая | Среднее | ML layer + behavioral detection + частые обновления сигнатур |
| Server downtime в турнирный сезон | Низкая | Высокое | Оффлайн-режим, multi-region failover |
| GDPR/privacy complaint | Средняя | Среднее | Opt-out система, data minimization, encryption at rest |
| GitHub Actions CI flakiness | Средняя | Низкое | Retry с backoff, раздельные typecheck/build |
| Electron CVE vulnerability | Низкая | Высокое | Dependabot, electron-updater policy, CSP headers |
| DB degradation (scan_results growth) | Высокая | Среднее | TTL archival (90 дней), index optimization |
| Token abuse (один токен — много PC) | Средняя | Высокое | device fingerprinting, rate-limit per token |

---

## 📈 МЕТРИКИ УСПЕХА (v1.0.0)

| Метрика | Сейчас | Цель v1.0.0 |
|--------|--------|--------------|
| **Test coverage (desktop)** | ~2% (4 теста) | 20%+ (150+ тестов) |
| **Test coverage (server)** | 0% | 80%+ (48+ тестов) |
| **Test coverage (admin)** | 0% | 50%+ |
| **App startup time** | ~5s | <3s |
| **Full scan time** | 5-10 мин | <3 мин (parallel + incremental) |
| **False positive rate** | Unknown | <2% (tracked в Prometheus) |
| **Crash rate** | Unknown | <0.1% (crash.log мониторинг) |
| **API p95 latency** | ~200ms | <100ms |
| **Concurrent users (API)** | ~10 | 100+ |
| **Signature update time** | Code PR (часы) | <5 мин (JSON push → hot-reload) |
| **App.tsx lines** | ~400 | <150 (разбит на хуки) |
| **Admin bulk ops** | Нет | Approve/reject за 2 клика |
| **i18n languages** | 2 (ручной T) | 2+ (JSON locale, легко добавить) |

---

*План поддерживается командой Predator. Обновляется каждый спринт.*
*Принцип: THINK FIRST → Research → Propose → Implement by stages. Никогда не пропускать анализ.*
