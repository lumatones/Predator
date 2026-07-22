# Changelog

## [0.0.4] — 2026-07-22

### Добавлено

#### Backend API (`server/`)
- Express сервер на порту 3001 с MySQL (WAMP)
- JWT-авторизация администраторов (jsonwebtoken + bcryptjs)
- Система токенов доступа (32 символа, crypto.randomBytes)
- `POST /api/auth/token` — проверка токена
- `POST /api/auth/token/use` — проверка + отметка использования
- `POST /api/auth/request` — создание запроса на доступ (имя ПК)
- `GET /api/auth/status/:id` — статус запроса (pending/approved/rejected)
- `POST /api/admin/login` — вход администратора
- `GET /api/admin/pending` — ожидающие запросы
- `POST /api/admin/approve/:id` и `/reject/:id` — обработка запросов
- `POST /api/admin/tokens/generate` — генерация токенов (1–10)
- `GET /api/admin/tokens` — список всех токенов
- `POST /api/admin/tokens/revoke/:id` — отзыв токена
- `GET /api/admin/history` — объединённая история (токены + запросы)
- Auto-создание `.env` из `.env.example` при `npm install`
- Фильтрация истёкших запросов

#### Admin Site (`admin/`)
- Vite + React 19 + React Router 7 + TypeScript
- Тёмная тема в едином стиле Predator (анимации, glassmorphism)
- Страница Login: вход по логину/паролю, JWT в localStorage
- Dashboard: сводка по токенам и запросам
- Pending: запросы на доступ с кнопками Одобрить/Отклонить
- Tokens: генерация, копирование, отзыв токенов
- History: сортируемая таблица с фильтрами (все/токены/запросы) и поиском
- Sidebar с навигацией, аватаром пользователя, выходом
- Прокси `/api` → localhost:3001 через Vite
- Responsive дизайн (адаптация под мобильные)

#### Интеграция приложения с бэкендом
- API-клиент (`src/api.ts`): validateToken, useToken, requestAccess, checkRequestStatus
- Экран токена: реальная проверка через `POST /api/auth/token` + отметка использования
- Запрос доступа: отправка имени ПК, polling статуса каждые 3 сек
- IPC `get-pc-name`: получение имени пользователя ПК
- CSP обновлён для connect-src http://localhost:3001
- Фикс: `pool.execute()` → `pool.query()` для совместимости с `LIMIT ?`

#### Экран чекера (`src/pages/Checker.tsx`)
- Файловый сканер в Electron main process (`electron/scanner.ts`)
- Поиск в папках: Downloads, Desktop, Documents, AppData
- Целевые расширения: .js, .exe, .dll, .lua, .py, .bat и др.
- Ключевые слова: nightfall, cheat, hack, inject, bypass, aimbot, wallhack и др.
- Анализ риска: высокий/средний/низкий (по расширению + совпадениям)
- Проверка истории браузера (Chrome, Yandex, Opera)
- Анимация радара и прогресс-бар при сканировании
- Таблица результатов с деталями файла (путь, совпадения, риск)
- Кнопка Назад на главный экран, Очистить, Проверить снова
- Dev-режим: демо-скан с мок-данными без Electron

### Исправлено
- `EPERM: operation not permitted` — путь установки изменён с `C:\Program Files\` на `%LOCALAPPDATA%\Predator`
- `Cannot read properties of undefined (reading 'find')` — GitHub API без релизов
- Системная `PORT=62956` переопределяла `.env` — фикс приоритета .env
- `LIMIT ?` с prepared statements — переключение на `pool.query()`

## [0.0.3] — 2026-07-22

### Добавлено
- Auto-Updater через electron-updater
- Автоматическая проверка обновлений при запуске (через 1.5 сек после старта)
- Прогресс-бар загрузки с процентом, скоростью и размером
- Кнопка ручной проверки обновлений
- Скачивание и установка обновлений с GitHub Releases
- Обработка ошибок при проверке/загрузке
- 4-сек fallback timeout для dev-режима (без зависаний)
- Экран выбора языка: 🇷🇺 Русский / 🇬🇧 English
- Экран выбора темы: Predator Red, Ocean Blue, Stealth Black, Nebula Purple
- Экран авторизации: 32-символьный токен с автоформатированием XXXX-XXXX-XXXX-XXXX
- Динамическая смена темы через CSS custom properties + color-mix()
- Полный онбординг: обновления → язык → тема → токен → главный экран

## [0.0.2] — 2026-07-22

### Добавлено
- Инициализация Vite + React + TypeScript проекта
- Electron (main process + preload) с contextBridge
- Красивый UI: тёмная тема, градиенты, анимации, scan-line эффект
- Сгенерированы ресурсы для NSIS-инсталлера (sidebar/header битмапы, иконка 256×256 PNG)
- Кастомный NSIS скрипт (installer.nsh) с тёмной темой и русской локализацией
- electron-builder конфигурация для сборки .exe установщика
- Скрипт генерации ресурсов (pure Node.js, без зависимостей)
- Обработка ошибок загрузки в Electron main process

## [0.0.1] — 2026-07-22

### Добавлено
- Инициализация репозитория Predator
- README с описанием проекта
- RULES.md — правила разработки
- CHANGELOG.md — журнал изменений
- Настроен governing doc в Freebuff Desktop для памяти о проекте
