# Predator 🦅

**Система проверки безопасности для GTA 5 RP**

<p align="center">
  <a href="https://github.com/lumatones/Predator/releases/latest">
    <img src="https://img.shields.io/badge/Скачать_Predator-ff4444?style=for-the-badge&logo=windows&logoColor=white&labelColor=1a1a2e" alt="Download Predator">
  </a>
  <br>
  <a href="https://github.com/lumatones/Predator/releases">
    <img src="https://img.shields.io/github/v/release/lumatones/Predator?style=flat-square&label=Версия&color=ff4444" alt="Version">
  </a>
  <a href="https://github.com/lumatones/Predator/releases">
    <img src="https://img.shields.io/github/downloads/lumatones/Predator/total?style=flat-square&label=Скачиваний&color=ff6b35" alt="Downloads">
  </a>
  <a href="https://github.com/lumatones/Predator/actions/workflows/release.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/lumatones/Predator/release.yml?style=flat-square&label=Build&color=3B82F6" alt="Build">
  </a>
</p>

Predator — десктопное приложение для обнаружения следов стороннего ПО (читов) на компьютере пользователя. Проводит комплексную проверку в **6 режимах**: файлы, процессы, поиск читов, DMA-устройства, расширенное сканирование и сеть.

Полная экосистема: десктопное приложение → API-сервер → админ-панель.

---

## ⬇️ Установка

1. Скачайте последнюю версию из [Releases](https://github.com/lumatones/Predator/releases)
2. Запустите скачанный `.exe` файл
3. После первого запуска приложение само предложит обновления (auto-updater)

> **Системные требования:** Windows 10/11, 64-bit

---

## 🚀 Первый запуск

При первом запуске приложение проведёт вас через несколько шагов:

1. **Язык** 🇷🇺 / 🇬🇧
2. **Тема оформления** — выберите цветовую схему (Predator Red, Ocean Blue, Stealth Black, Nebula Purple)
3. **Авторизация** — введите токен доступа или запросите его через сайт

После авторизации открывается главный экран с кнопками:
- **Начать проверку** → открывает сканер
- **Мониторинг** → системный дашборд (CPU/RAM/температура)
- **Статистика** → графики по истории сканирований

---

## 🔍 Режимы проверки

| Режим | Иконка | Описание |
|-------|--------|----------|
| **Файлы** | 📁 | Поиск подозрительных файлов и скриптов (JS, DLL, LUA, ASI...) |
| **Процессы** | ⚙️ | Проверка запущенных процессов, недавних элементов и Prefetch |
| **Читы** | 🎯 | Поиск Nightfall, DMA, 0Xcheat, 1337 Cheat, Noleet и других |
| **DMA** | 🔌 | Обнаружение DMA-карт и FPGA-устройств (Xilinx, Altera, FTDI) |
| **Расширенный** | 🛡️ | Полное сканирование: энтропия, YARA-правила, PE-анализ, Prefetch, реестр, сеть |
| **Сеть** | 🌐 | DNS-кеш, hosts файл, активные подключения, подозрительные IP/порты |

### 🧬 Расширенный режим (8 этапов)

1. **Продвинутая проверка процессов** — DLL-модули, загрузчики
2. **Эвристический анализ файлов** — энтропия, YARA (8 правил), PE-секции, digital signature
3. **Глубокая проверка реестра** — 9 категорий угроз, Winlogon
4. **Анализ Prefetch** — история запусков по категориям
5. **Сетевые соединения** — прокси/VPN порты, подозрительные IP
6. **Обнаружение DMA** — PCI-устройства, драйверы, registry
7. **Стандартный поиск читов** — реестр
8. **История браузера** — SQLite-парсер (Chrome, Edge, Yandex, Opera)

После сканирования доступен:
- 🔍 **Поиск по результатам** — фильтрация по имени, пути или совпадениям
- 📊 **Экспорт отчёта** — HTML с Chart.js или JSON
- 📤 **Отправка на сервер** — результаты сохраняются на бэкенде

---

## 📡 Архитектура системы

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  PREDATOR APP    │     │   BACKEND API    │     │   ADMIN SITE     │
│  (Electron)      │◄───►│  localhost:3001  │◄───►│  localhost:5173  │
│                  │     │                  │     │                  │
│  ┌──────────┐    │     │  ┌────────────┐  │     │  ┌──────────┐   │
│  │Сканер    │    │     │  │Express 4   │  │     │  │Вход      │   │
│  │Дашборд   │    │     │  │MySQL 8     │  │     │  │Запросы   │   │
│  │Статистика│    │     │  │Socket.IO   │◄─┼───  │  │Токены    │   │
│  │IPC Stream│    │     │  │JWT Auth    │  │  ┌──┼──┤История   │   │
│  └──────────┘    │     │  └────────────┘  │  │  │  │Графики   │   │
└──────────────────┘     └──────────────────┘  │  │  └──────────┘   │
                                                │  └────────────────┘
                                                │
                                        WebSocket (Socket.IO)
                                        События: new-request,
                                        request-update,
                                        token-generated, scan-result
```

---

## 🔄 Обновления

Приложение автоматически проверяет наличие новой версии:

- **При запуске** — через 1.5 секунды после старта
- **Фоном** — каждые 5 минут, даже если вы не перезапускали приложение
- **По WebSocket** — админ-панель получает real-time уведомления

Рядом с версией в футере загорается красная пульсирующая точка ●, если обновление доступно.

---

## 🌐 API Endpoints

### Auth (публичные)
| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/auth/token` | Проверить 32-символьный токен |
| POST | `/api/auth/token/use` | Активировать токен (с именем ПК) |
| POST | `/api/auth/request` | Создать запрос на доступ |
| GET | `/api/auth/status/:id` | Статус запроса |
| POST | `/api/auth/submit-scan` | Отправить результаты сканирования (`token_id` обязателен) |

### Admin (требуется JWT)
| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/admin/login` | Вход администратора |
| GET | `/api/admin/pending` | Ожидающие запросы |
| POST | `/api/admin/approve/:id` | Одобрить запрос |
| POST | `/api/admin/reject/:id` | Отклонить |
| POST | `/api/admin/tokens/generate` | Создать токены (1–10) |
| GET | `/api/admin/tokens` | Список токенов |
| POST | `/api/admin/tokens/revoke/:id` | Отозвать токен |
| GET | `/api/admin/history` | История событий |
| GET | `/api/admin/scan-stats` | Статистика сканирований |

---

## 🔒 Безопасность

- Все эндпоинты используют параметризованные SQL-запросы
- `token_id` проверяется в БД перед сохранением результатов
- Админ-эндпоинты защищены JWT (24h expiry)
- Токены доступа — 32-символьные hex (crypto.randomBytes)
- Пароли — bcrypt + salt
- Приложение работает в изолированном окружении Electron

---

## 💻 Разработка

```bash
# Десктопное приложение
npm run dev            # Vite dev server
npm run electron:dev   # Electron + Vite

# Backend
cd server
npm start

# Admin panel
cd admin
npm run dev
```

### Сборка релиза

```bash
npm run electron:build:win     # Собрать .exe
node scripts/generate-latest-yml.js  # latest.yml
node scripts/upload-release.js       # Загрузить на GitHub
```

---

## 📄 Лицензия

Все права защищены. Несанкционированное копирование или распространение запрещено.
