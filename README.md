# Predator 🦅

**Система проверки безопасности для GTA 5 RP (Majestic)**

<p align="center">
  <a href="https://github.com/lumatones/Predator/releases/latest/download/Predator-0.0.4.exe">
    <img src="https://img.shields.io/badge/Скачать_Predator-0.0.4-8B5CF6?style=for-the-badge&logo=windows&logoColor=white&labelColor=1a1a2e" alt="Download Predator">
  </a>
  <br>
  <a href="https://github.com/lumatones/Predator/releases">
    <img src="https://img.shields.io/github/v/release/lumatones/Predator?style=flat-square&label=Версия&color=8B5CF6" alt="Version">
  </a>
  <a href="https://github.com/lumatones/Predator/releases">
    <img src="https://img.shields.io/github/downloads/lumatones/Predator/total?style=flat-square&label=Скачиваний&color=A78BFA" alt="Downloads">
  </a>
  <a href="https://github.com/lumatones/Predator">
    <img src="https://img.shields.io/github/last-commit/lumatones/Predator?style=flat-square&label=Обновлено&color=C084FC" alt="Last commit">
  </a>
  <a href="https://github.com/lumatones/Predator/actions/workflows/release.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/lumatones/Predator/release.yml?style=flat-square&label=Сборка&color=10B981" alt="Build status">
  </a>
</p>

Predator — десктопное приложение для поиска следов стороннего ПО (читов) на компьютере пользователя. Проверяет файловую систему, историю браузера и другие артефакты.

---

## ⬇️ Скачать установщик

| Версия | Ссылка | Размер |
|--------|--------|--------|
| **v0.0.4** (latest) | [📥 Predator-0.0.4.exe](https://github.com/lumatones/Predator/releases/download/v0.0.4/Predator-0.0.4.exe) | ~72 MB |
| Все релизы | [→ GitHub Releases](https://github.com/lumatones/Predator/releases) | — |

> 💡 **Как установить:** Скачайте `Predator-0.0.4.exe`, запустите двойным кликом и следуйте инструкциям установщика.

---

## 🚀 Быстрый старт (для разработки)

```bash
# Установка зависимостей
npm install

# Запуск в режиме разработки
npm run dev

# Сборка portable .exe
npm run electron:build:win
```

---

## 📦 Версии

| Версия | Дата | Что нового |
|--------|------|-----------|
| **v0.0.4** | 2026-07-22 | Backend API, Admin Site, Checker (сканирование файлов) |
| **v0.0.3** | 2026-07-22 | Auto-Updater, онбординг (язык/тема/токен) |
| **v0.0.2** | 2026-07-22 | Vite + React + Electron, UI, NSIS-ресурсы |
| **v0.0.1** | 2026-07-22 | Инициализация репозитория |

---

## 🏗 Технический стек

### Основное приложение (`src/` + `electron/`)

| Компонент | Технология |
|-----------|-----------|
| Frontend | Vite 6 + React 19 + TypeScript 5 |
| Desktop | Electron 33 |
| Auto-Updater | electron-updater (GitHub Releases) |
| Сборка | electron-builder (portable .exe) |

### Установщик (`installer/`)

| Компонент | Технология |
|-----------|-----------|
| UI | HTML + CSS (glassmorphism, frameless) |
| Desktop | Electron 33 |
| Сборка | electron-builder (portable .exe) |

---

## 🗂 Структура проекта

```
Predator/
├── src/                    ← Основное React-приложение
│   ├── App.tsx             ← Главный компонент (автоапдейтер + онбординг + главный экран)
│   ├── App.css             ← Тёмная тема, анимации, glassmorphism
│   ├── main.tsx            ← React entry point
│   └── types/
│       └── electron.d.ts   ← TypeScript типы для IPC
├── electron/
│   ├── main.ts             ← Electron main process (auto-updater, IPC handlers)
│   └── preload.ts          ← contextBridge (IPC мост)
├── installer/              ← Electron-приложение-установщик
│   ├── main.js             ← Frameless window, загрузка с GitHub, установка
│   ├── preload.js          ← IPC мост для установщика
│   └── src/
│       ├── index.html      ← 2-панельный glassmorphism UI
│       ├── styles.css      ← Тёмная тема, purple → red palette
│       └── renderer.js     ← Логика установки (прогресс, лог, retry)
├── scripts/
│   └── generate-resources.js  ← Генератор BMP/PNG/ICO (pure Node.js)
├── resources/              ← Иконки, битмапы для NSIS
├── release/                ← Сборка основного приложения (portable .exe)
├── release-installer/      ← Сборка установщика
├── RULES.md                ← Правила разработки
├── CHANGELOG.md            ← Журнал изменений
└── package.json            ← Основной проект (v0.0.3)
```

---

## 🎨 Функционал

### Auto-Updater
- Автопроверка обновлений через 1.5 сек после запуска
- Прогресс-бар с процентом, скоростью и размером
- Кнопка "Установить и перезапустить"
- Fallback 4 секунды (не зависает в dev-режиме)

### Онбординг (первый запуск)
1. **Выбор языка** 🇷🇺 Русский / 🇬🇧 English
2. **Выбор темы** 🔴 Predator Red / 🔵 Ocean Blue / ⚫ Stealth Black / 🟣 Nebula Purple
3. **Авторизация** — 32-символьный токен с автоформатированием XXXX-XXXX-XXXX-XXXX

### Установщик
- Electron-приложение с премиальным glassmorphism дизайном
- Выбор пути установки и сервера загрузки
- Прогресс-бар, лог установки, retry при ошибке
- Создание ярлыков (рабочий стол + меню Пуск)
- Загрузка последней версии с GitHub Releases

---

## 🔒 Безопасность

- `contextIsolation: true` — изоляция процессов
- `nodeIntegration: false` — Node.js недоступен из рендерера
- CSP — Content Security Policy настроена
- preload script — только bridge через contextBridge

---

## 🛠 Скрипты

| Команда | Описание |
|---------|----------|
| `npm run dev` | Запуск Vite dev server |
| `npm run build` | TypeScript + Vite build |
| `npm run electron:build:win` | Сборка portable .exe |
| `npm run generate:resources` | Генерация иконок и битмапов |

**Установщик:**
```bash
cd installer
npm install
npm run build        # сборка Predator Installer-1.0.0.exe
```

---

## 📄 Лицензия

MIT
