# Predator — Структура CSS

> 26 файлов · 7 434 строки · 2026-07-31

---

## Дерево файлов

```
src/styles/
├── tokens.css                   169  Design tokens: цвета, шрифты, spacing, shadow scale, chart palette
├── layout.css                   348  Фон, контейнер, логотип, scrollbar, курсор
├── components.css               278  Main cards, footer, update-indicator, skeleton, toast, shared classes
│
├── Components (5 модулей)
├── components-buttons.css       171  Button, spinner, progress bar, ready state
├── components-glass-eye.css     619  Glass eye, red screen, scary mode, sonar rings
├── components-music-player.css  722  Music panel, mini player, EQ, controls
├── components-settings.css      211  Settings panel, theme grid, floating buttons
│
├── Checker (4 модуля)
├── checker-core.css            1248  Wrapper, header, tabs, scan button, idle, scanning, summary, error, search, skeleton
├── checker-groups.css           923  Result groups, cheat groups, device section, export actions
├── checker-modal.css            556  File detail modal, hash detail modal
├── checker-terminal.css         154  Scan terminal, CRT overlay, stats bar
│
├── Dashboard (8 модулей)
├── dashboard.css                718  Update modal, server status, info cards, typography utils, Neuralyn Dark theme
├── dashboard-gauges.css          48  Speedometer gauges (CPU, RAM, temp)
├── dashboard-processes.css       74  Process list, filter, empty state
├── dashboard-stats.css           29  Stats wrapper, clear button
├── dashboard-stats-cards.css     56  Summary cards, sections
├── dashboard-stats-chart.css    103  Bar chart, top cheats list
├── dashboard-stats-dirs.css      68  Hot directories
├── dashboard-stats-modes.css     44  Scan by mode
├── dashboard-threat-map.css      86  Threat map bars, dot indicators
│
├── Onboarding (5 модулей)
├── onboarding.css                 3  Comment header
├── onboarding-welcome.css        36  Status card, labels
├── onboarding-demo.css          106  Step indicators, actions, btnSlideUp
├── onboarding-steps.css         218  Language grid, theme grids (old + new)
├── onboarding-auth.css           58  Token input, error, request badge
├── onboarding-v2.css            388  v2 onboarding styles
│
└── Итого: 26 файлов, 7 434 строки
```

## Группировка по функциональности

| Группа | Файлов | Строк | Покрытие |
|--------|--------|-------|----------|
| Core (tokens + layout + components) | 3 | 795 | Дизайн-система, общие компоненты |
| Components | 5 | 1 894 | Кнопки, глаз, плеер, настройки |
| Checker | 4 | 2 881 | Сканер: табы, результаты, терминал, модалки |
| Dashboard | 8 | 1 226 | Дашборд: статистика, процессы, графики |
| Onboarding | 5 | 803 | Онбординг: шаги, темы, авторизация |
| **Всего** | **26** | **7 434** | |

## История рефакторинга

| Дата | Файл | Было | Стало |
|------|------|------|-------|
| 2026-07-30 | `checker.css` | 2 880 строк | 4 модуля |
| 2026-07-30 | `admin/App.css` | 3 709 строк | 5 модулей |
| 2026-07-31 | `components.css` | 1 960 строк | 5 модулей |
| 2026-07-31 | `dashboard.css` | 1 219 строк | 5 модулей |
| 2026-07-31 | `dashboard-stats.css` | 308 строк | 5 модулей |
| 2026-07-31 | `onboarding.css` | 421 строка | 5 модулей |
| **Итого** | **~10 497 строк** | **29 файлов** |

## Shared Classes (components.css)

После P2-унификации в `components.css` добавлены общие классы:

| Класс | Назначение | Где используется |
|-------|-----------|-----------------|
| `.card-section` | bg 0.02 + border + radius-lg + hover | ThreatMap, dash-processes, checker-summary |
| `.section-title` | xs bold uppercase 0.5px, mb-3 | threat-map-title, stats-section-title |
| `.status-dot` | 8px circle + color modifiers | (ожидает применения) |

## Основные токены (tokens.css)

```
Цвета:       --bg-primary/secondary, --text-primary/secondary/muted
Акценты:     --accent-red, --accent-orange, --accent-gradient
Семантика:   --color-success/warning/error/info + dim/glow варианты
Chart:       --chart-* (11 цветов + 4 алиаса)
Тени:        --shadow-xs/sm/md/lg/xl
Типографика: --text-2xs..4xl (11-32px), --font-display/heading/body/code
Spacing:     --space-1..16 (4-64px)
Радиусы:     --radius-sm/md/lg/xl/full
Анимации:    --ease-out/spring/smooth, --duration-fast/normal/slow
Layout:      --container-max: 680px, --max-w-prose: 65ch
```
