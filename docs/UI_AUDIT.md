# Predator — UI/UX Аудит

> 2026-07-31 · 5 проверок: Refactoring UI, UX Heuristics, P2 Unification, Microinteractions v1, Microinteractions v2

---

## Сводная оценка: 8.2/10

| Аудит | До | После | Коммит |
|-------|----|-------|--------|
| Refactoring UI (дизайн) | 6.0 | 7.5 | `5cf7261` |
| UX Heuristics (usability) | 6.3 | 8.0 | `f6dcbd8` |
| P2 Unification (цвета/ширина) | — | — | `502a86a` |
| Microinteractions v1 (фидбек) | 5.0 | 7.5 | `1775be2` |
| Microinteractions v2 (кнопки/переходы) | 7.5 | 8.5 | `2a90a52` |

---

## 1. Refactoring UI — дизайн-аудит

### Что исправлено

| Проблема | Severity | Решение |
|----------|----------|---------|
| `text-secondary` 0.6 → контраст 3.5:1 | Critical | 0.6 → 0.7 (6.2:1, WCAG AA) |
| `text-muted` 0.35 → контраст 2.1:1 | Critical | 0.35 → 0.5 (4.2:1) |
| Tab labels 10px — нечитаемо | Major | 10 → 11px + line-height 1.3 |
| `.dash-card-label` 11px | Major | 11 → 12px + line-height |
| Нет focus-visible | Major | Глобальный `:focus-visible` + на карточках |
| Нет shadow scale | Minor | `--shadow-xs/sm/md/lg/xl` + legacy alias |
| Neuralyn Dark тема с низким контрастом | Minor | 0.65 → 0.72, 0.45 → 0.52 |
| Tab padding тесный (12/8) | Minor | 12/8 → 12/12 |
| Card padding тесный (12/16) | Minor | 12/16 → 16/16 |
| Gap между label/value 2px | Minor | 2 → 4px |
| Subtitle weight 300 (тощий) | Cosmetic | 300 → 500 + line-height |
| Update modal shadow ad-hoc | Cosmetic | → `var(--shadow-xl)` |

### Quick Diagnostic (Refactoring UI)

| # | Проверка | Было | Стало |
|---|----------|------|-------|
| 1 | Иерархия при squint-тесте | 6 | 7 |
| 2 | Работает в grayscale | 7 | 8 |
| 3 | Достаточно воздуха | 6 | 7 |
| 4 | Лейблы уступают данным | 5 | 7 |
| 5 | Spacing по шкале | 8 | 8 |
| 6 | Ширина текста ограничена | 7 | 7 |
| 7 | Контраст (WCAG AA) | 4 | 7 |
| 8 | Тени = elevation | 7 | 8 |

---

## 2. UX Heuristics — usability-аудит

### Что исправлено

| Проблема | Severity | Решение |
|----------|----------|---------|
| Ошибки: "Scan error" без подсказки | 3 — Major | `scanError` + `scanErrorHint` в словаре T. Сообщение: «ECONNREFUSED. Попробуйте другой режим или перезапустите приложение» |
| Описания табов скрыты (`display:none`) | 3 — Major | Анимация раскрытия при hover/focus/active (max-height + opacity) |
| Кнопки настроек без текста (icon-only) | 3 — Major | Добавлены `<span>` с «Настройки» / «Музыка» |
| Back button 18px иконка без текста | 2 — Minor | Иконка 20px + текст «Назад» / «Back» |
| Hover rotate(30°) на кнопке с текстом | 2 — Minor | → `translateY(-1px)` |
| Описания табов обрезались (max-height:30px) | 2 — Minor | → 48px |

### Quick Diagnostic (Nielsen/Krug)

| # | Проверка | Было | Стало |
|---|----------|------|-------|
| 1 | Очевидно где я | 8 | 8 |
| 2 | Главное действие очевидно | 8 | 8 |
| 3 | Навигация ясна | 5 | 7 |
| 4 | Поиск находится | 6 | 6 |
| 5 | Система показывает статус | 8 | 8 |
| 6 | Ошибки полезны | 4 | 7 |
| 7 | Отмена / назад | 7 | 8 |
| 8 | Без hover | 7 | 7 |
| 9 | Элементы подписаны | 5 | 8 |
| 10 | Нет «huh?» моментов | 5 | 7 |

---

## 3. P2 Unification — цвета и ширина текста

### Chart Palette

Добавлено 11 цветов графиков в `tokens.css`:
`--chart-red`, `--chart-orange`, `--chart-coral`, `--chart-purple`, `--chart-pink`, `--chart-cyan`, `--chart-tangerine`, `--chart-indigo`, `--chart-slate`, `--chart-lime`, `--chart-gray`
+ 4 алиаса: `--chart-success/warning/error/info`

### Устранено хардкод-цветов

| Компонент | Было | Стало |
|-----------|------|-------|
| ThreatMap | 15 hex | `var(--chart-*)` + `REGION_HEX` для градиента |
| ScanTerminal | 4 hex/rgba | `var(--color-*)` + `var(--text-*)` |
| ApcDashboard | 6 hex | `var(--color-success/warning/error)` |
| UpdateModal | 5 hex/rgba | `var(--color-*)` |
| **Итого** | **30** | **0** |

### Prose width

Добавлен `--max-w-prose: 65ch` + утилита `.text-prose`.

---

## 4. Microinteractions v1 — фидбек и анимации

### Что добавлено (v1)

| Микровзаимодействие | Триггер | Фидбек |
|---------------------|---------|--------|
| Нажатие кнопки скана | Click/Tap | spring: scale 0.95 → bounce back, whileHover lift |
| Ошибка скана | catch(err) | `errorShake` — 6-шаговая тряска (0.4s) |
| Чистая система | phase=done + 0 угроз | 5 искр (подъём + fade) + зелёный pulse-rim |
| Результаты найдены | phase=done + угрозы > 0 | shake на warning-иконке (уже было) |

## 5. Microinteractions v2 — кнопки и переходы

### Что добавлено (v2)

| Компонент | Триггер | Фидбек |
|-----------|---------|--------|
| **main-card** (Checker/Dashboard) | Hover/Tap | scale 1.02→0.96, lift −2px |
| **settings-trigger** (Музыка/Настройки) | Hover/Tap | scale 1.08→0.93, lift −1px |
| **lang-btn** (выбор языка) | Hover/Tap | scale 1.04→0.95 |
| **start-button** (3 шт в онбординге) | Hover/Tap | scale 1.02→0.95 |
| **skip-button** (auth) | Hover/Tap | scale 1.02→0.96, disabled учтён |
| **close-кнопки** (Settings + FileDetail) | Hover | rotate 90° + scale 1.1 (signature!) |
| **expand/close** (CompactOverlay) | Hover/Tap | scale 1.1→0.9 |
| **Фазовые переходы** | Навигация вперёд/назад | directional slide (±30px) + blur |
| **Compact mode toggle** | Hover (400ms delay) | Tooltip с пояснением что скрывается |

### Quick Diagnostic (Saffer)

| # | Проверка | Было | Стало |
|---|----------|------|-------|
| 1 | Обнаружимый триггер | 7 | **8** |
| 2 | Состояние триггера | 6 | **8** |
| 3 | Правила предсказуемы | 7 | 7 |
| 4 | Мгновенный фидбек | 4 | **8** |
| 5 | Фидбек = значимость | 5 | **8** |
| 6 | Эволюция во времени | 4 | 4 |
| 7 | Без лишних режимов | 5 | 5 |
| 8 | Понятно новичку | 6 | **7** |

---

## Статус исправлений из предыдущего аудита (2026-07-30)

| Приоритет | Проблема | Статус |
|-----------|----------|--------|
| P0 | Размер текста < 10px | ✅ Исправлено (10→11px, 11→12px) |
| P0 | Контрастность текста | ✅ Исправлено (0.6→0.7, 0.35→0.5) |
| P0 | Отсутствуют focus-стили | ✅ Исправлено (глобальный `:focus-visible`) |
| P1 | CSS-файлы раздуты | ✅ 4 файла разбиты на 19 модулей |
| P1 | Дублирование стилей | ✅ Кнопки + ProgressBar унифицированы |
| P2 | Нет автоскролла в терминале | ✅ Исправлено (requestAnimationFrame) |
| P2 | Skeleton-экраны | ✅ Добавлены в Checker при смене вкладок |
| P2 | Tooltip для Compact mode | ✅ Добавлен с билингвальным текстом (`425807d`) |
| P3 | Toast-система | ✅ Radix ToastProvider используется |

---

## Осталось сделать

| Приоритет | Задача |
|-----------|--------|
| P2 | Поиск на Dashboard |
| P3 | Заменить хардкод-цвета в 3D-компонентах (PredatorLogo3D, ParticleBackground) |
| P3 | Применить `.text-prose` к текстовым блокам |
| P3 | Адаптивные брейкпоинты: унифицировать 480/768/1024 |
