# 🎨 Predator Admin Panel — План редизайна с 3D-эффектами

> **Цель:** Превратить текущую функциональную, но визуально простую админку в премиальный cyberpunk/glassmorphism дашборд с 3D-эффектами, плавными анимациями и иммерсивным опытом.
>
> **Целевая модель:** Kimi-k2.7 (дизайн-ориентированная) или Claude с доступом к Three.js/Framer Motion.
>
> **Стек:** React 18 + TypeScript + Framer Motion + Three.js (React Three Fiber) + Tailwind CSS + shadcn/ui

---

## 📐 Текущее состояние (аудит)

| Страница | Файл | Состояние |
|----------|------|-----------|
| **Login** | `admin/src/pages/Login.tsx` | Минимальная форма + 3 glass-орба (CSS). Хорошая база. |
| **Dashboard** | `admin/src/pages/Dashboard.tsx` | 6 stat-карточек + 2 графика (Chart.js) + 2 таблицы + WebSocket toast. Функционально, но уныло. |
| **Pending** | `admin/src/pages/Pending.tsx` | Таблица запросов + countdown-таймер + approve/reject. |
| **Tokens** | `admin/src/pages/Tokens.tsx` | Форма генерации + таблица + health gauge. |
| **History** | `admin/src/pages/History.tsx` | Таблица с фильтрами + поиск + 3 stat-карточки. |
| **SuspiciousHashes** | `admin/src/pages/SuspiciousHashes.tsx` | 4 вкладки (pending/confirmed/false_positive/scan_results) + таблица. |
| **Layout** | `admin/src/components/Layout.tsx` | Sidebar с навигацией + user-footer. |
| **Стили** | `admin/src/App.css` | 700+ строк. Хорошая дизайн-система (CSS variables), но нет анимаций. |

**Проблемы:**
- ❌ Таблицы выглядят как Excel 2010
- ❌ Графики базовые (Chart.js без кастомизации)
- ❌ Нет микро-анимаций (hover, переходы, skeleton loading)
- ❌ Нет 3D-эффектов (всё плоско)
- ❌ Нет частиц / фоновых эффектов
- ❌ Логин — единственная страница с glassmorphism
- ❌ Emoji в иконках stat-карточек (вместо SVG)

---

## 🎯 Целевое состояние: страница за страницей

### 1. 🔐 Login Page — "Predator Command Center Access"

**Концепция:** Тёмный cyberpunk-терминал с 3D-щитом Predator, вращающимся на фоне.

#### 3D-эффекты:
- **Three.js фон:** Вращающийся 3D-логотип Predator (гексагональный щит) с glow-эффектом. Рендерится через React Three Fiber.
- **Particle field:** `tsparticles` — красные светящиеся частицы, медленно дрейфующие как «сетевой трафик».
- **Scan line effect:** CSS-анимация горизонтальной линии сканирования (как в Terminator), пробегает по экрану каждые 5 секунд.

#### Анимации (Framer Motion):
```
Карточка логина:
- Появление: scale(0.9) → scale(1) + fade in (0.6s, spring)
- Input focus: border-glow расширяется как пульс
- Кнопка: hover → elevation +3px, glow усиливается
- Ошибка: shake-анимация (3 цикла)
- Успешный вход: карточка "схлопывается" с частицами
```

#### UI-спецификация:
```css
.login-wrapper {
  background: radial-gradient(ellipse at center, #0d0d1a 0%, #050510 100%);
  /* + Three.js canvas behind */
  /* + tsparticles overlay */
}

.login-card {
  background: rgba(10, 10, 22, 0.85);
  backdrop-filter: blur(24px);
  border: 1px solid rgba(255, 68, 68, 0.15);
  border-radius: 16px;
  box-shadow: 0 0 60px rgba(255, 68, 68, 0.08),
              0 0 120px rgba(255, 68, 68, 0.03),
              inset 0 1px 0 rgba(255, 255, 255, 0.03);
}

/* Terminal scan line */
.login-wrapper::after {
  content: '';
  position: absolute; top: 0; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, rgba(255,68,68,0.3), transparent);
  animation: scan-line 5s linear infinite;
}
```

---

### 2. 📊 Dashboard — "Predator Command Center"

**Концепция:** SOC (Security Operations Center) — центральный командный пункт с живыми данными, пульсирующими индикаторами и картой угроз.

#### 3D-эффекты:
- **3D Globe Threat Map (левый верх):** Трёхмерная сфера с точками угроз (красные пульсары на карте мира). React Three Fiber + Drei `<Sphere>` с кастомным шейдером.
- **Particle Network (фон):** Лёгкие соединительные линии между stat-карточками (canvas-анимация).
- **Pulse Rings:** У каждой stat-карточки — анимированные концентрические кольца (CSS `@keyframes pulse-ring`).

#### Анимации (Framer Motion):
```
Stat-карточки:
- Stagger-анимация появления (каждая с задержкой 100ms)
- Hover: scale(1.02) + border-glow + фон слегка светлеет
- Цифры: count-up анимация (useSpring)
- WebSocket обновление: число вспыхивает и гаснет

Графики:
- Анимированные переходы между данными (Recharts с animate={true})
- Doughnut chart: сегменты выезжают с rotation-анимацией

Таблицы:
- Строки появляются с fade-in + slide-up stagger
- Hover: строка подсвечивается + слева появляется accent-полоска
- Skeleton loading: пульсирующие placeholder-строки

WebSocket индикатор:
- Connected: зелёная точка с breathing-анимацией
- Disconnected: красная точка с быстрой пульсацией
```

#### UI-спецификация:
```tsx
// Stat-карточка с 3D-эффектом
<motion.div
  className="stat-card group"
  whileHover={{ scale: 1.02, y: -2 }}
  transition={{ type: 'spring', stiffness: 400, damping: 25 }}
>
  {/* Pulse ring — абсолютно позиционированная окружность */}
  <div className="stat-pulse-ring" />
  
  {/* Иконка — заменяем emoji на SVG-иконки Predator */}
  <ShieldIcon className="stat-icon" />
  
  {/* Значение с count-up */}
  <AnimatedNumber value={stats.pendingCount} />
</motion.div>
```

#### Новые графики (замена Chart.js → Recharts):
| Текущий | Новый |
|---------|-------|
| Bar chart (Chart.js) | Recharts `<AreaChart>` с градиентной заливкой |
| Doughnut (Chart.js) | Recharts `<PieChart>` с кастомными label-ами и анимацией |
| — | **+ Threat Timeline** (линейный график угроз по времени) |
| — | **+ Heatmap** (активность по дням/часам) |

---

### 3. 📋 Pending Page — "Access Requests"

**Концепция:** Карточки запросов с таймером обратного отсчёта и swipe-жестами (Tinder-style для одобрения/отклонения).

#### Анимации:
```
Список запросов:
- Карточки вместо таблицы (card layout)
- Новая заявка: slide-in слева + badge "NEW" пульсирует
- Approve: карточка "улетает" вправо зелёным следом
- Reject: карточка "улетает" влево красным следом + shake

Countdown:
- Круговой progress-бар (SVG circle с dasharray)
- < 5 минут: красная пульсация + vibration-эффект
- Истёк: grey out + перечёркивание
```

#### UI-спецификация:
```tsx
// Вместо таблицы — карточки в grid
<div className="request-cards-grid">
  {requests.map((req, i) => (
    <motion.div
      key={req.id}
      className="request-card"
      initial={{ opacity: 0, x: -40 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: i * 0.08 }}
      exit={{ opacity: 0, x: action === 'approve' ? 200 : -200 }}
    >
      <div className="request-card-header">
        <Avatar name={req.pc_username} />
        <CountdownCircle expiresAt={req.expires_at} />
      </div>
      <div className="request-card-body">
        <h3>{req.pc_username}</h3>
        <p>Запросил доступ {formatRelative(req.created_at)}</p>
      </div>
      <div className="request-card-actions">
        <Button variant="approve" onClick={handleApprove}>Одобрить</Button>
        <Button variant="reject" onClick={handleReject}>Отклонить</Button>
      </div>
    </motion.div>
  ))}
</div>
```

---

### 4. 🔑 Tokens Page — "Token Management"

**Концепция:** Терминал генерации ключей с анимацией «печати» и glass-карточками токенов.

#### Анимации:
```
Генерация токенов:
- Кнопка "Сгенерировать": progress-бар внутри кнопки
- Новые токены: "печатаются" посимвольно (typewriter effect)
- Токен-карточка: появляется из центра с blur → sharp transition

Health Gauge:
- Замена статичного progress-bar на анимированный градиентный
- Пульсация когда активных токенов < 2
- SVG gauge с дугой (как спидометр)

Revoke:
- Токен "перечёркивается" красной линией
- Строка fading to grey
```

#### 3D-эффект:
- Фон страницы: матрица из падающих hex-символов (Matrix rain) на очень низкой прозрачности

---

### 5. 📜 History Page — "Event Timeline"

**Концепция:** Визуальный таймлайн событий вместо скучной таблицы.

#### UI:
```
Вместо таблицы:
- Вертикальный timeline с точками
- Токены — синие точки, Запросы — зелёные/красные
- Hover на точке — показывает детали в tooltip
- Фильтр: анимированные pill-кнопки (все / токены / запросы)

Поиск:
- Search bar с иконкой-лупой и анимацией раскрытия
- Мгновенный фильтр с blur-эффектом на несовпадающих элементах
```

#### Анимации:
```
Timeline:
- Точки появляются снизу вверх (stagger)
- Линия таймлайна "прорастает" (SVG line drawing)
- Скролл: parallax-эффект на элементах
```

---

### 6. 🧬 Suspicious Hashes — "Threat Database"

**Концепция:** Лаборатория анализа угроз — карточки хешей с визуализацией бинарных данных.

#### 3D-эффекты:
- **DNA-подобная спираль** из SHA256-символов на фоне (Three.js)
- Хеш-строки анимированно «переливаются» при hover

#### Анимации:
```
Вкладки:
- Переключение с sliding-индикатором (как iOS segmented control)
- Контент: crossfade между вкладками

Подтверждение чита:
- Confetti-анимация (react-confetti) при подтверждении
- Карточка "улетает" в облачную базу

Ложное срабатывание:
- Карточка перечёркивается и fading to 0.3 opacity
```

---

## 🎨 Дизайн-система (обновлённая)

### Цветовая палитра
```css
:root {
  /* Primary bg — глубже и насыщеннее */
  --bg-primary: #06060e;
  --bg-secondary: #0c0c1a;
  --bg-card: rgba(12, 12, 26, 0.85);

  /* Accent — Predator Red с градиентом */
  --accent: #ff3b3b;
  --accent-glow: rgba(255, 59, 59, 0.4);
  --accent-gradient: linear-gradient(135deg, #ff3b3b 0%, #ff6b35 50%, #ff3b3b 100%);

  /* Новые цвета для глубины */
  --neon-cyan: #00f0ff;      /* Для кибер-элементов */
  --electric-violet: #7c3aed; /* Для secondary-акцентов */
  --warning-amber: #f59e0b;   /* Для alert-элементов */

  /* Glass */
  --glass-bg: rgba(255, 255, 255, 0.03);
  --glass-border: rgba(255, 255, 255, 0.06);
  --glass-blur: 20px;
}
```

### Типографика
```css
--font-display: 'JetBrains Mono', monospace;  /* Заголовки, коды, токены */
--font-heading: 'Inter', sans-serif;           /* H1-H4 */
--font-body: 'Inter', sans-serif;              /* Основной текст */
```

### Тени (3D depth)
```css
/* Уровни elevation */
--shadow-sm: 0 1px 3px rgba(0,0,0,0.4);
--shadow-md: 0 4px 12px rgba(0,0,0,0.5), 0 0 30px rgba(255,59,59,0.05);
--shadow-lg: 0 8px 30px rgba(0,0,0,0.6), 0 0 60px rgba(255,59,59,0.08);
--shadow-glow: 0 0 40px rgba(255,59,59,0.15), 0 0 80px rgba(255,59,59,0.05);

/* Card with 3D tilt */
--card-3d: 
  0 20px 60px rgba(0,0,0,0.6),
  0 0 0 1px rgba(255,255,255,0.04),
  inset 0 1px 0 rgba(255,255,255,0.03);
```

---

## 🧩 Компоненты (новые)

| Компонент | Файл | Описание |
|-----------|------|----------|
| `<AnimatedNumber />` | `components/AnimatedNumber.tsx` | Число с count-up анимацией (useSpring) |
| `<StatCard3D />` | `components/StatCard3D.tsx` | Карточка с pulse-ring, tilt-эффектом, glow |
| `<CountdownCircle />` | `components/CountdownCircle.tsx` | SVG-круговой таймер с анимацией |
| `<ParticleBackground />` | `components/ParticleBackground.tsx` | tsparticles фон для всех страниц |
| `<ThreatGlobe />` | `components/ThreatGlobe.tsx` | Three.js 3D-сфера с точками угроз |
| `<PredatorLogo3D />` | `components/PredatorLogo3D.tsx` | Вращающийся 3D-щит для логина |
| `<ScanLine />` | `components/ScanLine.tsx` | Горизонтальная линия сканирования |
| `<Timeline />` | `components/Timeline.tsx` | Вертикальный таймлайн для истории |
| `<Skeleton />` | `components/Skeleton.tsx` | Пульсирующие плейсхолдеры |
| `<TypewriterText />` | `components/TypewriterText.tsx` | Посимвольная печать (для токенов) |
| `<Toast3D />` | `components/Toast3d.tsx` | Улучшенные toast-уведомления с анимацией |

---

## 📦 Технический стек

| Слой | Текущий | Новый |
|------|---------|-------|
| **3D** | — | `@react-three/fiber` + `@react-three/drei` + `three` |
| **Анимации** | CSS keyframes | `framer-motion` (уже есть?) |
| **Частицы** | CSS orbs | `@tsparticles/react` (или `react-tsparticles`) |
| **Графики** | `chart.js` + `react-chartjs-2` | `recharts` (React-native, лучше анимации) |
| **UI-компоненты** | Чистый CSS | `@shadcn/ui` (Tailwind-based) |
| **Иконки** | Emoji + Raw SVG | `lucide-react` (единый стиль) |
| **3D tilt** | — | `react-parallax-tilt` (опционально) |

### Установка:
```bash
cd admin

# 3D
npm install three @react-three/fiber @react-three/drei

# Particles
npm install @tsparticles/react @tsparticles/slim

# Charts
npm uninstall chart.js react-chartjs-2
npm install recharts

# Icons
npm install lucide-react

# Optional: 3D tilt on cards
npm install react-parallax-tilt
```

---

## 📝 Промпт для Kimi-k2.7 (или другой дизайн-модели)

### Prompt 1: Login Page (3D)

```
Создай React-компонент LoginPage для админ-панели Predator (античит-система).

Дизайн: Cyberpunk Security Terminal с 3D-эффектами.

Технические требования:
1. Используй React Three Fiber (@react-three/fiber) для 3D-фона:
   - Вращающийся гексагональный щит Predator (логотип) с emission-материалом (#ff3b3b)
   - 3D-частицы, медленно вращающиеся вокруг щита
   - Glow-эффект через Bloom post-processing (@react-three/postprocessing)

2. Используй @tsparticles/react для фоновых частиц:
   - Красные светящиеся точки (#ff3b3b, opacity 0.3)
   - Медленное движение вверх (как data-поток)
   - Соединительные линии между ближайшими частицами

3. Используй framer-motion для UI-анимаций:
   - Карточка логина: scale(0.9)→1, opacity 0→1, spring-анимация
   - Input focus: градиентная border-glow анимация
   - Кнопка: hover → translateY(-2px), glow усиливается
   - Ошибка: shake-анимация (translateX ±5px, 3 цикла)
   - Успех: карточка scale(1.1)→0, opacity 1→0, частицы разлетаются

4. Glassmorphism-карточка:
   - background: rgba(10, 10, 26, 0.85), backdrop-filter: blur(24px)
   - border: 1px solid rgba(255, 59, 59, 0.15)
   - box-shadow с accent-glow

5. Scan-line эффект:
   - CSS-псевдоэлемент ::after — горизонтальная линия
   - Проходит сверху вниз каждые 5 секунд
   - Цвет: rgba(255, 59, 59, 0.3)

6. Типографика:
   - Заголовок "Predator" — JetBrains Mono, gradient text (accent-gradient)
   - Input labels — uppercase tracking-wider, 11px
   - Placeholder — muted color

Цвета:
- bg: #06060e → #0c0c1a (radial gradient)
- accent: #ff3b3b
- text: #f0f0f0
- muted: rgba(255,255,255,0.4)
- error: #ff6b6b

Функциональность:
- Login-форма с username + password
- Состояния: idle, loading (spinner + "Authenticating..."), error (shake), success
- Доступность: aria-labels, focus management

Не используй: emoji, внешние CDN, не-React библиотеки.
```

### Prompt 2: Dashboard (SOC Command Center)

```
Создай React-компонент Dashboard для SOC (Security Operations Center) админ-панели Predator.

Концепция: "Predator Command Center" — киберпанк командный центр мониторинга угроз.

Секции (сверху вниз):

=== Секция 1: Stats Row (6 карточек) ===
Каждая карточка:
- Framer Motion stagger-анимация (delay = index * 80ms)
- SVG-иконка (lucide-react) в цветном круге вместо emoji
- Значение с animated count-up (useSpring, duration 1.5s)
- CSS pulse-ring анимация (концентрические круги)
- Hover: scale(1.02), y-2, border-color accent
- WebSocket-обновление: число мигает (opacity 1→0.5→1)

Карточки:
1. Ожидающие запросы (yellow) — иконка Clock
2. Активные токены (green) — иконка Key
3. Использованные токены (red) — иконка UserCheck
4. Всего сканирований (blue) — иконка Activity
5. Найдено угроз (red) — иконка AlertTriangle
6. Файлов проверено (green) — иконка Search

=== Секция 2: 3D Threat Globe + Activity Chart (2 колонки) ===
Левая колонка — 3D Threat Globe:
- React Three Fiber: сфера с континентами (проволочный каркас)
- Красные пульсирующие точки в случайных местах (угрозы)
- Медленное вращение (useFrame)
- Подпись: "Threat Map — Global"

Правая колонка — Recharts AreaChart:
- X: даты, Y: количество сканов
- Два датасета: "Сканы" (синий градиент fill), "Угрозы" (красный градиент fill)
- Анимация при появлении: линии "растут" слева направо
- Tooltip с glassmorphism

=== Секция 3: Scan Mode Distribution (Doughnut) + Recent Scans (таблица) ===
Левая колонка — Recharts PieChart:
- Doughnut с данными по режимам сканирования
- Анимация: сегменты появляются с rotation
- Цвета: full=#22c55e, quick=#3b82f6, dma=#8b5cf6

Правая колонка — Таблица последних сканов:
- Glassmorphism table
- Строки: fade-in stagger
- Hover: accent-полоска слева, background светлеет
- Статус: цветной badge (✓ 0 зелёный, ⚠ N красный)

=== Секция 4: Recent Requests + Recent Tokens (2 таблицы) ===
- Таблицы с glassmorphism
- Skeleton loading state (пульсирующие placeholder-строки)
- Empty state: иконка + пояснительный текст

WebSocket индикатор (правый верх):
- Connected: зелёная точка, breathing-анимация, текст "Real-time"
- Disconnected: красная точка, быстрая пульсация, текст "Disconnected"

Toast-уведомления:
- slide-in справа
- Цвета: success=#22c55e, warning=#eab308, info=#3b82f6
- Авто-закрытие через 5 секунд

Skeleton loading:
- Пульсирующие div'ы (bg-gray-800, animate-pulse)
- Форма соответствует загружаемому контенту

Цвета те же. Шрифты: Inter (UI), JetBrains Mono (коды/токены).
```

### Prompt 3: Pending Requests (Tinder-style cards)

```
Создай React-компонент PendingRequests для админ-панели Predator.

Концепция: "Access Control" — карточки запросов с жестами одобрения/отклонения.

Вместо таблицы используй card grid (responsive: 1/2/3 колонки).

Карточка запроса:
- Аватар (первая буква имени + случайный цвет)
- Имя ПК (жирный шрифт)
- "Запросил доступ X минут назад" (relative time)
- Круговой countdown-таймер (SVG circle):
  - > 1 час: зелёный
  - < 1 час: жёлтый
  - < 5 минут: красный + pulse-анимация
  - Истёк: серый + strikethrough
- Кнопки: "Одобрить" (зелёный градиент) и "Отклонить" (красный outline)

Анимации:
- Новая карточка: slide-in слева (stagger)
- Approve: карточка улетает вправо (x: 200) с зелёным свечением
- Reject: карточка shake + улетает влево (x: -200) с красным
- Удаление из DOM через AnimatePresence

Действия:
- Approve → API-вызов → toast "✓ Запрос одобрен"
- Reject → confirm диалог → API-вызов → toast
- Кнопки disabled во время API-вызова (спиннер)

Пустое состояние:
- Иконка CheckCircle (зелёная)
- "Все запросы обработаны"
- Частицы на фоне (мало)
```

### Prompt 4: Tokens Management (Terminal style)

```
Создай React-компонент TokenManager для админ-панели Predator.

Концепция: "Key Generation Terminal" — матричный стиль с анимациями печати.

=== Секция 1: Token Health ===
- 3 stat-карточки: Активные / Использовано / Всего
- Health Gauge: SVG дуга (спидометр) вместо полоски
- Цвет дуги: зелёный (>5) → жёлтый (2-5) → красный (<2)
- Анимация: дуга "заполняется" при загрузке

=== Секция 2: Генератор токенов ===
- Input: количество (1-10)
- Кнопка "Сгенерировать": с progress-анимацией внутри (fill слева направо)
- Результат: карточки с typewriter-эффектом (посимвольная печать)
- Кнопка "Копировать" с анимацией checked (иконка меняется на ✓)
- Токены видны 8 секунд (countdown progress bar)

=== Секция 3: Список токенов ===
- Glassmorphism таблица
- Код токена: моноширинный, letter-spacing, с кнопкой копирования
- Статус: цветной badge
- Revoke: кнопка с подтверждением, строка fading to grey + strikethrough

3D-фон:
- Матричный дождь из hex-символов (0-9, A-F) — низкая прозрачность (#ff3b3b, opacity 0.05)
- Canvas-анимация или CSS
```

### Prompt 5: History Timeline

```
Создай React-компонент EventTimeline для админ-панели Predator.

Концепция: Визуальный таймлайн событий безопасности.

=== Stat Row ===
- 3 карточки: Токенов использовано / Запросов обработано / Всего событий

=== Фильтры ===
- Pill-кнопки: Все / Токены / Запросы
- Анимированный sliding-индикатор под активной кнопкой
- Поиск: input с иконкой лупы, раскрывается при фокусе

=== Timeline ===
Вертикальная линия (CSS) с точками-событиями:

Каждая точка:
- Иконка: 🔑 (токен) или 👤 (запрос) → lucide-react Key/User
- Цвет: синий (токен), зелёный (approved), красный (rejected)
- Соединительная линия слева
- Карточка справа с деталями

Карточка события:
- Дата/время (моноширинный)
- Тип события (badge)
- Описание (жирный)
- Детали (код токена или имя ПК)
- Администратор (текст)

Анимации:
- Точки появляются снизу вверх (stagger, delay от индекса)
- Линия таймлайна "прорастает" (height 0→100%, transition 2s)
- Hover: точка увеличивается, карточка слегка приподнимается

Пустое состояние: иконка + "Событий не найдено"
Поиск без результатов: "Попробуйте изменить запрос" + иконка поиска
```

### Prompt 6: Threat Database (Suspicious Hashes)

```
Создай React-компонент ThreatDatabase для админ-панели Predator.

Концепция: "Forensic Lab" — анализ цифровых улик с визуализацией хешей.

=== Вкладки ===
- Segmented control (iOS-style): На проверке / Подтверждённые / Ложные / Из сканов
- Sliding-индикатор под активной вкладкой
- Счётчик на вкладке "Из сканов"

=== Таблица ===
- SHA256: моноширинный, первые 16 символов + "...", кнопка копирования
- Имя файла: truncate с tooltip
- Пользователь: текст
- Размер: форматированный (KB/MB)
- Риск: цветной badge (HIGH=red, MEDIUM=yellow, LOW=green)
- Дата: форматированная

=== Действия (На проверке) ===
- "✅ Чит" — зелёная кнопка → confetti-анимация → строка уходит
- "❌ Спам" — красная кнопка → строка fading out

=== 3D-фон ===
- DNA-подобная двойная спираль из SHA256-символов
- Медленное вращение
- React Three Fiber + кастомный шейдер

Анимации:
- Вкладки: crossfade-переход (opacity 0→1 + translateY 10→0)
- Новая строка: slide-in справа
- Подтверждение: confetti + glow
- Отклонение: красная вспышка + fade out
```

---

## 🔗 Ссылки на бесплатные дизайны и вдохновение

### React-шаблоны дашбордов (бесплатные):
| Название | Стек | Особенности |
|----------|------|-------------|
| [Horizon UI](https://horizon-ui.com/) | Chakra UI + Framer Motion | Glassmorphism, dark mode, анимации |
| [Berry Dashboard](https://berrydashboard.io/) | MUI + Framer Motion | Бесплатная версия, тёмная тема |
| [Mantis](https://mantisdashboard.io/) | MUI + Framer Motion | Профессиональный, анимации |
| [TailAdmin](https://tailadmin.com/) | Tailwind CSS | Тёмная тема, чистый |
| [Aceternity UI](https://ui.aceternity.com/) | Tailwind + Framer Motion | **Топ** для анимированных компонентов |

### 3D-компоненты (бесплатные):
| Ресурс | Что даёт |
|--------|---------|
| [Aceternity UI 3D Card](https://ui.aceternity.com/components/3d-card) | 3D tilt-карточки |
| [Aceternity Background Beams](https://ui.aceternity.com/components/background-beams) | Анимированные лучи |
| [Aceternity Bento Grid](https://ui.aceternity.com/components/bento-grid) | Сетка с анимациями |
| [React Three Fiber Examples](https://r3f.docs.pmnd.rs/getting-started/examples) | 3D-сцены |
| [Drei Components](https://github.com/pmndrs/drei) | Готовые 3D-компоненты |

### Motion-дизайн вдохновение:
| Платформа | Поисковый запрос |
|-----------|-----------------|
| **Dribbble** | `#cybersecurity dashboard`, `#glassmorphism`, `#3D UI` |
| **Awwwards** | Category: "Dashboards", filter by high interaction |
| **Behance** | `cyberpunk UI`, `security dashboard` |
| **CodePen** | `Three.js dashboard`, `Framer Motion card` |
| **Framer Marketplace** | Category: 3D templates |
| **Morphin.dev** | Animated dashboard charts (React + Framer Motion) |

### Готовые 3D-ассеты (бесплатно):
| Ресурс | Формат |
|--------|--------|
| Sketchfab (free models) | GLTF/GLB |
| Poly Pizza | GLTF |
| Three.js Editor | JSON |

---

## 📋 Приоритеты реализации

| # | Задача | Сложность | Влияние |
|---|--------|----------|---------|
| 1 | **Login Page** (3D щит + частицы + scan-line) | 🟡 Средняя | 🔴 Огромное (первое впечатление) |
| 2 | **Dashboard Stats** (анимированные карточки + count-up) | 🟢 Лёгкая | 🔴 Огромное |
| 3 | **Графики Recharts** (замена Chart.js) | 🟡 Средняя | 🟡 Большое |
| 4 | **3D Threat Globe** (Three.js) | 🔴 Сложная | 🟡 Большое |
| 5 | **Pending Cards** (Tinder-style) | 🟡 Средняя | 🟡 Большое |
| 6 | **History Timeline** | 🟢 Лёгкая | 🟢 Среднее |
| 7 | **Tokens Terminal** (typewriter) | 🟢 Лёгкая | 🟢 Среднее |
| 8 | **Threat Database DNA** (3D спираль) | 🔴 Сложная | 🟢 Среднее |
| 9 | **Particle Background** (глобальный) | 🟢 Лёгкая | 🟡 Большое |
| 10 | **Skeleton Loading** | 🟢 Лёгкая | 🟢 Среднее |

### Рекомендуемый порядок:
1. Установить зависимости (Three.js, Framer Motion, tsparticles, Recharts, lucide-react)
2. Создать глобальный `<ParticleBackground />`
3. Login Page (самый эффектный, даёт вау-эффект)
4. Dashboard Stats (count-up + pulse rings)
5. Графики (Recharts замена)
6. Toast-уведомления
7. Pending → Tokens → History → Threat Database (по очереди)

---

## 🚀 Быстрый старт для дизайн-модели

Если даёшь это Kimi-k2.7 или другой модели:

```
У нас есть админ-панель Predator (React 18 + TypeScript + CSS variables).
Текущий код: admin/src/App.css (700+ строк), admin/src/components/Layout.tsx,
admin/src/pages/{Login,Dashboard,Pending,Tokens,History,SuspiciousHashes}.tsx,
admin/src/api.ts (23 API-функции).

Задача: полный редизайн с 3D-эффектами и анимациями.
НЕ трогай: API-клиент, логику состояний, бизнес-логику.
МЕНЯЙ: вёрстку, стили, анимации, добавляй 3D-компоненты.

Сначала сделай Login Page по Prompt 1.
Потом Dashboard по Prompt 2.
Потом покажи результат.
```

---

> **Создано:** 26.07.2026 | **Версия:** 1.0 | **Для:** Predator Anti-Cheat System
