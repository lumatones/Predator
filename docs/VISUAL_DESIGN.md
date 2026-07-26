# Predator — Visual Design Architecture

> Документ для Kimi-k2.7 (дизайн-ориентированная модель)
> Задача: реализовать визуальные улучшения на основе этого плана

---

## 🎯 Концепция

**Predator** — античит-сканер для GTA 5 RP. Визуальный стиль:
- **Dark tech** — тёмная тема, красные акценты, неоновое свечение
- **Glassmorphism** — стеклянные карточки с `backdrop-filter`
- **Cyberpunk / Terminal** — моноширинный шрифт, scan-line, «радар»
- **Профессиональный инструмент** — не игрушка, а серьёзный софт

---

## 🎨 Дизайн-система (уже существует в `src/App.css`)

### Design Tokens (`:root` CSS custom properties)
```css
--accent-red: #ff4444;         /* Основной акцент */
--accent-orange: #ff6b35;      /* Вторичный акцент */
--accent-gradient: linear-gradient(135deg, #ff4444, #ff6b35, #ff0044);
--bg-primary: #0a0a0f;         /* Фон */
--bg-card: rgba(255,255,255,0.03); /* Карточки */
--border-color: rgba(255,255,255,0.06);
--font-display: 'JetBrains Mono', monospace;  /* Заголовки */
--font-body: 'Inter', sans-serif;             /* Текст */
```

### Цветовые темы (4 шт.)
| ID | Название | accent | light | dark |
|----|----------|--------|-------|------|
| `predator` | Predator Red | `#ff4d5a` | `#ff8a5b` | `#b91c1c` |
| `ocean` | Ocean Blue | `#7dd3fc` | `#60a5fa` | `#1d4ed8` |
| `stealth` | Stealth Black | `#a1a1aa` | `#e4e4e7` | `#3f3f46` |
| `nebula` | Nebula Purple | `#c084fc` | `#f0abfc` | `#7c3aed` |

---

## 📦 Стек (гибридный подход)

| Библиотека | Назначение | Статус |
|-----------|------------|--------|
| `framer-motion` | Анимации, transitions | ✅ Уже в проекте |
| `@tsparticles/react` + `@tsparticles/slim` | Particle-фон | 🔲 Установить |
| `@radix-ui/react-toast` | Toast-уведомления | 🔲 Установить |
| `@radix-ui/react-dialog` | Accessible модалки | 🔲 Установить |
| `@radix-ui/react-slot` | Композитные кнопки | 🔲 Установить |
| `react-spring` | Пружинные анимации | 🔲 Установить |
| `@react-three/fiber` + `@react-three/drei` | 3D-логотип | 🔲 Опционально (тяжёлые) |

> **Важно**: НЕ трогаем существующий CSS — он остаётся как есть. Новые компоненты стилизуем через существующие CSS-переменные.

---

## 🖼️ Задачи (в порядке реализации)

### 1. Particle-фон (`ParticleBackground`)
**Заменить**: текущие статичные `.gradient-orb` (3 цветных круга с blur)
**Файл**: `src/components/ui/ParticleBackground.tsx`

```tsx
// Использовать в App.tsx вместо <div className="background-gradient">
import Particles from '@tsparticles/react'
import { loadSlim } from '@tsparticles/slim'

// Конфиг:
// - Цвет частиц: #ff4444, #ff6b35
// - Размер: 1-3px
// - Движение: медленное (speed: 0.5)
// - Связи (links): тонкие линии между близкими частицами
// - Реакция на курсор: repulse при наведении
// - Количество: ~80 частиц
```

### 2. Toast-уведомления (`ToastProvider`)
**Файлы**: `src/components/ui/Toast.tsx`, `src/components/ui/ToastProvider.tsx`

```tsx
// Radix Toast + свой CSS (использовать --accent-red, --bg-card)
// Типы: success (зелёный), error (красный), warning (оранжевый), info (синий)
// Позиция: правый нижний угол
// Анимация: slideIn справа + fade
// Примеры использования:
//   toast.success('Сканирование завершено')
//   toast.error('Ошибка подключения к серверу')
```

### 3. Page Transitions (`AnimatePresence`)
**Где**: `src/App.tsx` — обернуть все экраны в `<AnimatePresence>`

```tsx
// Каждый экран получает motion.div с:
//   initial={{ opacity: 0, filter: 'blur(10px)', scale: 0.97 }}
//   animate={{ opacity: 1, filter: 'blur(0px)', scale: 1 }}
//   exit={{ opacity: 0, filter: 'blur(10px)', scale: 0.97 }}
//   transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
```

### 4. Stagger-анимация результатов
**Где**: `src/pages/Checker.tsx` — строки результатов

```tsx
// Каждая .result-row получает:
//   variants: { hidden: { opacity: 0, x: -20 }, visible: { opacity: 1, x: 0 } }
//   Контейнер: staggerChildren: 0.03 (каскад с задержкой 30ms)
// Уже есть @keyframes rowSlideIn в CSS — можно заменить на framer-motion
```

### 5. Glitch-эффект заголовка
**Где**: Логотип «Predator» в `src/App.tsx`

```tsx
// CSS-only эффект при наведении на .title:
//   ::before { content: 'Predator'; position: absolute; color: #0ff; clip: rect(0,900px,0,0) }
//   ::after  { content: 'Predator'; position: absolute; color: #f0f; clip: rect(0,900px,0,0) }
//   Анимация: случайное смещение clip + transform: skew()
//   Триггер: :hover на .logo-section
```

### 6. Skeleton Loading
**Где**: Вместо `<div className="spinner">` на всех экранах загрузки

```tsx
// Компонент Skeleton: анимированный placeholder формы контента
//   background: linear-gradient(90deg, transparent, rgba(255,255,255,0.04), transparent)
//   background-size: 200% 100%
//   animation: shimmer 1.5s infinite
// Варианты: SkeletonCard, SkeletonText, SkeletonCircle
```

### 7. Магнитный hover
**Где**: Карточки `.main-card`, табы `.checker-tab`, кнопки `.start-button`

```tsx
// Хук useMagneticEffect(ref, strength = 0.3):
//   onMouseMove → вычисляет смещение от центра элемента
//   transform: translate(${dx * strength}px, ${dy * strength}px)
//   transition: transform 0.2s ease-out
//   onMouseLeave → transform: translate(0, 0)
```

### 8. Модалки v2 (Radix Dialog)
**Где**: `src/components/ui/UpdateModal.tsx` — заменить текущую реализацию

```tsx
// Radix Dialog.Root + Dialog.Portal + Dialog.Overlay + Dialog.Content
// Стилизация через существующие CSS-переменные:
//   Overlay: background: rgba(0,0,0,0.6), backdrop-filter: blur(4px)
//   Content: background: var(--bg-card), border: 1px solid var(--border-color)
//   Анимация: motion.div scale(0.95)→1 + fade
// Преимущества: focus-trap, ESC-to-close, aria-атрибуты
```

### 9. 3D-логотип Predator (опционально)
**Где**: Заменить текущий SVG в `src/App.tsx`

```tsx
// React Three Fiber: Canvas + Mesh с геометрией щита
// Частицы вокруг логотипа
// Медленное вращение
// При наведении — ускорение вращения
// Освещение: pointLight красного цвета
```

### 10. Рикошет кнопок (spring bounce)
**Где**: Все кнопки через общий компонент `<Button>`

```tsx
// react-spring: useSpring с config: { tension: 300, friction: 10 }
// При клике: scale: [1, 0.92, 1.05, 1]
// Эффект «отпружинивания»
```

---

## 📁 Целевая структура файлов (визуальная часть)

```
src/
├── components/
│   ├── ui/
│   │   ├── ParticleBackground.tsx    # tsparticles фон
│   │   ├── Toast.tsx                 # Radix Toast
│   │   ├── ToastProvider.tsx         # Провайдер + хук useToast
│   │   ├── UpdateModal.tsx           # Обновить на Radix Dialog
│   │   ├── Skeleton.tsx              # Skeleton loading
│   │   └── Button.tsx                # Кнопка с spring-анимацией
│   └── scanner/                      # (техническая часть)
├── hooks/
│   ├── useMagnetic.ts                # Магнитный hover
│   └── useToast.ts                   # Хук для toast
├── styles/
│   └── glitch.css                    # Glitch-эффект (опционально)
└── App.tsx                           # AnimatePresence, ParticleBackground
```

---

## 🎬 Порядок реализации (рекомендуемый)

1. **ParticleBackground** — сразу wow-эффект, видно на всех экранах
2. **ToastProvider** — нужно для всех уведомлений
3. **Page Transitions** — плавные переходы между экранами
4. **Stagger-анимация** — строки результатов появляются каскадом
5. **Skeleton Loading** — замена спиннеров
6. **Модалки v2 (Radix Dialog)** — accessibility
7. **Glitch-эффект** — изюминка
8. **Магнитный hover** — приятная мелочь
9. **Рикошет кнопок** — финальный штрих
10. **3D-логотип** — опционально, самое сложное

---

## ⚠️ Правила

- **НЕ удалять существующий CSS** — только добавлять новые файлы
- **Использовать CSS-переменные** (`var(--accent-red)` и т.д.) для консистентности
- **Учитывать 4 цветовые темы** — все компоненты должны работать с любой темой
- **Не трогать `electron/`** — это зона технической модели
- **Typecheck после каждого изменения**: `npx tsc --noEmit`
