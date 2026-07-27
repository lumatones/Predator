# Predator — Global Design System v2.0

> **Source of Truth:** This document governs ALL visual decisions across Predator EXE, Admin Dashboard, Server, and future Public Website.
> **Generated:** 2026-07-27
> **Skills:** ui-ux-pro-max + frontend-design + web-design-guidelines + vercel-react-view-transitions + vercel-react-best-practices

---

## 0. Brand Identity

### Product DNA
- **Name:** Predator
- **Product type:** Anti-cheat security scanner (desktop + admin dashboard + server API)
- **Target audience:** GTA 5 RP server admins (25-45), PC gamers, anti-cheat moderators
- **Tone:** Elite, military-grade, no-nonsense, professional, intimidating but trustworthy
- **One-sentence brand:** "The anti-cheat that hunts what others can't see."

### Visual DNA
Predator's visual identity is built on THREE core tensions:

| Axis | Pole A (Restraint) | Pole B (Intensity) | Where Predator Sits |
|------|-------------------|-------------------|---------------------|
| Color | Monochrome black | Saturated red | 90% black, 10% red — red is earned, never wasted |
| Space | Dense data | Breathable emptiness | Dense dashboards, airy idle screens |
| Motion | Static stillness | Aggressive animation | Micro-interactions only; no decorative motion |

### Signature Element
The 3D Predator shield (`PredatorLogo3D`) is the single most memorable visual element. It must:
- Appear on EVERY empty/idle screen
- Animate in response to scan state (idle → scanning → done)
- Never be shrunk below 64px
- Always have its ambient glow (CSS `::after` pseudo-element)

---

## 1. Color System

### Primary Palette

| Token | Hex | HSL | Usage | Opacity Variants |
|-------|-----|-----|-------|------------------|
| `--bg-primary` | `#0a0a0f` | 240° 25% 5% | App background | — |
| `--bg-secondary` | `#12121a` | 240° 18% 9% | Sidebar, cards | — |
| `--bg-card` | `rgba(255,255,255,0.03)` | — | Card surfaces | hover: 0.06 |
| `--accent-red` | `#ff4444` | 0° 100% 63% | Primary CTA, high-risk, active | 15%, 30%, 50% |
| `--accent-orange` | `#ff6b35` | 22° 100% 60% | Gradient partner, medium-risk | 15%, 30% |
| `--accent-gradient` | `135deg, #ff4444, #ff6b35, #ff0044` | — | Logo, buttons, hero | — |

### Semantic Colors

| Token | Hex | Meaning | Glow |
|------|-----|---------|------|
| `--color-success` | `#22c55e` | Clean system, approved, active | `0 0 12px rgba(34,197,94,0.4)` |
| `--color-warning` | `#f59e0b` | Medium risk, pending | `0 0 12px rgba(245,158,11,0.3)` |
| `--color-error` | `#ef4444` | High risk, rejected, danger | `0 0 12px rgba(239,68,68,0.4)` |
| `--color-info` | `#3b82f6` | Neutral information | `0 0 12px rgba(59,130,246,0.2)` |

### Text Colors

| Token | Value | Usage |
|-------|-------|-------|
| `--text-primary` | `#ffffff` | Headings, body, active nav |
| `--text-secondary` | `rgba(255,255,255,0.65)` | Descriptions, metadata |
| `--text-muted` | `rgba(255,255,255,0.45)` | Disabled, placeholders, timestamps |

### Color Usage Rules

- **Red is EARNED.** Never use red for decoration. Red = danger, active, critical.
- **Green = safe.** Only for "clean" states, approved badges, active tokens.
- **Yellow = pending.** Only for medium-risk, waiting states.
- **NEVER use raw hex in components.** Always reference CSS custom properties.
- **Gradient accent:** Reserve for brand moments — logo, primary buttons, hero title. Never for borders or backgrounds.

---

## 2. Typography

### Font Pairing

| Role | Font Family | Weight | Usage |
|------|-----------|--------|-------|
| **Display** | `'JetBrains Mono', 'SF Mono', 'Fira Code', monospace` | 800-900 | Logo, hero title, "PREDATOR", scan counts |
| **Heading** | `'Inter', -apple-system, BlinkMacSystemFont, sans-serif` | 600-700 | Page titles, card headers, section labels |
| **Body** | `'Inter', -apple-system, BlinkMacSystemFont, sans-serif` | 400-500 | Paragraphs, descriptions, table cells |
| **Code/Data** | `'JetBrains Mono', 'SF Mono', 'Fira Code', monospace` | 500-700 | SHA256, tokens, PIDs, file paths, metrics |

### Type Scale

| Token | Size | Line Height | Letter Spacing | Usage |
|-------|------|------------|----------------|-------|
| `--text-2xs` | `11px` | 1.4 | — | Tab badges, captions (*was 10px — fixed for WCAG*) |
| `--text-xs` | `12px` | 1.5 | `0.02em` | Metadata, timestamps, labels |
| `--text-sm` | `13px` | 1.5 | — | Body, descriptions, table cells |
| `--text-base` | `14px` | 1.5 | — | Default body |
| `--text-lg` | `16px` | 1.4 | — | Subtitles, card values |
| `--text-xl` | `20px` | 1.3 | `-0.01em` | Section headings |
| `--text-2xl` | `24px` | 1.2 | `-0.02em` | Page titles |
| `--text-3xl` | `28px` | 1.2 | `-0.03em` | Hero subheading |
| `--text-4xl` | `32px` | 1.15 | `-0.03em` | Stat cards |
| `--text-display` | `42px` | 1 | `0.1em` | "PREDATOR" logo (uppercase) |

### Typography Rules

- ✅ `tabular-nums` on ALL number columns, scan counts, timestamps, PIDs
- ✅ `text-wrap: balance` or `text-pretty` on headings
- ✅ `…` (ellipsis character), never `...` (three dots)
- ✅ Curly quotes `"` `"`, never straight `"`
- ✅ Non-breaking spaces: `10&nbsp;MB`, `⌘&nbsp;K`
- ✅ `font-display: swap` on web fonts
- ❌ NEVER use `font-weight: 300` or thinner — too faint on dark backgrounds
- ❌ NEVER use `text-transform: uppercase` on body text — ONLY on labels/badges/captions

---

## 3. Spacing Scale (4px base)

```
--space-1:  4px    (icon padding, tight gaps)
--space-2:  8px    (inline gaps, badge padding)
--space-3:  12px   (card padding, form gaps)
--space-4:  16px   (section gaps, button padding)
--space-5:  20px   (card body padding)
--space-6:  24px   (section margins)
--space-8:  32px   (page padding, large gaps)
--space-10: 40px   (hero spacing)
--space-12: 48px   (page-top spacing)
--space-16: 64px   (empty state padding)
```

### Spacing Rules

- Dashboard density (high): prefer `space-2` to `space-4`
- Marketing/onboarding (low): prefer `space-6` to `space-10`
- NEVER use arbitrary px values — always reference `--space-*`

---

## 4. Border Radius

```
--radius-sm:  6px    (inputs, badges, small cards)
--radius-md:  10px   (cards, modals, panels)
--radius-lg:  16px   (main cards, stat cards)
--radius-xl:  20px   (modal dialogs)
--radius-full: 50%   (avatars, dots, status indicators)
```

### Radius Rule
- **NO `border-radius: 0`.** Predator is NOT brutalist. Minimum 6px.
- **NO `border-radius: 999px` on cards.** Pills are for badges only.

---

## 5. Borders & Shadows

### Borders
```css
--border-color: rgba(255, 255, 255, 0.06);    /* Default */
--border-hover: rgba(255, 255, 255, 0.12);    /* Hover */
--border-active: rgba(255, 68, 68, 0.3);      /* Active/selected — RED tint */
```

### Shadows
```css
--shadow-card: 0 8px 32px rgba(0, 0, 0, 0.3);              /* Cards */
--shadow-glow: 0 0 20px rgba(255, 68, 68, 0.15);           /* Active card glow */
--shadow-modal: 0 32px 64px rgba(0, 0, 0, 0.5);            /* Modals */
--shadow-button: 0 4px 12px color-mix(in srgb, var(--accent-red) 25%, transparent); /* Primary buttons */
```

### Border Rules
- Cards: ALWAYS `1px solid var(--border-color)` — never borderless
- Glass cards: `backdrop-filter: blur(20px)`
- Hover: border brightens to `--border-hover`
- Active/selected: border turns RED (`--border-active`)

---

## 6. Animation System

### Easing Curves
```css
--ease-out:    cubic-bezier(0.16, 1, 0.3, 1);      /* Entrances, reveals */
--ease-spring: cubic-bezier(0.34, 1.56, 0.64, 1);  /* Bounces, badges */
--ease-smooth: cubic-bezier(0.4, 0, 0.2, 1);       /* Standard transitions */
```

### Duration Tokens
```css
--duration-fast:   150ms;   /* Hover states, focus rings */
--duration-normal: 200ms;   /* Button presses, toggles */
--duration-slow:   300ms;   /* Page transitions, card reveals */
```

### Motion Hierarchy (from vercel-react-view-transitions)

| Priority | Pattern | When | CSS Class |
|----------|---------|------|-----------|
| 1 | Shared element (`name`) | Image → detail view | `view-transition-name: hero-${id}` |
| 2 | Suspense reveal | Data loading | `enter="fade-in" exit="fade-out"` |
| 3 | List identity (`key`) | Reordered items | Per-item `<ViewTransition key={item.id}>` |
| 4 | State change (enter/exit) | Modals, toasts, drawers | `enter="slide-up" exit="slide-down"` |
| 5 | Route change (directional) | Page navigation | `addTransitionType('nav-forward')` |

### Animation Rules (from web-design-guidelines)

- ✅ ALWAYS honor `prefers-reduced-motion` — disable ALL decorative animations
- ✅ Animate ONLY `transform` and `opacity` (GPU-composited)
- ✅ `transition-duration: 150-300ms` — never instant (0ms), never slow (>500ms)
- ❌ NEVER `transition: all` — list properties explicitly
- ❌ NEVER animate `width`, `height`, `top`, `left` — causes layout thrashing
- ✅ Interruptible animations — respond to user input mid-animation
- ✅ Set correct `transform-origin` for scale/rotate animations

### Motion Presets

| Context | Animation | Duration | Easing |
|---------|-----------|----------|--------|
| Card enter | `opacity: 0→1, translateY(8px→0)` | 300ms | `--ease-out` |
| Modal open | `opacity: 0→1, scale(0.96→1)` | 200ms | `--ease-spring` |
| Toast enter | `opacity: 0→1, translateX(16px→0)` | 200ms | `--ease-out` |
| List item stagger | Each item `+50ms` delay | 200ms/item | `--ease-out` |
| Hover lift | `translateY(-1px)` | 150ms | `--ease-smooth` |
| Tab switch | `opacity cross-fade` | 150ms | `--ease-out` |
| Page transition (forward) | `translateX(20px→0), opacity 0→1` | 250ms | `--ease-out` |
| Page transition (back) | `translateX(-20px→0), opacity 0→1` | 250ms | `--ease-out` |

---

## 7. Component Patterns

### 7.1 Buttons

| Variant | Background | Text | Border | Hover |
|---------|-----------|------|--------|-------|
| Primary | `--accent-gradient` | `#fff` | none | `translateY(-1px)`, stronger shadow |
| Secondary | `rgba(255,255,255,0.04)` | `--text-secondary` | `--border-color` | bg → `0.08`, text → primary |
| Ghost | transparent | `--text-secondary` | none | bg → `0.04` |
| Danger | `rgba(255,68,68,0.12)` | `#ff6b6b` | `rgba(255,68,68,0.2)` | bg → `0.2`, red glow |
| Success | `#22c55e → #16a34a` | `#fff` | none | green glow |

**Button Rules (from web-design-guidelines):**
- ✅ `<button>` for actions, `<a>`/`<Link>` for navigation — NEVER `<div onClick>`
- ✅ `focus-visible:ring-2 ring-[--accent-red] ring-offset-2`
- ✅ `:disabled` → `opacity: 0.5; cursor: not-allowed`
- ✅ Min hit target: `44×44px` (Touch & Interaction)
- ✅ Icon-only buttons: MUST have `aria-label`
- ❌ NEVER `outline: none` without focus-visible replacement
- ❌ NEVER `user-scalable=no` or `maximum-scale=1`

### 7.2 Cards

```css
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: var(--space-5);
  transition: border-color var(--duration-fast),
              box-shadow var(--duration-fast),
              transform var(--duration-fast);
}
.card:hover {
  border-color: var(--border-hover);
  transform: translateY(-1px);
}
.card.active {
  border-color: var(--border-active);
  box-shadow: var(--shadow-glow);
}
```

**Card Rules:**
- Glass cards: `backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px)`
- Stat cards: large number (`--text-4xl`, `tabular-nums`), small label (`--text-xs`, uppercase)
- Pending/request cards: avatar + username + countdown + actions
- NEVER use `box-shadow` without `border`

### 7.3 Inputs

```css
.input {
  background: rgba(255,255,255,0.03);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: var(--space-2) var(--space-3);
  color: var(--text-primary);
  font: inherit;
  transition: border-color var(--duration-fast);
}
.input:focus {
  border-color: var(--accent-red);
  box-shadow: 0 0 0 3px rgba(255,68,68,0.15);
  outline: none;
}
.input::placeholder {
  color: var(--text-muted);
}
```

**Input Rules (from web-design-guidelines):**
- ✅ Every input needs `<label>` or `aria-label`
- ✅ `autocomplete` attribute on ALL form fields
- ✅ `type="email"`, `type="url"`, `type="number"` — use correct types
- ✅ Placeholders end with `…` and show example pattern
- ❌ NEVER block paste (`onPaste + preventDefault`)
- ❌ NEVER `spellCheck={true}` on emails, codes, usernames, tokens
- ✅ `inputmode` for mobile: `numeric`, `email`, `url`

### 7.4 Tables

```css
.table {
  width: 100%;
  border-collapse: collapse;
}
.table th {
  font-size: var(--text-xs);
  font-weight: var(--fw-semibold);
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: var(--space-3) var(--space-4);
  border-bottom: 1px solid var(--border-color);
}
.table td {
  padding: var(--space-3) var(--space-4);
  font-size: var(--text-sm);
  border-bottom: 1px solid rgba(255,255,255,0.03);
}
.table tr:hover { background: var(--bg-hover); }
```

**Table Rules:**
- ✅ Number columns: `font-variant-numeric: tabular-nums; text-align: right`
- ✅ SHA256/tokens: monospace font, `letter-spacing: 0.05em`
- ✅ Empty state: centered illustration + message (NEVER render broken table)
- ✅ Horizontal scroll on mobile (`overflow-x: auto`)
- ❌ NEVER use `<div>` tables — use semantic `<table>`, `<thead>`, `<tbody>`

### 7.5 Badges

```css
.badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: 2px 8px;
  border-radius: var(--radius-full);
  font-size: var(--text-2xs);
  font-weight: var(--fw-bold);
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.badge-high   { background: rgba(255,68,68,0.15); color: #ff6b6b; }
.badge-medium { background: rgba(245,158,11,0.15); color: #fbbf24; }
.badge-low    { background: rgba(107,114,128,0.15); color: #9ca3af; }
.badge-safe   { background: rgba(34,197,94,0.15); color: #4ade80; }
```

### 7.6 Modals / Dialogs

```css
.modal-overlay {
  position: fixed; inset: 0; z-index: 1000;
  background: rgba(0,0,0,0.6);
  backdrop-filter: blur(8px);
  display: flex; align-items: center; justify-content: center;
}
.modal {
  background: rgba(18,18,26,0.96);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-modal);
  padding: var(--space-8);
}
```

**Modal Rules:**
- ✅ `overscroll-behavior: contain` — prevent background scroll
- ✅ `Esc` closes, click-outside closes
- ✅ Focus trap inside modal
- ✅ `aria-modal="true"`, `role="dialog"`
- ✅ Entrance: `opacity + scale`, 200ms, spring easing

---

## 8. Accessibility (CRITICAL — All P0)

### Color Contrast
- Text/background: ≥4.5:1 for body, ≥3:1 for large text (18px+)
- Interactive elements: ≥3:1 against adjacent colors
- Focus indicators: ≥3:1 against background

### Focus States
```css
*:focus-visible {
  outline: 2px solid var(--accent-red);
  outline-offset: 2px;
  border-radius: 2px;
}
```

### Semantic HTML
- ✅ `<button>` for actions, `<a>`/`<Link>` for navigation
- ✅ `<table>`, `<thead>`, `<tbody>` for tabular data
- ✅ `<h1>`–`<h6>` hierarchy — ONE `<h1>` per page
- ✅ `<label htmlFor>` wrapping ALL inputs
- ✅ `alt` on ALL images (or `alt=""` if decorative)
- ✅ `aria-label` on ALL icon-only buttons
- ✅ `aria-live="polite"` on toast containers, async updates
- ✅ `role="status"` on loading indicators

### Keyboard Navigation
- ✅ All interactive elements reachable via `Tab`
- ✅ `Enter`/`Space` activates buttons
- ✅ `Esc` closes modals, dropdowns, drawers
- ✅ `Arrow keys` navigate lists, tabs, menus
- ✅ Skip-to-content link as first focusable element

### Reduced Motion
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

### Touch Targets
- ✅ Minimum `44×44px` for ALL interactive elements
- ✅ `touch-action: manipulation` — prevent double-tap zoom
- ✅ `-webkit-tap-highlight-color: transparent` — but WITH focus-visible fallback

---

## 9. Icon System

### Rules
- ✅ SVG components ONLY — NEVER emoji, NEVER icon fonts, NEVER PNG sprites
- ✅ `stroke="currentColor"` for automatic theme adaptation
- ✅ Props: `size`, `color`, `animated?: boolean`
- ✅ `aria-hidden="true"` on decorative icons
- ✅ SMIL animations for idle states (folder pulse, gear rotation)
- ✅ Support `--text-secondary`, `--accent-red` as CSS variable fallbacks
- ❌ NEVER hardcode colors in SVG — use `currentColor` or CSS variables

### Icon Categories

| Category | Icons | Animated? |
|----------|-------|-----------|
| Navigation | ChevronLeft, ChevronRight, ArrowUp, Home | No |
| Actions | Search, Copy, Download, Refresh, Close | Refresh spins |
| Scan types | Shield (full), Crosshair (quick), USB (DMA), Eraser (cleaner) | Yes — per idle state |
| Risk levels | AlertTriangle (high), Alert (medium), Info (low), CheckCircle (safe) | High: pulse |
| File types | Folder, File, Image, Code | No |
| System | CPU, Memory, Disk, Network, Temperature | CPU: pulse |
| Status | Circle (online), XCircle (offline), Clock (pending) | Online: breathe |

---

## 10. Dark Mode ONLY

Predator is a dark-mode-only product. There is NO light theme. This is intentional — anti-cheat is a security tool, used in dimly-lit server rooms and gaming setups.

### Dark Mode Rules
- ✅ `<html style="color-scheme: dark">` — fixes scrollbars, inputs, form controls
- ✅ `<meta name="theme-color" content="#0a0a0f">` — matches bg-primary
- ✅ Native `<select>`: explicit `background-color` and `color` (Windows dark mode fix)
- ✅ Scrollbar: `rgba(255,68,68,0.25)` thumb, transparent track

---

## 11. i18n (Internationalization)

### Supported Languages
- `ru` — Russian (primary audience: GTA 5 RP CIS)
- `en` — English (secondary)

### i18n Rules
- ✅ ALL user-facing strings use `t('key')` — NEVER hardcoded
- ✅ Dates: `Intl.DateTimeFormat` — NEVER hardcoded formats
- ✅ Numbers: `Intl.NumberFormat` — NEVER hardcoded formats
- ✅ Brand names: `translate="no"` wrapper
- ✅ Language detection: `navigator.languages`, NOT IP geolocation
- ✅ RTL support: not required (ru/en are LTR)

### Translation Key Format
```ts
// ✅ GOOD: hierarchical, semantic
t('checker.tabs.full.label')
t('checker.empty.clean.title')

// ❌ BAD: flat, positional
t('tabFullLabel')
t('cleanTitle')
```

---

## 12. Performance (from vercel-react-best-practices)

### Bundle Size
- ✅ Import directly, avoid barrel files (`bundle-barrel-imports`)
- ✅ `React.lazy()` for heavy components (PredatorLogo3D, ThreatMap, ScanTerminal)
- ✅ Dynamic imports for admin pages
- ✅ Defer third-party scripts (analytics) after hydration

### Re-renders
- ✅ `useMemo` for expensive computations (filteredResults, groupedResults)
- ✅ `useCallback` for handlers passed to children
- ✅ Extract pure helpers OUTSIDE component (formatSize, riskClass, typeIcon)
- ✅ `React.memo()` on list items, table rows, stat cards
- ❌ NEVER define components inside components (`rerender-no-inline-components`)
- ❌ NEVER derive state in useEffect when it can be derived during render

### Data Fetching
- ✅ `Promise.all()` for independent fetches (`async-parallel`)
- ✅ `startTransition` for non-urgent UI updates (`rerender-transitions`)
- ✅ `useDeferredValue` for search/filter inputs
- ✅ Suspense boundaries for code-split components

### Lists
- ✅ Virtualize lists >100 items (`content-visibility: auto` or `virtua`)
- ✅ `key` on EVERY list item — NEVER use index as key
- ✅ `font-variant-numeric: tabular-nums` on number columns

---

## 13. Component Architecture (from vercel-react-best-practices)

### Hierarchy
```
App
├── ParticleBackground (ambient, always mounted)
├── PhaseRouter (based on app phase)
│   ├── OnboardingFlow
│   │   ├── WelcomeStep
│   │   │   └── PredatorLogo3D (Three.js, lazy loaded)
│   │   ├── LangStep
│   │   ├── ThemeStep
│   │   ├── AuthStep
│   │   └── DemoScanStep
│   │       └── ScanTerminal (MatrixRain + animated lines)
│   ├── MainScreen
│   │   ├── PredatorLogo3D
│   │   ├── Button ("Start Check")
│   │   └── Button ("Dashboard")
│   ├── Checker
│   │   ├── Tabs (Full/Quick/DMA/Cleaner)
│   │   ├── ScanTerminal (during scan)
│   │   ├── ThreatMap (post-scan)
│   │   ├── ResultsList (risk-grouped, virtualized)
│   │   │   └── ResultRow (memoized)
│   │   ├── FileDetailModal (lazy)
│   │   └── ExportActions
│   └── Dashboard
│       ├── Gauges (CPU/Memory/Temp)
│       ├── InfoCards (Uptime/OS/Hostname)
│       ├── ServerStatus
│       └── ProcessList (filterable)
├── UpdateModal (conditional)
└── ToastProvider (always mounted)
```

### State Management
- ✅ `useState` for local UI state (tabs, filters, expanded)
- ✅ `useRef` for mutable values that shouldn't trigger re-renders
- ✅ `useMemo` for derived state (filtered results, grouped items)
- ✅ Context for: Auth, Theme, Toast
- ❌ NO Redux/MobX — overkill for this app size
- ❌ NO prop drilling beyond 2 levels — extract to Context or composition

---

## 14. View Transitions (from vercel-react-view-transitions)

### Page-Level Transitions
```tsx
// Directional navigation — communicates spatial depth
startTransition(() => {
  addTransitionType('nav-forward'); // or 'nav-back' for back button
  router.push('/checker');
});

<ViewTransition
  enter={{ 'nav-forward': 'slide-from-right', 'nav-back': 'slide-from-left', default: 'none' }}
  exit={{ 'nav-forward': 'slide-to-left', 'nav-back': 'slide-to-right', default: 'none' }}
  default="none"
>
  <Page />
</ViewTransition>
```

### Shared Elements
```tsx
// Logo morphs between screens
<ViewTransition name="predator-logo">
  <PredatorLogo3D />
</ViewTransition>
```

### Suspense Reveals
```tsx
<Suspense fallback={<ViewTransition exit="fade-out"><Skeleton /></ViewTransition>}>
  <ViewTransition enter="fade-in" default="none">
    <HeavyComponent />
  </ViewTransition>
</Suspense>
```

---

## 15. Anti-Patterns (BLOCKED at Code Review)

| Anti-Pattern | Why It's Blocked | Fix |
|-------------|-----------------|-----|
| Emoji as icons | OS-dependent rendering, unprofessional | SVG component |
| `outline: none` without `:focus-visible` | Keyboard users can't navigate | `focus-visible:ring-2` |
| `transition: all` | GPU thrashing, unpredictable | List properties explicitly |
| `<div onClick>` | Not accessible, no keyboard | `<button>` or `<a>` |
| `user-scalable=no` | Blocks zoom for visually impaired | Remove entirely |
| `onPaste + preventDefault` | Blocks password managers, accessibility | Allow paste |
| Raw hex in components | No theme consistency | `var(--token)` |
| Image without `width`/`height` | Cumulative Layout Shift (CLS) | Explicit dimensions |
| `animation: infinite` without `prefers-reduced-motion` | Vestibular disorders | Reduced motion query |
| `font-size: 10px` | Below WCAG minimum (12px) | Minimum `--text-2xs: 11px` |

---

## 16. File Structure Convention

```
src/
├── styles/
│   ├── tokens.css          # All CSS custom properties (THE source)
│   ├── reset.css           # Box-sizing, scrollbar, base
│   ├── layout.css          # App shell, container, background
│   ├── typography.css      # Type scale utility classes
│   ├── components.css      # Buttons, inputs, badges, cards, tables
│   ├── checker.css         # Checker-specific styles
│   ├── dashboard.css       # Dashboard + stats
│   └── onboarding.css      # Onboarding flow
├── components/
│   ├── ui/                 # Reusable primitives
│   │   ├── Button.tsx
│   │   ├── Skeleton.tsx
│   │   ├── Tooltip.tsx
│   │   ├── Toast.tsx
│   │   └── Modal.tsx
│   ├── checker/            # Checker page components
│   │   ├── ScanTerminal.tsx
│   │   ├── ThreatMap.tsx
│   │   ├── ResultsList.tsx
│   │   └── FileDetailModal.tsx
│   ├── dashboard/          # Dashboard components
│   │   ├── Gauge.tsx
│   │   ├── ProcessList.tsx
│   │   └── ServerStatus.tsx
│   └── onboarding/         # Onboarding components
├── pages/                  # Route-level components
│   ├── Checker.tsx
│   └── Dashboard.tsx
├── hooks/                  # Custom hooks
│   ├── useSound.ts
│   └── useSystemStream.ts
├── types/                  # TypeScript type definitions
└── icons/                  # SVG icon components
```

---

## 17. Immediate Fixes Required (from Audit)

### P0 — BLOCKING
1. ❌ **Remove Neuralyn Override** in `tokens.css` — overrides Predator theme to white
2. ❌ **Fix `--text-2xs: 10px` → `11px`** — WCAG minimum
3. ❌ **i18n empty state** in Checker.tsx — hardcoded Russian
4. ❌ **Admin: split `App.css`** into modules (tokens, layout, components, pages)

### P1 — HIGH
5. ❌ Emoji in CompactScanOverlay (`🛡️⚡🔌🧹`) → SVG icons
6. ❌ Emoji in admin empty states (`📭`) → SVG illustrations
7. ❌ Icon-only buttons missing `aria-label` in admin
8. ❌ Dashboard: mock data → real IPC streaming

### P2 — MEDIUM
9. ❌ Admin: no pagination in History
10. ❌ Admin: no breadcrumbs for navigation context
11. ❌ Admin: `memo()` on Login component with no props
12. ❌ Dashboard: process list needs CPU% + sorting

---

## 18. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | 2026-07-27 | Initial MASTER.md — 5-skill synthesis, complete design system |
