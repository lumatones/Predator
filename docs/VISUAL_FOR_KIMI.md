# 🎨 Predator Desktop App — Visual Design Brief for Kimi-k2.7

> **READ THIS FIRST. You have everything you need to start coding immediately.**
>
> **Your job:** Enhance the visual experience of the existing Predator desktop app with animations (Framer Motion), particles (tsparticles), page transitions (AnimatePresence), skeleton loading, magnetic hover, glitch effects, and toast notifications.
>
> **DO NOT change:** Business logic, state management, IPC calls, API functions, error handling, data flow, or the 4-color-theme system.
> **DO change/add:** Animations, transitions, loading states, micro-interactions, particle backgrounds, toast system.

---

## 📦 Project Overview

**Predator** is an anti-cheat scanner for GTA 5 RP. The desktop app (`src/`) is an Electron app with a React 18 + TypeScript frontend. Users go through onboarding (language → theme → auth), then can run security scans (3 modes: full/quick/DMA) or view a system monitor dashboard.

**Current stack:** React 18 + TypeScript + CSS Variables + Framer Motion (already installed)  
**Target additions:** tsparticles, Radix Toast, React Spring (optional)

**Install these before starting:**
```bash
npm install @tsparticles/react @tsparticles/slim
npm install @radix-ui/react-toast @radix-ui/react-dialog @radix-ui/react-slot
```

---

## 🗂️ Main App File Structure

```
src/
├── main.tsx                    # ReactDOM.createRoot + App
├── App.tsx                     # Main app: 8 phases, onboarding flow, routing
├── App.css                     # 700+ line design system (MODIFY THIS)
├── api.ts                      # API functions: validateToken, useToken, requestAccess, checkRequestStatus
├── types/
│   ├── index.ts                # AppPhase, ThemeId, ThemeColors, Lang, T (translations)
│   └── electron.d.ts           # ElectronAPI interface, ScanResult, ScanProgress, SystemInfoSnapshot
├── hooks/
│   ├── useAuth.ts              # Token validation + access request + polling
│   └── useScan.ts              # Scan state management
├── components/
│   ├── ErrorBoundary.tsx       # React error boundary
│   ├── ServerStatus.tsx        # Server connectivity indicator
│   └── ui/
│       └── UpdateModal.tsx     # Update modal (available/downloading/done/error)
├── pages/
│   ├── Checker.tsx             # Scanner UI: 3 tab modes, progress, results, search, export
│   └── Dashboard.tsx           # System monitor: SVG gauges, process list, streaming data
├── icons/
│   ├── index.ts                # Barrel exports
│   ├── IconChart.tsx, IconCrosshair.tsx, IconDashboard.tsx, IconDNA.tsx
│   ├── IconFolder.tsx, IconGear.tsx, IconGlobe.tsx, IconLock.tsx
│   ├── IconMonitor.tsx, IconRegistry.tsx, IconShield.tsx, IconUSB.tsx
└── utils/
    └── export-report.ts        # HTML/JSON report export with Chart.js
```

---

## 🎨 Color Theme System — CRITICAL

The app has **4 themes** that can be switched by the user. ALL visual components MUST work with any theme.

```typescript
// src/types/index.ts
export type ThemeId = 'predator' | 'ocean' | 'stealth' | 'nebula'

export const THEMES: Record<ThemeId, ThemeColors> = {
  predator: { accent: '#ff4d5a', light: '#ff8a5b', dark: '#b91c1c', bg: '#020202', card: '#0d0d0f', name: 'Predator Red' },
  ocean:    { accent: '#7dd3fc', light: '#60a5fa', dark: '#1d4ed8', bg: '#020202', card: '#0d0d0f', name: 'Ocean Blue' },
  stealth:  { accent: '#a1a1aa', light: '#e4e4e7', dark: '#3f3f46', bg: '#020202', card: '#0d0d0f', name: 'Stealth Black' },
  nebula:   { accent: '#c084fc', light: '#f0abfc', dark: '#7c3aed', bg: '#020202', card: '#0d0d0f', name: 'Nebula Purple' },
}
```

**How themes work in CSS:** The `App.tsx` sets CSS custom properties dynamically:
```tsx
r.style.setProperty('--accent-red', c.accent)
r.style.setProperty('--accent-orange', c.light)
r.style.setProperty('--accent-gradient', `linear-gradient(135deg, ${c.accent}, ${c.light}, ${c.dark})`)
r.style.setProperty('--bg-primary', c.bg)
r.style.setProperty('--bg-secondary', c.card)
```

**RULE: Always get colors from CSS variables, never hardcode.**
```css
/* ✅ Correct */
background: var(--accent-red);
color: var(--text-primary);

/* ❌ Wrong */
background: #ff4444;
```

---

## 🧩 App Architecture (`App.tsx`)

The app has 8 phases managed by `useState<AppPhase>`:

```
loading → onboarding-lang → onboarding-theme → onboarding-auth → main
                                                    ↓ (request access)
                                            requesting-access → main (when approved)
                                                                 → onboarding-auth (when rejected)

main → checker (scan UI)  or  main → dashboard (system monitor)
     ↖ back              ↖ back
```

**Phase rendering pattern:**
```tsx
{phase === 'loading' && renderCard(<Spinner + "Загрузка..." + progress bar />)}
{phase === 'onboarding-lang' && renderCard(<Language selector />)}
{phase === 'onboarding-theme' && renderCard(<4 theme buttons />)}
{phase === 'onboarding-auth' && renderCard(<Token input + confirm + request access />)}
{phase === 'requesting-access' && renderCard(<Polling status: pending/approved/rejected />)}
{phase === 'main' && renderCard(<2 main cards: Start Check + Dashboard />)}
{phase === 'checker' && <Checker />}
{phase === 'dashboard' && <Dashboard />}
```

**Key components rendered in App.tsx:**
- `<Logo>` — SVG predator logo with gradient, memoized
- `<Footer>` — version + secure connection indicator, memoized
- `<UpdateModal>` — 4-state update modal
- `background-gradient` — 3 gradient orbs (`.orb-1`, `.orb-2`, `.orb-3`)
- `scan-line` — CSS animated scan line

**Existing CSS classes (KEEP THESE NAMES):**
- `.app`, `.container`, `.background-gradient`, `.gradient-orb`, `.orb-1/2/3`, `.scan-line`
- `.logo-section`, `.logo-icon`, `.title`, `.subtitle`
- `.status-section`, `.status-card`
- `.onb-steps`, `.onb-step`, `.onb-step-dot`, `.onb-step-label`, `.onb-step-line`, `.onb-step-actions`
- `.onb-label`, `.onb-desc`
- `.lang-grid`, `.lang-btn`, `.lang-flag`, `.lang-name`
- `.theme-grid`, `.theme-btn`, `.theme-swatch`, `.theme-name`
- `.token-input-wrap`, `.token-label`, `.token-field`, `.token-input`, `.token-error`, `.request-id-badge`
- `.start-button`, `.start-button.secondary`, `.skip-button`
- `.spinner`, `.spinner-ring`, `.status-text`, `.progress-bar`, `.progress-fill`
- `.ready-icon`, `.ready-text`
- `.main-cards`, `.main-card`, `.main-card-icon`, `.main-card-body`, `.main-card-title`, `.main-card-desc`, `.main-card-arrow`
- `.footer`, `.dot`, `.secure`, `.version`, `.update-indicator`
- `.update-modal-overlay`, `.update-modal`, `.update-modal-icon`, `.update-modal-title`, `.update-modal-version`, `.update-modal-actions`, `.update-modal-btn`

**Checker CSS classes (KEEP THESE NAMES):**
- `.checker-wrapper`, `.checker-header`, `.checker-title-row`, `.checker-title`, `.checker-desc`, `.checker-back-btn`
- `.checker-status-dot`, `.checker-tabs`, `.checker-tab`, `.checker-tab-icon`, `.checker-tab-text`, `.checker-tab-label`, `.checker-tab-desc`, `.checker-tab-badge`
- `.checker-start-btn`
- `.checker-scanning`, `.checker-scanning-phase`, `.checker-scanning-sub`
- `.checker-radar`, `.radar-ring`, `.radar-dot`
- `.checker-progress-header`, `.checker-progress-label`, `.checker-progress-pct`, `.checker-progress-bar`, `.checker-progress-fill`, `.checker-progress-info`
- `.checker-current-dir`, `.checker-error`
- `.checker-results`, `.checker-summary`, `.checker-summary-icon`, `.checker-summary-text`, `.checker-summary-stats`, `.checker-summary-dot`, `.checker-summary-risks`
- `.checker-search`, `.search-icon`, `.search-input`, `.search-clear`, `.search-no-results`
- `.checker-results-split`, `.checker-results-list`, `.checker-results-detail`
- `.result-row`, `.result-group`, `.result-group-header`, `.result-group-content`, `.result-group-badge`
- `.checker-export-btns`, `.checker-export-btn`

**Dashboard CSS classes (KEEP THESE NAMES):**
- `.dash-wrapper`, `.dash-header`, `.dash-title`, `.dash-header-right`, `.dash-online`, `.dash-loading`
- `.dash-gauges`, `.dash-gauge`, `.dash-gauge-label`, `.dash-gauge-value`, `.dash-gauge-text`, `.dash-gauge-sub`
- `.dash-info-row`, `.dash-card`, `.dash-card-label`, `.dash-card-value`, `.dash-card-sub`
- `.dash-processes`, `.dash-processes-header`, `.dash-process-filter`, `.dash-process-list`
- `.dash-process-row`, `.dash-pid`, `.dash-pname`, `.dash-pname-dot`, `.dash-pmem`
- `.dash-empty`, `.dash-empty-text`

---

## 🧩 Checker.tsx Architecture (Scanner UI)

The Checker page has 4 states:

```
1. Tab Selection (idle):
   - 3 tabs in grid: Full Scan (green) / Quick Scan (blue) / DMA (purple)
   - Each tab has: icon + label + description
   - "Start Check" button below tabs
   - Back button to return to main

2. Eye Animation → Scanning (scanning):
   - 2.5s Red Eye animation (opening → scanning → closing)
   - Then: scanning phase label, radar animation, progress bar, current dir, file counts

3. Results (done):
   - Summary card (emoji + text + stats + risk badges)
   - Search bar with focus glow
   - Results split: list (left) + detail panel (right)
   - Groups: high risk (red) / medium (yellow) / low (green)
   - Each result row: icon + filename + path + matches
   - Export buttons: HTML / JSON

4. Error:
   - Red error card with retry button
```

**Tab colors and icons:**
```typescript
const TABS = [
  { id: 'full',  label: 'Полное сканирование', desc: '...', icon: IconShield, color: '#22c55e', accent: '#22c55e' },
  { id: 'quick', label: 'Быстрая проверка',    desc: '...', icon: IconCrosshair, color: '#3B82F6', accent: '#3B82F6' },
  { id: 'dma',   label: 'DMA-устройства',      desc: '...', icon: IconUSB, color: '#8B5CF6', accent: '#8B5CF6' },
]
```

---

## 🧩 Dashboard.tsx Architecture (System Monitor)

```
- Back button + title + ServerStatus indicator + online/loading badge
- 3 SVG gauges: CPU (red), Memory (blue), Temperature (green/yellow)
- 3 info cards: Uptime, OS, Hostname
- Process list with filter
```

**Gauge component** — SVG circles with `stroke-dasharray` animation. Accepts `value` (0-100), `label`, `sub`, `color`, `size`.

---

## 🔌 Electron API (for IPC calls)

```typescript
// src/types/electron.d.ts
interface ElectronAPI {
  getAppVersion(): Promise<string>
  getPCName(): Promise<string>
  getConfig(): Promise<Config>
  saveConfig(partial: Partial<Config>): Promise<Config>
  getApiBase(): Promise<string>
  setApiBase(url: string): Promise<string>

  // Scanner
  startScan(mode?: ScanMode, tokenId?: number): Promise<ScanResponse>
  onScanProgress(callback: (data: ScanProgress) => void): () => void
  offScanProgress?(unsubscribe?: () => void): void

  // System dashboard
  getSystemSnapshot(): Promise<SystemInfoSnapshot>
  startSystemStream(intervalMs?: number): void
  stopSystemStream(): void
  onSystemUpdate(callback: (data: SystemInfoSnapshot) => void): () => void

  // Auto-updater
  startUpdateCheck(): Promise<{ updateAvailable: boolean; version?: string }>
  startDownload(): Promise<{ success: boolean; error?: string }>
  restartApp(): Promise<void>
  onUpdateAvailable(callback: (info: { version: string }) => void): void
  onUpdateNotAvailable(callback: () => void): void
  onDownloadProgress(callback: (data: DownloadProgress) => void): void
  onUpdateDownloaded(callback: () => void): void
  onUpdateError(callback: (message: string) => void): void
}
```

**The API is accessed via `window.electronAPI`. In dev mode (no Electron), it may be undefined — pages use mock data as fallback.**

---

## 📋 VISUAL TASKS — Do these IN ORDER

---

### ═══════════════════════════════════════
### TASK 1: ParticleBackground Component
### ═══════════════════════════════════════

**Create:** `src/components/ui/ParticleBackground.tsx`  
**Modify:** `src/App.tsx` (add inside `.background-gradient` div)

**Current state:** 3 static CSS gradient orbs (`.orb-1/2/3`) with blur animation.  
**Target:** Interactive particle network that responds to cursor.

**What to build:**
```tsx
import { useCallback } from 'react'
import Particles from '@tsparticles/react'
import { loadSlim } from '@tsparticles/slim'
import type { Engine } from '@tsparticles/engine'

export default function ParticleBackground() {
  const particlesInit = useCallback(async (engine: Engine) => {
    await loadSlim(engine)
  }, [])

  return (
    <Particles
      id="predator-particles"
      init={particlesInit}
      options={{
        fullScreen: false,
        fpsLimit: 60,
        particles: {
          number: { value: 60, density: { enable: true } },
          color: { value: ['#ff4444', '#ff6b35'] },
          shape: { type: 'circle' },
          opacity: { value: 0.25, random: true },
          size: { value: { min: 1, max: 3 }, random: true },
          move: {
            enable: true,
            speed: 0.5,
            direction: 'none' as const,
            random: true,
            outModes: { default: 'bounce' as const },
          },
          links: {
            enable: true,
            color: '#ff4444',
            opacity: 0.08,
            distance: 150,
          },
        },
        interactivity: {
          events: {
            onHover: { enable: true, mode: 'repulse' },
          },
          modes: {
            repulse: { distance: 100, duration: 0.4 },
          },
        },
        detectRetina: true,
        background: { color: 'transparent' },
      }}
      style={{
        position: 'absolute',
        inset: 0,
        zIndex: 0,
        pointerEvents: 'none',
      }}
    />
  )
}
```

**Integration in App.tsx:**
```tsx
// In .background-gradient div, ADD after the 3 gradient orbs:
<ParticleBackground />
```

**Keep the existing orbs** — they work well together with particles.

---

### ═══════════════════════════════════════
### TASK 2: Page Transitions (AnimatePresence)
### ═══════════════════════════════════════

**Modify:** `src/App.tsx`  
**Add:** Framer Motion `<AnimatePresence>` and `<motion.div>`

**Wrap each phase in a motion.div with exit animation:**

```tsx
import { AnimatePresence, motion } from 'framer-motion'

// Inside the return, wrap each phase block:
<AnimatePresence mode="wait">
  {phase === 'loading' && (
    <motion.div
      key="loading"
      initial={{ opacity: 0, filter: 'blur(8px)', scale: 0.97 }}
      animate={{ opacity: 1, filter: 'blur(0px)', scale: 1 }}
      exit={{ opacity: 0, filter: 'blur(8px)', scale: 0.97 }}
      transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
    >
      {/* existing content */}
    </motion.div>
  )}
  {/* Repeat for ALL phases: onboarding-lang, -theme, -auth, requesting-access, main, checker, dashboard */}
</AnimatePresence>
```

**Important:** The `renderCard()` helper already returns JSX — wrap its result.

---

### ═══════════════════════════════════════
### TASK 3: Toast System (Radix Toast)
### ═══════════════════════════════════════

**Create:** `src/components/ui/Toast.tsx`, `src/components/ui/ToastProvider.tsx`  
**Create:** `src/hooks/useToast.ts`

**What to build:**
- Radix Toast primitive with custom styling
- 4 variants: success (green), error (red), warning (amber), info (blue)
- Slide-in from bottom-right with Framer Motion
- Auto-dismiss after 5 seconds
- Stack multiple toasts vertically

```tsx
// useToast hook:
const { toast } = useToast()
toast.success('Сканирование завершено')
toast.error('Ошибка подключения')
```

**Use CSS variables:**
- Background: `var(--bg-card)` with `backdrop-filter: blur(16px)`
- Border: `1px solid var(--border-color)`
- Success border-left: `#22c55e`, Error: `#EF4444`
- Text color: `var(--text-primary)`

**Integrate in App.tsx:**
```tsx
// Wrap the entire app:
<ToastProvider>
  <div className="app">...</div>
</ToastProvider>
```

---

### ═══════════════════════════════════════
### TASK 4: Stagger Animations for Results
### ═══════════════════════════════════════

**Modify:** `src/pages/Checker.tsx` (the results rendering section)

**Replace the CSS `@keyframes rowSlideIn` with Framer Motion stagger:**

```tsx
import { motion } from 'framer-motion'

const containerVariants = {
  hidden: {},
  visible: {
    transition: { staggerChildren: 0.03 }
  }
}

const itemVariants = {
  hidden: { opacity: 0, x: -20 },
  visible: { opacity: 1, x: 0, transition: { duration: 0.3 } }
}

// Wrap results list:
<motion.div
  className="checker-results-list"
  variants={containerVariants}
  initial="hidden"
  animate="visible"
>
  {results.map((r, i) => (
    <motion.div key={i} className="result-row" variants={itemVariants}>
      {/* existing row content */}
    </motion.div>
  ))}
</motion.div>
```

**Also apply stagger to result groups** (high/medium/low risk accordion groups).

---

### ═══════════════════════════════════════
### TASK 5: Skeleton Loading
### ═══════════════════════════════════════

**Create:** `src/components/ui/Skeleton.tsx`

**Replace:** All `.spinner` loading states with skeleton placeholders that match the content shape.

**Variants:**
```tsx
// SkeletonCard — matches .status-card shape
// SkeletonText — 1-3 lines of text
// SkeletonCircle — avatar/icon placeholder
// SkeletonTable — 5 rows matching table column widths
// SkeletonGauge — circle placeholder for dashboard gauges

export function SkeletonCard({ lines = 3 }: { lines?: number }) { ... }
export function SkeletonTable({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) { ... }
```

**Animation:**
```css
@keyframes shimmer {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}

.skeleton {
  background: linear-gradient(
    90deg,
    rgba(255, 255, 255, 0.03) 25%,
    rgba(255, 255, 255, 0.06) 50%,
    rgba(255, 255, 255, 0.03) 75%
  );
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: var(--radius-md);
}
```

**Where to use:**
- `App.tsx` phase `'loading'` → SkeletonCard instead of spinner
- `Checker.tsx` before results arrive → SkeletonTable
- `Dashboard.tsx` before snapshot → SkeletonGauge + SkeletonCard

---

### ═══════════════════════════════════════
### TASK 6: Glitch Effect on Logo
### ═══════════════════════════════════════

**Modify:** `src/App.tsx` (the Logo component) and `src/App.css`

**Add CSS-only glitch effect on the `Predator` title when hovered:**
```css
.title {
  position: relative;
}

.title:hover::before,
.title:hover::after {
  content: 'Predator';
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: var(--accent-gradient);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}

.title:hover::before {
  animation: glitch-1 0.3s infinite linear alternate-reverse;
  clip-path: polygon(0 15%, 100% 25%, 100% 40%, 0 45%);
}

.title:hover::after {
  animation: glitch-2 0.4s infinite linear alternate-reverse;
  clip-path: polygon(0 65%, 100% 60%, 100% 85%, 0 80%);
}

@keyframes glitch-1 {
  0% { transform: translateX(0); filter: hue-rotate(0deg); }
  20% { transform: translateX(2px); }
  50% { transform: translateX(-1px); }
  80% { transform: translateX(1px); filter: hue-rotate(90deg); }
  100% { transform: translateX(0); }
}

@keyframes glitch-2 {
  0% { transform: translateX(0); filter: hue-rotate(0deg); }
  30% { transform: translateX(-2px); }
  60% { transform: translateX(1px); filter: hue-rotate(-90deg); }
  100% { transform: translateX(0); }
}
```

---

### ═══════════════════════════════════════
### TASK 7: Magnetic Hover Hook
### ═══════════════════════════════════════

**Create:** `src/hooks/useMagnetic.ts`

**What it does:** Elements follow the cursor slightly within their bounds, creating a subtle magnetic attraction effect.

```tsx
import { useRef, useEffect } from 'react'

export function useMagnetic(strength = 0.3) {
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    const handleMove = (e: MouseEvent) => {
      const rect = el.getBoundingClientRect()
      const x = e.clientX - rect.left - rect.width / 2
      const y = e.clientY - rect.top - rect.height / 2
      el.style.transform = `translate(${x * strength}px, ${y * strength}px)`
      el.style.transition = 'transform 0.2s ease-out'
    }

    const handleLeave = () => {
      el.style.transform = 'translate(0, 0)'
    }

    el.addEventListener('mousemove', handleMove)
    el.addEventListener('mouseleave', handleLeave)
    return () => {
      el.removeEventListener('mousemove', handleMove)
      el.removeEventListener('mouseleave', handleLeave)
    }
  }, [strength])

  return ref
}
```

**Apply to:** Main cards (`.main-card`), theme buttons (`.theme-btn`), checker tabs (`.checker-tab`).

---

### ═══════════════════════════════════════
### TASK 8: Modal v2 — Radix Dialog
### ═══════════════════════════════════════

**Modify:** `src/components/ui/UpdateModal.tsx`

**Replace the current custom overlay/click-handler with Radix Dialog:**
- `<Dialog.Root>` controlled by `modal.show`
- `<Dialog.Portal>` for rendering outside DOM hierarchy
- `<Dialog.Overlay>` with `backdrop-filter: blur(4px)` and fade animation
- `<Dialog.Content>` with scale(0.95)→1 spring animation
- Focus trap, ESC-to-close, aria-attributes come free with Radix

**Keep the same 4 internal states** (available/downloading/done/error) — only replace the outer wrapper.

---

### ═══════════════════════════════════════
### TASK 9: Spring Bounce Buttons
### ═══════════════════════════════════════

**Create:** `src/components/ui/Button.tsx`

**Replace ad-hoc buttons with a unified component:**
```tsx
import { motion } from 'framer-motion'

interface ButtonProps {
  variant?: 'primary' | 'secondary' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  children: React.ReactNode
  onClick?: () => void
  disabled?: boolean
  className?: string
}

export function Button({ variant = 'primary', size = 'md', ...props }: ButtonProps) {
  return (
    <motion.button
      className={`btn-${variant} btn-${size}`}
      whileHover={{ scale: 1.02, y: -1 }}
      whileTap={{ scale: 0.96 }}
      transition={{ type: 'spring', stiffness: 400, damping: 25 }}
      {...props}
    >
      {props.children}
    </motion.button>
  )
}
```

**Apply to:** All buttons in App.tsx, Checker.tsx, Dashboard.tsx — especially the "Start Check" button and "Confirm" button.

---

### ═══════════════════════════════════════
### TASK 10: 3D Logo (Optional — Most Complex)
### ═══════════════════════════════════════

**Create:** `src/components/ui/PredatorLogo3D.tsx`

**This is the most complex task. Skip if short on time.**
- React Three Fiber `<Canvas>` with a hexagonal shield
- Wireframe edges with red emissive material
- Slow rotation on Y-axis
- Point light for glow
- Rendered inside the `.logo-icon` div, replacing the static SVG

---

## ⚡ CRITICAL RULES

1. **DO NOT modify `api.ts`, `types/index.ts`, `types/electron.d.ts`, `hooks/useAuth.ts`** — these are correct.
2. **DO NOT change page-level state logic.** Keep `useState`, `useEffect`, handlers as-is.
3. **DO change rendering.** Replace div soup with proper animated components.
4. **RESPECT the 4 color themes.** Always use CSS variables, never hardcoded colors.
5. **Keep all existing CSS class names** that are referenced in JS. You can add new classes, change styles, but don't delete existing class names from the HTML.
6. **New components go in `src/components/ui/`.** Named exports.
7. **New hooks go in `src/hooks/`.** Named exports.
8. **Use TypeScript.** All props must be typed.
9. **Test after each task.** Run `npx tsc --noEmit`.
10. **Work in order:** Task 1 → 2 → 3 → ... → 10. Each builds on the previous.
11. **Use Framer Motion for ALL animations.** `motion.div`, `AnimatePresence`, variants, stagger.
12. **Keep `framer-motion` — it's already installed.** Don't replace with CSS animations.

---

## 🚀 Getting Started

1. Install new dependencies (listed at top)
2. Start with Task 1 (ParticleBackground) — immediately visible on all screens
3. After each task, verify with `npx tsc --noEmit`
4. Continue through all 10 tasks

**The existing code works. Make it beautiful.**
