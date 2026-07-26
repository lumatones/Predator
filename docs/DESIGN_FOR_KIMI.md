# 🎨 Predator Admin Panel — Complete Redesign Brief for Kimi-k2.7

> **READ THIS FIRST. You have everything you need to start coding immediately.**
>
> **Your job:** Redesign the existing React admin panel with 3D effects (Three.js), animations (Framer Motion), particles (tsparticles), glassmorphism, and a cyberpunk aesthetic.
>
> **DO NOT change:** Business logic, state management, API calls, error handling, or data flow.
> **DO change:** Component markup, CSS, animations, 3D backgrounds, transitions, loading states, icons.

---

## 📦 Project Overview

**Predator** is an anti-cheat system for GTA 5 RP. The admin panel (`admin/`) lets administrators manage access tokens, approve/reject user requests, view scan history, monitor threats, and review suspicious file hashes.

**Current stack:** React 18 + TypeScript + CSS Variables + Chart.js  
**Target stack:** React 18 + TypeScript + Framer Motion + Three.js (React Three Fiber) + tsparticles + Recharts + lucide-react

**Install these before starting:**
```bash
cd admin
npm install framer-motion three @react-three/fiber @react-three/drei @tsparticles/react @tsparticles/slim recharts lucide-react
npm uninstall chart.js react-chartjs-2
```

---

## 🗂️ File Structure

```
admin/
├── package.json
├── vite.config.ts          # Vite with proxy /api → localhost:3001
├── tsconfig.json
├── index.html
├── src/
│   ├── main.tsx            # ReactDOM + BrowserRouter
│   ├── App.tsx             # Auth state + routes
│   ├── App.css             # 700+ line design system (YOUR MAIN TARGET)
│   ├── api.ts              # 23 API functions (DO NOT MODIFY)
│   ├── components/
│   │   └── Layout.tsx      # Sidebar + navigation + user footer
│   └── pages/
│       ├── Login.tsx           # Login form with 3 CSS orbs
│       ├── Dashboard.tsx       # Stats cards + charts + tables + WebSocket
│       ├── Pending.tsx         # Access request table + countdown timer
│       ├── Tokens.tsx          # Token generation form + table
│       ├── History.tsx         # Event table with filters + search
│       └── SuspiciousHashes.tsx # 4-tab table: pending/confirmed/false_positive/scan_results
```

---

## 🔌 API Client (`api.ts`) — Complete Reference

**Base:** `/api` (proxied by Vite to `localhost:3001`)  
**Auth:** JWT token in `Authorization: Bearer <token>` header

### Types

```typescript
interface AuthState {
  token: string
  admin: { id: number; username: string; role: string }
}

interface PendingRequest {
  id: number
  pc_username: string
  status: string
  created_at: string
  expires_at: string | null
}

interface Token {
  id: number
  code: string
  code_display: string
  is_active: boolean
  used_by: string | null
  used_at: string | null
  created_at: string
  created_by_name: string
}

interface DashboardStats {
  pendingCount: number
  activeTokens: number
  usedTokens: number
  recentRequests: PendingRequest[]
  recentTokens: Token[]
}

interface HistoryItem {
  id: string
  date: string
  type: 'token' | 'request'
  subType: string
  description: string
  detail: string
  created_at: string
  actor: string
}

interface ScanStats {
  totalScans: number
  totalScanned: number
  totalSuspicious: number
  byMode: { mode: string; cnt: number; threats: number }[]
  byDay: { day: string; cnt: number; threats: number }[]
  recent: {
    id: number
    pc_username: string
    mode: string
    total_scanned: number
    suspicious_files: number
    high_risk_count: number
    created_at: string
  }[]
}

interface SuspiciousHash {
  id: number
  sha256: string
  file_name: string
  pc_username: string
  file_size: number
  risk_score: number
  status: 'pending' | 'confirmed' | 'false_positive'
  reviewed_by: number | null
  reviewed_by_name: string
  reviewed_at: string | null
  created_at: string
}

interface ScanResultHash {
  sha256: string
  file_name: string
  file_size: number
  pc_usernames: string[]
  first_seen: string
  last_seen: string
  occurrences: number
  status: 'new' | 'pending' | 'confirmed' | 'false_positive'
}
```

### API Functions

```typescript
// Auth
login(username: string, password: string): Promise<LoginResponse>

// Pending
getPending(token: string): Promise<PendingRequest[]>
approveRequest(token: string, id: number): Promise<{ success: boolean }>
rejectRequest(token: string, id: number): Promise<{ success: boolean }>

// Tokens
getTokens(token: string): Promise<Token[]>
generateTokens(token: string, count: number): Promise<{ success: boolean; tokens: string[] }>
revokeToken(token: string, id: number): Promise<{ success: boolean }>

// Dashboard (composed from getPending + getTokens)
getDashboardStats(token: string): Promise<DashboardStats>

// Scan Stats
getScanStats(token: string): Promise<ScanStats>

// History
getHistory(token: string, limit: number): Promise<{ total: number; items: HistoryItem[]; stats: {...} }>

// Suspicious Hashes
getSuspiciousHashes(token: string, status: string): Promise<SuspiciousHash[]>
approveHash(token: string, id: number): Promise<{ success: boolean }>
rejectHash(token: string, id: number): Promise<{ success: boolean }>
getScanResultHashes(token: string, limit: number): Promise<{ total: number; hashes: ScanResultHash[] }>
confirmHashFromScan(token: string, sha256: string, fileName?: string, fileSize?: number): Promise<{ success: boolean }>
```

**IMPORTANT:** All API functions are already correct. Do not modify `api.ts` or any API call logic in pages.

---

## 🎨 Current CSS Design System (`App.css`) — Key Variables

```css
:root {
  --bg-primary: #0a0a0f;
  --bg-secondary: #12121a;
  --bg-card: rgba(18, 18, 26, 0.92);
  --bg-hover: rgba(255, 255, 255, 0.04);
  --border: rgba(255, 255, 255, 0.06);
  --border-active: rgba(255, 68, 68, 0.3);
  --text-primary: #f0f0f0;
  --text-secondary: rgba(255, 255, 255, 0.5);
  --text-muted: rgba(255, 255, 255, 0.3);
  --accent: #ff4444;
  --accent-dim: rgba(255, 68, 68, 0.15);
  --accent-glow: rgba(255, 68, 68, 0.3);
  --accent-gradient: linear-gradient(135deg, #ff4444 0%, #ff6b35 100%);
  --green: #22c55e;
  --green-dim: rgba(34, 197, 94, 0.15);
  --yellow: #eab308;
  --yellow-dim: rgba(234, 179, 8, 0.15);
  --sidebar-width: 240px;
  --radius: 12px;
  --radius-sm: 8px;

  /* Typography */
  --font-display: 'JetBrains Mono', monospace;
  --font-heading: 'Inter', sans-serif;
  --font-body: 'Inter', sans-serif;
  --font-code: 'JetBrains Mono', monospace;
}
```

**Existing CSS classes used across all pages:**
- `.layout`, `.sidebar`, `.sidebar-header`, `.sidebar-logo`, `.sidebar-nav`, `.nav-link`, `.nav-link.active`, `.sidebar-footer`, `.sidebar-user`
- `.main-content`, `.page-header`, `.page-actions`
- `.stats-grid`, `.stat-card`, `.stat-card-icon`, `.stat-card-value`, `.stat-card-label`
- `.table-container`, `.table-header`, `.table-empty`, `table`, `thead th`, `tbody td`
- `.badge`, `.badge-pending`, `.badge-approved`, `.badge-rejected`, `.badge-active`, `.badge-inactive`
- `.btn`, `.btn-primary`, `.btn-green`, `.btn-outline`, `.btn-danger`, `.btn-sm`
- `.form-input`, `.form-group`, `.login-card`, `.login-wrapper`, `.orb-1/2/3`
- `.token-code`, `.token-code-sm`, `.copy-btn`
- `.generate-form`, `.generate-result`, `.token-list`, `.token-item`
- `.loading`, `.spinner`, `.toast-container`, `.toast`, `.toast-success`, `.toast-error`
- `.text-display`, `.text-h1`-`.text-h4`, `.text-body`, `.text-sm`, `.text-caption`, `.text-code`, `.text-gradient`
- `.action-btns`, `.filter-tabs`

**You can keep these classes or replace them — your choice.** The key rule: don't break the JS logic in page components.

---

## 🧩 Component Architecture

### `App.tsx` (Auth + Router)
```tsx
// AuthContext provides { auth, login, logout }
// auth = { token: string, admin: { id, username, role } } | null

// Routes:
//   /          → Dashboard
//   /pending   → Pending
//   /tokens    → Tokens
//   /history   → History
//   /hashes    → SuspiciousHashes

// Login page shown when !auth (wrapped in .login-wrapper with 3 .orb divs)
// All other pages wrapped in <Layout> which contains sidebar + main-content
```

### `Layout.tsx` (Sidebar)
```tsx
// Props: { children: ReactNode }
// Uses useAuth() to get auth, logout
// Sidebar contains:
//   - Logo (SVG with gradient) + "Predator" + "admin" badge
//   - 5 NavLinks: Dashboard, Запросы, Токены, История, Сигнатуры
//   - User footer: avatar (first letter), username, role, logout button
// Active nav link: accent background + left border accent bar
```

### Page Pattern (every page follows this):
```tsx
export default function PageName() {
  const { auth } = useAuth()
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  // ... API calls, handlers, effects
  
  // 3 states: loading → spinner, error → error message + retry, data → content
  
  return (
    <div>
      <div className="page-header">
        <div><h1>Title</h1><p>Subtitle</p></div>
        <div className="page-actions">{/* buttons */}</div>
      </div>
      {/* content: stats-grid, tables, forms, etc. */}
    </div>
  )
}
```

---

## 🎯 NEW Design System (Target)

### Updated Color Palette
```css
:root {
  --bg-primary: #06060e;         /* deeper black-blue */
  --bg-secondary: #0c0c1a;
  --bg-card: rgba(12, 12, 26, 0.85);

  --accent: #ff3b3b;
  --accent-glow: rgba(255, 59, 59, 0.4);
  --accent-gradient: linear-gradient(135deg, #ff3b3b 0%, #ff6b35 50%, #ff3b3b 100%);

  --neon-cyan: #00f0ff;
  --electric-violet: #7c3aed;
  --warning-amber: #f59e0b;

  --glass-bg: rgba(255, 255, 255, 0.03);
  --glass-border: rgba(255, 255, 255, 0.06);
  --glass-blur: 20px;
}
```

### Shadow System (3D depth)
```css
--shadow-sm: 0 1px 3px rgba(0,0,0,0.4);
--shadow-md: 0 4px 12px rgba(0,0,0,0.5), 0 0 30px rgba(255,59,59,0.05);
--shadow-lg: 0 8px 30px rgba(0,0,0,0.6), 0 0 60px rgba(255,59,59,0.08);
--shadow-glow: 0 0 40px rgba(255,59,59,0.15), 0 0 80px rgba(255,59,59,0.05);
--shadow-card: 0 20px 60px rgba(0,0,0,0.6), 
               0 0 0 1px rgba(255,255,255,0.04), 
               inset 0 1px 0 rgba(255,255,255,0.03);
```

### Glassmorphism Utility
```css
.glass {
  background: rgba(12, 12, 26, 0.85);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid rgba(255, 255, 255, 0.06);
}
```

---

## 📋 IMPLEMENTATION PROMPTS — Do these IN ORDER

---

### ═══════════════════════════════════════
### PROMPT 1: Login Page (3D Cyberpunk Terminal)
### ═══════════════════════════════════════

**File to edit:** `admin/src/pages/Login.tsx`  
**Also edit:** `admin/src/App.tsx` (login-wrapper section), `admin/src/App.css` (login styles)

**Current state:** Simple form with 3 CSS-animated glass orbs as background.  
**Target:** Immersive cyberpunk terminal with 3D rotating Predator shield, particle field, and scan-line effect.

**What to build:**

#### A. 3D Background — React Three Fiber
Create a new component `admin/src/components/PredatorLogo3D.tsx`:
- A hexagonal shield made of lines (EdgesGeometry + LineBasicMaterial)
- Rotating slowly on Y-axis (useFrame)
- Inner concentric hexagons with decreasing opacity
- Red emissive glow (#ff3b3b)
- Point light at center
- Optional: small orbiting particles around the shield

```tsx
// Skeleton:
import { Canvas, useFrame } from '@react-three/fiber'
import { Edges, Line } from '@react-three/drei'
import { useRef } from 'react'

function PredatorShield() {
  const meshRef = useRef<THREE.Mesh>(null!)
  useFrame((_, delta) => { meshRef.current.rotation.y += delta * 0.3 })
  // Create hexagonal geometry, render with LineBasicMaterial
  // Add inner hexagons, glow via point light
}
```

#### B. Particle Field — tsparticles
Wrap the login page with:
```tsx
import Particles from '@tsparticles/react'
import { loadSlim } from '@tsparticles/slim'

// Options:
// - particles: color #ff3b3b, number 80, opacity 0.3
// - move: direction top, speed 0.5, outModes out
// - links: color #ff3b3b, opacity 0.1, distance 150
// - background: transparent
```

#### C. Scan Line Effect
CSS-only pseudo-element:
```css
.login-wrapper::after {
  content: '';
  position: absolute; top: -100%; left: 0; right: 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, rgba(255,59,59,0.4), transparent);
  animation: scan-line 5s linear infinite;
}
@keyframes scan-line {
  0% { top: -2px; }
  100% { top: 100%; }
}
```

#### D. Login Card — Glassmorphism + Framer Motion
- `background: rgba(12, 12, 26, 0.85)`, `backdrop-filter: blur(24px)`
- `border: 1px solid rgba(255, 59, 59, 0.15)`
- Shadow with accent glow
- Framer Motion animations:
  - Entry: `initial={{ scale: 0.9, opacity: 0 }}` → `animate={{ scale: 1, opacity: 1 }}` (spring)
  - Error: `animate={{ x: [0, -5, 5, -5, 5, 0] }}` (shake, 0.4s)
  - Loading: button shows spinner + "Authenticating..."
  - Focus: input border glows accent

#### E. Icons
Replace raw SVG with lucide-react:
- Shield icon for logo area
- User icon for username input
- Lock icon for password input

**Complete working code expected.** Keep the existing `LoginProps` interface and `onLogin` callback.

---

### ═══════════════════════════════════════
### PROMPT 2: Global Background + Layout Upgrade
### ═══════════════════════════════════════

**Files to edit:** `admin/src/components/Layout.tsx`, `admin/src/App.css`

**Target:** Add subtle particle/network background to all authenticated pages, upgrade the sidebar with micro-animations.

#### A. ParticleBackground Component
Create `admin/src/components/ParticleBackground.tsx`:
- Lighter than login — only 30 particles, opacity 0.15
- Slow movement (speed 0.3)
- No connecting lines (or very faint)
- Rendered behind main-content but above bg-primary
- Import and use in Layout.tsx

#### B. Sidebar Animations
- Logo: subtle pulse on hover (scale 1.03)
- Nav links: 
  - Hover: slide indicator from left (width grows)
  - Active: left border bar with glow
  - Transition: all 0.2s ease
- User avatar: gradient background, subtle ring
- Logout button: hover → color shifts to red

#### C. Main Content
- Page header: fade-in on route change
- Add subtle top border gradient (accent → transparent) below header

---

### ═══════════════════════════════════════
### PROMPT 3: Dashboard (SOC Command Center)
### ═══════════════════════════════════════

**File to edit:** `admin/src/pages/Dashboard.tsx`  
**Also edit:** `admin/src/App.css` (dashboard-specific styles)

**Current state:** 6 stat cards with emoji, 2 Chart.js charts, 2 tables, WebSocket toasts.  
**Target:** Immersive SOC dashboard with animated stats, Recharts, skeleton loading.

**What to build:**

#### A. AnimatedNumber Component
Create `admin/src/components/AnimatedNumber.tsx`:
```tsx
// Props: { value: number; duration?: number }
// Uses framer-motion useSpring to count up from 0 to value
// Formatted with commas for large numbers
```

#### B. Stat Cards (6 cards in stats-grid)
Replace emoji icons with lucide-react:
1. Pending: `Clock` icon, yellow bg
2. Active tokens: `Key` icon, green bg
3. Used tokens: `UserCheck` icon, red bg
4. Total scans: `Activity` icon, blue bg
5. Threats found: `AlertTriangle` icon, red bg
6. Files scanned: `Search` icon, green bg

Each card:
- Framer Motion stagger entry (delay = index * 80ms)
- Use `<AnimatedNumber>` for the value
- CSS pulse-ring (concentric circle animation)
- Hover: scale(1.02), translateY(-2px), border glow
- WebSocket update: brief opacity pulse on the number

#### C. Charts — Replace Chart.js with Recharts
**Remove:** All Chart.js imports, ChartJS.register, Doughnut, Bar.  
**Add:** Recharts components.

1. **Scan Activity (AreaChart):**
   - Data: `scanStats.byDay`
   - X axis: formatted dates
   - Two areas: "Scans" (blue gradient fill, #3B82F6), "Threats" (red gradient fill, #ff3b3b)
   - Tooltip with glassmorphism style
   - Entry animation: lines grow left-to-right

2. **Mode Distribution (PieChart):**
   - Data: `scanStats.byMode`
   - Donut style (innerRadius 60, outerRadius 90)
   - Colors: full=#22c55e, quick=#3B82F6, dma=#8B5CF6
   - Entry animation: segments appear with rotation
   - Custom label showing percentage

#### D. Tables — Style Upgrade
Recent scans table + Recent requests table:
- Glassmorphism container
- Staggered row entry (fadeIn + slideUp, 50ms delay per row)
- Hover: accent left border appears, bg slightly lighter
- Skeleton loading: 5 pulsing rows matching table column widths
- Empty state: icon + explanatory text

#### E. WebSocket Indicator
Top-right corner:
- Green dot + "Real-time" when connected (breathing animation)
- Red dot + "Disconnected" when not (fast pulse)

#### F. Toast Notifications
Already functional — just upgrade styling:
- Glassmorphism background
- Slide-in from right (Framer Motion)
- Color-coded left border (success=green, warning=yellow, info=blue)

**DO NOT change:** WebSocket connection logic, data fetching, error handling, filter/search logic.

---

### ═══════════════════════════════════════
### PROMPT 4: Pending Requests (Card Layout)
### ═══════════════════════════════════════

**File to edit:** `admin/src/pages/Pending.tsx`

**Current state:** Table with ID, PC name, date, countdown, action buttons.  
**Target:** Card grid with countdown circles and animated approve/reject.

**What to build:**

#### A. CountdownCircle Component
Create `admin/src/components/CountdownCircle.tsx`:
```tsx
// Props: { expiresAt: string }
// SVG circle that depletes as time runs out
// stroke-dasharray animated
// Colors: green (>1hr) → yellow (<1hr) → red (<5min) → grey (expired)
// Pulse animation when <5min
```

#### B. Card Grid Layout
Replace `<table>` with responsive card grid:
- 1 column mobile, 2 tablet, 3 desktop
- Each card: avatar + name + relative time + countdown + action buttons

#### C. Card Animations
- Entry: stagger fade-in + slide-up
- Approve: card exits right (x: 200, opacity 0) with green glow
- Reject: shake then exits left (x: -200, opacity 0) with red glow
- Use `<AnimatePresence>` for exit animations

#### D. Empty State
- Large `CheckCircle` icon (green)
- "Все запросы обработаны"

**DO NOT change:** Countdown timer logic, API calls, approve/reject handlers, toast logic.

---

### ═══════════════════════════════════════
### PROMPT 5: Tokens (Terminal Style)
### ═══════════════════════════════════════

**File to edit:** `admin/src/pages/Tokens.tsx`

**Current state:** Health gauge bar + generate form + token table.  
**Target:** Speedometer gauge + typewriter token reveal + matrix background.

**What to build:**

#### A. Speedometer Gauge
Replace the flat progress bar with an SVG arc gauge:
- Semi-circular arc (0-180 degrees)
- Fill animation on load
- Color: green (>5 active) → yellow (2-5) → red (<2)
- Center: large number (active count)

#### B. TypewriterText Component
Create `admin/src/components/TypewriterText.tsx`:
```tsx
// Props: { text: string; speed?: number }
// Reveals text character by character
// Used for generated token codes
```

#### C. Token Generation
- Button has internal progress bar animation during generation
- Generated tokens appear with typewriter effect
- "Copy" button toggles icon (Copy → Check) with animation
- Auto-hide after 8s with countdown progress bar

#### D. Matrix Rain Background (for this page only)
- Subtle green-on-black falling characters
- Low opacity (0.03) so it doesn't distract
- Canvas or CSS-based

**DO NOT change:** Token generation logic, API calls, state management, copy-to-clipboard logic.

---

### ═══════════════════════════════════════
### PROMPT 6: History Timeline + Threat Database
### ═══════════════════════════════════════

**Files to edit:** `admin/src/pages/History.tsx`, `admin/src/pages/SuspiciousHashes.tsx`

#### A. History — Vertical Timeline
Replace the events table with an interactive timeline:
- Vertical line down the left side
- Event nodes (circles) with icons: Key (token) or User (request)
- Color: blue=token, green=approved, red=rejected
- Entry animation: nodes appear bottom-up (stagger)
- Line "grows" (height: 0 → 100%, transition 2s)
- Search bar with animated expand on focus
- Pill filter buttons with sliding active indicator

#### B. Suspicious Hashes — Glass Table + DNA Background
Upgrade the 4-tab table:
- Segmented control tabs (iOS style) with sliding indicator
- Tab content: crossfade transition
- Glassmorphism table
- Confirm: confetti animation + glow
- Reject: red flash + fade out

**Optionally add:** DNA-like double helix background (Three.js) — two intertwined spirals made of hex characters, slowly rotating. This is complex — skip if too time-consuming.

**DO NOT change:** Tab switching logic, API calls, approve/reject/confirm handlers.

---

## ⚡ CRITICAL RULES

1. **DO NOT modify `api.ts`.** All API functions are correct.
2. **DO NOT change page-level state logic.** Keep `useState`, `useEffect`, handlers as-is.
3. **DO change rendering.** Replace div soup with proper components.
4. **Keep all existing CSS class names** that are referenced in JS (e.g., `.layout`, `.sidebar`, `.main-content`, `.page-header`). You can change their styles, but don't delete them.
5. **New components go in `admin/src/components/`.** Named exports.
6. **Use TypeScript.** All props must be typed.
7. **Test after each prompt.** Run `npx tsc --noEmit` from `admin/` directory.
8. **Work in order:** Prompt 1 → 2 → 3 → 4 → 5 → 6. Each builds on the previous.
9. **Use Framer Motion for ALL animations.** Not CSS transitions. `motion.div`, `AnimatePresence`, `useSpring`.
10. **Use lucide-react for ALL icons.** No emoji. No raw SVG.

---

## 🚀 Getting Started

1. Install dependencies (listed at top)
2. Start with Prompt 1 (Login Page) — it's the most impactful
3. After each prompt, verify with `npx tsc --noEmit`
4. Continue through all 6 prompts

**The existing code works. Make it beautiful.**
