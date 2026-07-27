# Admin Dashboard — Design Override

> **Overrides:** MASTER.md §7 (Components), §12 (Performance)
> **Parent:** design-system/predator/MASTER.md

---

## Layout: Sidebar + Content

```
┌──────────┬──────────────────────────────────────────┐
│ PREDATOR │  Dashboard                    [WS ●] [↻] │
│ v1.0     │                                         │
│──────────│  ┌─────────┐ ┌─────────┐ ┌─────────┐    │
│ 🏠 Home  │  │ Scans   │ │ Tokens  │ │ Pending │    │
│ 📊 Dash  │  │ 1,247   │ │  89     │ │   3     │    │
│ 📋 Pend  │  └─────────┘ └─────────┘ └─────────┘    │
│ 🔑 Tokens│                                         │
│ 📜 Hist  │  ┌──────────────────────────────────┐    │
│ 🔍 Hashes│  │ Recent Scans                 [>] │    │
│ ✅ Safe  │  │ user_123  full   3 threats  2m   │    │
│──────────│  │ user_456  quick  0 threats  5m   │    │
│ 👤 Admin │  │ user_789  dma    1 threat   8m   │    │
│ [Logout] │  └──────────────────────────────────┘    │
└──────────┴──────────────────────────────────────────┘
```

## Spacing Overrides

| Element | MASTER Default | Admin Override | Reason |
|---------|---------------|----------------|--------|
| Sidebar width | — | `240px` (fixed) | Consistent navigation |
| Main padding | `space-8` (32px) | `space-8` | Breathable |
| Stat cards gap | `space-4` (16px) | `space-4` | Grid layout |
| Table cells | `space-3` (12px) | `space-3` | Compact but readable |

## Color Overrides

| Element | MASTER Default | Admin Override |
|---------|---------------|----------------|
| Sidebar bg | `--bg-secondary` | `--bg-secondary` (same) |
| Active nav | `--accent-dim` bg + red text | Red pill bg + white text |
| Nav hover | `--bg-hover` | `rgba(255,255,255,0.04)` |
| Stat card border | `--border-color` | `--border-color` (same) |

## Animation Overrides

| Element | MASTER Default | Admin Override |
|---------|---------------|----------------|
| Page enter | `opacity + translateY(8px)`, 300ms | `pageHeaderIn` keyframe |
| Stat card hover | `translateY(-1px)` + border glow | `pulse-ring` on `::before` |
| Nav link active | Instant | Left border slide + bg fade |
| Toast enter | `slide + fade`, 200ms | `glass-toast` with left glow bar |

## Page-Specific Patterns

### Login Page
```
         ┌────────────────────┐
         │   Particle BG       │
         │   (density: 80)     │
         │                    │
         │   ┌──────────────┐ │
         │   │  PREDATOR    │ │
         │   │  Admin Panel │ │
         │   │              │ │
         │   │ [Username]   │ │
         │   │ [Password]   │ │
         │   │              │ │
         │   │ [Sign In →]  │ │
         │   └──────────────┘ │
         │   scan-line ═══════│
         └────────────────────┘
```
- Particle density: 80 (higher = more dramatic login)
- Card: glass morphism, `backdrop-filter: blur(24px)`
- Scan line: `8s linear infinite`
- Red gradient on logo + button

### Pending Requests
```
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ 👤 user_123 │ │ 👤 user_456 │ │ 👤 user_789 │
│ #42          │ │ #43          │ │ #44          │
│ ⏱ 03:24      │ │ ⏱ 12:08      │ │ ⏱ —          │
│ Created:     │ │ Created:     │ │ Created:     │
│ 14:30        │ │ 08:15        │ │ yesterday    │
│              │ │              │ │              │
│ [Approve]    │ │ [Approve]    │ │ [Approve]    │
│ [Reject]     │ │ [Reject]     │ │ [Reject]     │
└─────────────┘ └─────────────┘ └─────────────┘
```
- 3-column grid → 2-col at 1024px → 1-col at 640px
- Countdown circle with pulse animation on expiry < 5 min
- Approve: green glow flash on card
- Reject: red flash on card

### Tokens Page
```
┌─────────────────────────────────────┐
│ Generate Tokens                     │
│ Count: [3] [Generate]               │
│                                     │
│ ┌─────────────────────────────────┐ │
│ │ ✓ 3 tokens generated            │ │
│ │                                 │ │
│ │ XXXX-XXXX-XXXX-XXXX  [Copy]     │ │
│ │ YYYY-YYYY-YYYY-YYYY  [Copy]     │ │
│ │ ZZZZ-ZZZZ-ZZZZ-ZZZZ  [Copy]     │ │
│ │                                 │ │
│ │ Auto-delete in 5:00 ████░░░░    │ │
│ └─────────────────────────────────┘ │
│                                     │
│ ┌─────────────────────────────────┐ │
│ │ Token History               [>] │ │
│ │ ID  │ Code      │ Used By │ ... │ │
│ │ 12  │ XXXX-XXXX │ user_5  │ ... │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```
- Typewriter effect on generated tokens
- 5-minute countdown bar with green gradient
- Copy button with "✓ Copied!" feedback

### Suspicious Hashes
```
┌─────────────────────────────────────┐
│ [Pending] [Confirmed] [False Pos.]  │
│                                     │
│ ┌─────────────────────────────────┐ │
│ │ SHA256            │ File │ ... │ │
│ │ a1b2c3...e4f5     │ .dll │ ... │ │
│ │ 3 users · 4.2 MB  │      │     │ │
│ │ [Confirm] [Reject]│      │     │ │
│ └─────────────────────────────────┘ │
└─────────────────────────────────────┘
```
- Segmented tab control (pending/confirmed/false positive)
- Hash row: monospace SHA256, file name, size, user count
- Confirm animation: green glow → row slides out
- Reject animation: red flash → row slides out

## Performance Notes

- `ParticleBackground` — `React.memo()` (pure, no props changes)
- Table rows >50: virtualize or use `content-visibility: auto`
- `PendingGrid` — `React.memo()` on each `PendingCard`
- Page transitions: `addTransitionType('nav-forward')` for hierarchical nav (list→detail)
