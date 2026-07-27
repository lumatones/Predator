# Dashboard Page — Design Override

> **Overrides:** MASTER.md §7 (Components), §12 (Performance)
> **Parent:** design-system/predator/MASTER.md

---

## Layout

```
┌─────────────────────────────────────────────────────┐
│ [← Back]  System Monitor        [Server ●] Online   │
├─────────────────────────────────────────────────────┤
│  ┌──────┐    ┌──────┐    ┌──────┐                  │
│  │ 47%  │    │ 38%  │    │ 52°C │                  │
│  │ CPU  │    │ MEM  │    │ TEMP │                  │
│  │8 cores│    │6/16GB│    │      │                  │
│  └──────┘    └──────┘    └──────┘                  │
│                                                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ Uptime   │ │ System   │ │ Hostname │            │
│  │ 2h 15m   │ │ win32 x64│ │ DEV-PC   │            │
│  └──────────┘ └──────────┘ └──────────┘            │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │ Processes (10)              [Filter...]      │    │
│  │ PID   Process          Memory               │    │
│  │ 4821  Predator.exe     89 MB                │    │
│  │ 1234  chrome.exe       452 MB               │    │
│  │ 5678  Discord.exe      234 MB               │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

## Spacing Overrides

| Element | MASTER Default | Dashboard Override | Reason |
|---------|---------------|-------------------|--------|
| Gauges grid | `space-4` (16px) | `space-4` | 3-column, centered |
| Info cards gap | `space-3` (12px) | `space-3` | Compact metadata |
| Process list | `space-2` (8px) | `space-2` | Dense table |

## Color Overrides

| Element | MASTER Default | Dashboard Override |
|---------|---------------|-------------------|
| CPU gauge | `--accent-red` | `#ff4444` (red) |
| Memory gauge | `--accent-red` | `#3B82F6` (blue) |
| Temp gauge | `--color-success` | Green <70°C, Yellow ≥70°C |

## Animation Overrides

| Element | MASTER Default | Dashboard Override |
|---------|---------------|-------------------|
| Gauge fill | Instant | `stroke-dashoffset 0.5s ease` |
| Process row enter | `staggerChildren: 0.02` | Sequential from top |
| Server status dot | `breathe 2.5s` (online), `fast-pulse 1s` (offline) | Pulse animation |

## Performance Notes

- `Gauge` — `React.memo()` (pure: only value, label, color props)
- `ProcessList` — limit to top 20 by memory; filter client-side
- Server status: poll IPC, not HTTP (uses `onSystemUpdate`)
- Skeleton loading: `SkeletonGauge`, `SkeletonCard`, `SkeletonTable`
