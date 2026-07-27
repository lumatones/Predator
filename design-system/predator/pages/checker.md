# Checker Page — Design Override

> **Overrides:** MASTER.md §7 (Components), §14 (View Transitions)
> **Parent:** design-system/predator/MASTER.md

---

## Layout: Results Split

```
┌─────────────────────────────────────────────────────┐
│ [← Back]  System Scan                    ● scanning  │
├─────────────────────────────────────────────────────┤
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ 🛡 Full  │ │ ⊕ Quick  │ │ 🔌 DMA  │ │ 🧹 Clean │ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
├─────────────────────────────────────────────────────┤
│ ◉ Search: ____________________                      │
│ ┌───────────────────────┐ ┌─────────────────────────┐│
│ │ ▼ HIGH RISK (4)       │ │ 📁 nightfall.dll        ││
│ │   ☠ Cheat Engine      │ │   Path: ~/Downloads/... ││
│ │   ☠ menu.dll          │ │   Type: File · High     ││
│ │   ☠ eulen.asi         │ │   Matches:              ││
│ │   ☠ Xilinx FPGA       │ │   [injector] [menu]     ││
│ │                       │ │                         ││
│ │ ▶ MEDIUM RISK (2)     │ │                         ││
│ │ ▶ LOW RISK (1)        │ │                         ││
│ └───────────────────────┘ └─────────────────────────┘ │
├─────────────────────────────────────────────────────┤
│ [Clear] [HTML Export] [MD] [PDF] [TG]              │
└─────────────────────────────────────────────────────┘
```

## Spacing Overrides

| Element | MASTER Default | Checker Override | Reason |
|---------|---------------|------------------|--------|
| Tabs gap | `space-2` (8px) | `space-2` | Keep compact |
| Tab padding | `space-3` (12px) | `space-2` (8px) | 4 tabs need to fit |
| Results list | `space-2` (8px) | `space-1` (4px) | Density for 20+ items |
| Detail panel | `space-4` (16px) | `space-4` | Readability |

## Color Overrides

| Element | MASTER Default | Checker Override | Reason |
|---------|---------------|------------------|--------|
| Tab active border | `--border-active` (red) | Tab-specific color | Each tab has unique accent |
| Full scan tab accent | `--accent-red` | `#22c55e` (green) | "Healthy" full scan |
| Quick scan tab accent | — | `#F59E0B` (yellow) | Warning speed |
| DMA scan tab accent | — | `#8B5CF6` (purple) | Hardware color |
| Cleaner scan tab accent | — | `#EF4444` (red) | Destruction red |

## Animation Overrides

| Element | MASTER Default | Checker Override |
|---------|---------------|------------------|
| Tab switch | `opacity cross-fade 150ms` | `exit → enter` staggered at 150ms |
| Result group expand | `height auto` | `AnimatePresence + motion.div` |
| Result row enter | `opacity 0→1` | `staggerChildren: 0.03` |
| Scan complete → results | `opacity cross-fade` | Terminal fades out, results slide up |

## View Transitions

```tsx
// Tab switching: no directional animation (lateral, not hierarchical)
<ViewTransition default="none">
  <TabContent key={activeTab} />
</ViewTransition>

// Results list: per-item identity for reorder
{results.map(r => (
  <ViewTransition key={r.path}>
    <ResultRow result={r} />
  </ViewTransition>
))}
```

## Empty States

### Idle (no scan run)
```
         ┌──────────────┐
         │  PredatorLogo │  ← 3D shield, ambient glow
         │    3D (80px)  │
         └──────────────┘
         
         Full Scan
         All modules: files, processes, registry,
         network, DMA, browser, heuristics
         
         [ 🔍 Start Scan ]   ← Crosshair cursor
```

### Clean (no threats)
```
         ┌──────────────┐
         │  PredatorLogo │
         │   3D + ✓      │
         └──────────────┘
         
         ✅ System Clean     ← Green check icon
         Scanned modules:
         [Files] [Processes] [Registry]
         [DMA] [Network] [Signatures]
         [Behavior] [Browser] [Entropy]
         
         2,487 files scanned · Time: 3.2 sec
```

## Performance Notes

- `ResultsList` — virtualize at >50 items
- `ResultRow` — `React.memo()` (pure component)
- `ScanTerminal` — `React.lazy()` (heavy: MatrixRain + animations)
- `FileDetailModal` — `React.lazy()` (rarely opened)
- `PredatorLogo3D` — `React.lazy()` (Three.js bundle ~150KB)
- Tab content: preserve with `display: none` instead of unmounting (avoid re-fetch)
