/**
 * Predator — Statistics store
 * Persists scan results in localStorage for the statistics dashboard.
 */

import type { ScanResult } from '../types/electron'

const STORAGE_KEY = 'predator_scan_history'

export interface StoredScan {
  id: string
  timestamp: number
  mode: string
  totalScanned: number
  suspiciousFiles: number
  highRiskCount: number
  scanTimeMs: number
  results: ScanResult[]
}

// ── Save a completed scan ──

export function saveScan(
  mode: string,
  totalScanned: number,
  suspiciousFiles: number,
  highRiskCount: number,
  scanTimeMs: number,
  results: ScanResult[],
) {
  const history = loadHistory()
  history.push({
    id: `scan_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    timestamp: Date.now(),
    mode,
    totalScanned,
    suspiciousFiles,
    highRiskCount,
    scanTimeMs,
    results,
  })
  // Keep last 100 scans max
  if (history.length > 100) {
    history.splice(0, history.length - 100)
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history))
}

// ── Load full history ──

export function loadHistory(): StoredScan[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    return JSON.parse(raw) as StoredScan[]
  } catch {
    return []
  }
}

// ── Clear all history ──

export function clearHistory() {
  localStorage.removeItem(STORAGE_KEY)
}

// ── Aggregated stats ──

export interface AggregatedStats {
  totalScans: number
  totalThreats: number
  avgScanTimeMs: number
  threatsByDay: { date: string; count: number }[]
  topCheatTypes: { name: string; count: number }[]
  hotDirectories: { path: string; count: number; risk: string }[]
  scanCountByMode: { mode: string; count: number }[]
}

export function aggregateStats(): AggregatedStats {
  const history = loadHistory()
  if (history.length === 0) {
    return generateDemoStats()
  }

  const totalScans = history.length
  const totalThreats = history.reduce((s, scan) => s + scan.suspiciousFiles, 0)
  const avgScanTimeMs = Math.round(history.reduce((s, scan) => s + scan.scanTimeMs, 0) / totalScans)

  // Threats by day (last 14 days)
  const dayMap = new Map<string, number>()
  const now = new Date()
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now)
    d.setDate(d.getDate() - i)
    const key = d.toISOString().slice(0, 10)
    dayMap.set(key, 0)
  }
  for (const scan of history) {
    const key = new Date(scan.timestamp).toISOString().slice(0, 10)
    if (dayMap.has(key)) {
      dayMap.set(key, (dayMap.get(key) || 0) + scan.suspiciousFiles)
    }
  }
  const threatsByDay = Array.from(dayMap.entries()).map(([date, count]) => ({ date, count }))

  // Top cheat types (from matches)
  const cheatTypeMap = new Map<string, number>()
  for (const scan of history) {
    for (const result of scan.results) {
      for (const match of result.matches) {
        const type = match.includes(':') ? match.split(':')[0] : 'other'
        const label = match.includes(':') ? match.split(':')[1] || match : match
        cheatTypeMap.set(label, (cheatTypeMap.get(label) || 0) + 1)
      }
    }
  }
  const topCheatTypes = Array.from(cheatTypeMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }))

  // Hot directories
  const dirMap = new Map<string, { count: number; risk: string }>()
  for (const scan of history) {
    for (const result of scan.results) {
      const dir = result.path.substring(0, result.path.lastIndexOf('\\'))
      if (dir) {
        const existing = dirMap.get(dir)
        if (existing) {
          existing.count++
          if (result.risk === 'high') existing.risk = 'high'
          else if (result.risk === 'medium' && existing.risk !== 'high') existing.risk = 'medium'
        } else {
          dirMap.set(dir, { count: 1, risk: result.risk })
        }
      }
    }
  }
  const hotDirectories = Array.from(dirMap.entries())
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 8)
    .map(([path, { count, risk }]) => ({ path, count, risk }))

  // Scan count by mode
  const modeMap = new Map<string, number>()
  for (const scan of history) {
    modeMap.set(scan.mode, (modeMap.get(scan.mode) || 0) + 1)
  }
  const scanCountByMode = Array.from(modeMap.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([mode, count]) => ({ mode, count }))

  return { totalScans, totalThreats, avgScanTimeMs, threatsByDay, topCheatTypes, hotDirectories, scanCountByMode }
}

// ── Demo data for first-time users / dev mode ──

function generateDemoStats(): AggregatedStats {
  const now = Date.now()
  const demoHistory: StoredScan[] = [
    {
      id: 'demo_1', timestamp: now - 86400000 * 6, mode: 'files',
      totalScanned: 340, suspiciousFiles: 3, highRiskCount: 2, scanTimeMs: 2800,
      results: [
        { path: '~/Downloads/cheat_loader.js', fileName: 'cheat_loader.js', type: 'file', risk: 'high', matches: ['filename:cheat', 'content:inject'], size: 15234, modifiedAt: '' },
        { path: '~/Desktop/menu.dll', fileName: 'menu.dll', type: 'file', risk: 'high', matches: ['pattern:mod menu'], size: 245760, modifiedAt: '' },
      ],
    },
    {
      id: 'demo_2', timestamp: now - 86400000 * 4, mode: 'processes',
      totalScanned: 45, suspiciousFiles: 1, highRiskCount: 1, scanTimeMs: 1800,
      results: [
        { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine'], size: 0, modifiedAt: '' },
      ],
    },
    {
      id: 'demo_3', timestamp: now - 86400000 * 2, mode: 'cheats',
      totalScanned: 12, suspiciousFiles: 4, highRiskCount: 2, scanTimeMs: 3500,
      results: [
        { path: '~/Downloads/Nightfall', fileName: 'Nightfall Loader', type: 'file', risk: 'high', matches: ['cheat:nightfall', 'filename:nightfall'], size: 0, modifiedAt: '' },
        { path: 'HKCU\\...\\Uninstall\\Nightfall', fileName: 'Registry: Nightfall', type: 'registry', risk: 'high', matches: ['registry:nightfall installed'], size: 0, modifiedAt: '' },
        { path: '~/Documents/Cheats/', fileName: 'mod_menu.lua', type: 'file', risk: 'medium', matches: ['lua:mod menu'], size: 8912, modifiedAt: '' },
        { path: 'Browser History', fileName: 'Chrome History', type: 'browser', risk: 'medium', matches: ['browser:nightfall'], size: 4096, modifiedAt: '' },
      ],
    },
    {
      id: 'demo_4', timestamp: now - 86400000 * 1, mode: 'dma',
      totalScanned: 8, suspiciousFiles: 2, highRiskCount: 2, scanTimeMs: 2100,
      results: [
        { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx (VEN_10ee)'], size: 0, modifiedAt: '' },
        { path: 'System32/drivers/', fileName: 'leeched.sys', type: 'software', risk: 'high', matches: ['dma-driver:leeched.sys'], size: 0, modifiedAt: '' },
      ],
    },
    {
      id: 'demo_5', timestamp: now - 3600000 * 3, mode: 'extended',
      totalScanned: 1847, suspiciousFiles: 7, highRiskCount: 4, scanTimeMs: 12400,
      results: [
        { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine'], size: 0, modifiedAt: '' },
        { path: '~/Downloads/cheat_loader.js', fileName: 'cheat_loader.js', type: 'file', risk: 'high', matches: ['filename:cheat'], size: 15234, modifiedAt: '' },
        { path: '~/AppData/Local/FiveM/mods/', fileName: 'eulen.asi', type: 'file', risk: 'high', matches: ['file:eulen'], size: 245760, modifiedAt: '' },
        { path: 'HKCU\\...\\Uninstall\\Nightfall', fileName: 'Registry: Nightfall', type: 'registry', risk: 'high', matches: ['registry:nightfall'], size: 0, modifiedAt: '' },
        { path: '~/Documents/Cheats/', fileName: 'mod_menu.lua', type: 'file', risk: 'medium', matches: ['lua:mod menu'], size: 8912, modifiedAt: '' },
        { path: 'C:\\Windows\\Prefetch\\DMA_TOOL.EXE-*.pf', fileName: 'DMA_TOOL.EXE-*.pf', type: 'file', risk: 'medium', matches: ['prefetch:dma'], size: 0, modifiedAt: '' },
        { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx'], size: 0, modifiedAt: '' },
      ],
    },
  ]

  // Re-hydrate into aggregateStats format
  const totalScans = demoHistory.length
  const totalThreats = demoHistory.reduce((s, scan) => s + scan.suspiciousFiles, 0)
  const avgScanTimeMs = Math.round(demoHistory.reduce((s, scan) => s + scan.scanTimeMs, 0) / totalScans)

  const dayMap = new Map<string, number>()
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now - 86400000 * (13 - i))
    dayMap.set(d.toISOString().slice(0, 10), 0)
  }
  for (const scan of demoHistory) {
    const key = new Date(scan.timestamp).toISOString().slice(0, 10)
    dayMap.set(key, (dayMap.get(key) || 0) + scan.suspiciousFiles)
  }
  const threatsByDay = Array.from(dayMap.entries()).map(([date, count]) => ({ date, count }))

  return {
    totalScans,
    totalThreats,
    avgScanTimeMs,
    threatsByDay,
    topCheatTypes: [
      { name: 'cheat', count: 4 },
      { name: 'dma', count: 3 },
      { name: 'process', count: 2 },
      { name: 'file', count: 2 },
      { name: 'registry', count: 2 },
    ],
    hotDirectories: [
      { path: '~/Downloads', count: 3, risk: 'high' },
      { path: '~/AppData/Local/FiveM/mods', count: 2, risk: 'high' },
      { path: 'HKCU\\...\\Uninstall', count: 2, risk: 'high' },
      { path: '~/Documents/Cheats', count: 2, risk: 'medium' },
      { path: '~/Desktop', count: 1, risk: 'high' },
      { path: 'C:\\Windows\\Prefetch', count: 1, risk: 'medium' },
      { path: 'PCI Bus', count: 1, risk: 'high' },
      { path: 'Browser History', count: 1, risk: 'medium' },
    ],
    scanCountByMode: [
      { mode: 'extended', count: 1 },
      { mode: 'files', count: 1 },
      { mode: 'processes', count: 1 },
      { mode: 'cheats', count: 1 },
      { mode: 'dma', count: 1 },
    ],
  }
}
