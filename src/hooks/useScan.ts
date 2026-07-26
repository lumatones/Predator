import { useState, useRef, useCallback, useMemo, useEffect } from 'react'
import type { ScanResult, ScanProgress, ScanResponse, ScanMode } from '../types/electron'
import { submitScan } from '../api'

const tabCache = new Map<ScanMode, { results: ScanResult[]; summary: ScanResponse['summary'] }>()

interface UseScanReturn {
  activeTab: ScanMode
  setActiveTab: (tab: ScanMode) => void
  phase: 'idle' | 'scanning' | 'done'
  progress: ScanProgress | null
  results: ScanResult[]
  filteredResults: ScanResult[]
  summary: ScanResponse['summary'] | null
  error: string
  searchQuery: string
  setSearchQuery: (q: string) => void
  tabCounts: Map<ScanMode, number>
  handleStartScan: () => Promise<void>
  handleClear: () => void
  handleTabChange: (tab: ScanMode) => void
}

function mockScan(tab: ScanMode): { results: ScanResult[]; scanned: number } {
  const now = new Date().toISOString()
  const base: Record<ScanMode, { results: ScanResult[]; scanned: number }> = {
    full: { scanned: 2487, results: [
      { path: '~/Desktop/menu.dll', fileName: '[Score:87] menu.dll', type: 'file', risk: 'high', matches: ['YARA [bypass_strings]', 'High entropy (7.82)'], size: 245760, modifiedAt: now },
      { path: 'HKCU\\...\\Run', fileName: 'Registry [injector]: inject', type: 'registry', risk: 'high', matches: ['registry-deep:inject'], size: 0, modifiedAt: now },
    ]},
    quick: { scanned: 45, results: [
      { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine'], size: 0, modifiedAt: now },
    ]},
    dma: { scanned: 8, results: [
      { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx', 'FPGA detected'], size: 0, modifiedAt: now },
    ]},
    cleaner: { scanned: 42, results: [
      { path: 'C:\\$Extend\\$UsnJrnl', fileName: 'USN Journal Deleted', type: 'system', risk: 'high', matches: ['usn-journal:deleted'], size: 0, modifiedAt: now },
    ]},
  }
  return base[tab]
}

export function useScan(tokenId: number | null): UseScanReturn {
  const [activeTab, setActiveTab] = useState<ScanMode>('full')
  const cachedEntry = tabCache.get(activeTab)
  const [phase, setPhase] = useState<'idle' | 'scanning' | 'done'>(cachedEntry ? 'done' : 'idle')
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [results, setResults] = useState<ScanResult[]>(cachedEntry?.results ?? [])
  const [summary, setSummary] = useState<ScanResponse['summary'] | null>(cachedEntry?.summary ?? null)
  const [error, setError] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [tabCounts, setTabCounts] = useState<Map<ScanMode, number>>(new Map())
  const scanRef = useRef(false)

  useEffect(() => {
    return () => { scanRef.current = false }
  }, [])

  const filteredResults = useMemo(() => {
    const q = searchQuery.toLowerCase().trim()
    if (!q) return results
    return results.filter(r =>
      r.fileName.toLowerCase().includes(q) ||
      r.path.toLowerCase().includes(q) ||
      r.matches.some(m => m.toLowerCase().includes(q))
    )
  }, [results, searchQuery])

  const handleStartScan = useCallback(async () => {
    const api = window.electronAPI
    if (scanRef.current) return
    scanRef.current = true
    tabCache.delete(activeTab)
    setPhase('scanning'); setError(''); setResults([]); setSummary(null); setProgress(null)

    if (!api?.startScan) {
      for (let i = 0; i <= 100; i += 10) {
        if (!scanRef.current) return
        await new Promise(r => setTimeout(r, 150))
        setProgress({ phase: i < 80 ? 'scanning' : i < 100 ? 'analyzing' : 'done', currentDir: 'Scanning...', filesFound: Math.floor(i / 20), filesScanned: Math.floor(i * 3), totalDirs: 5, dirsDone: Math.min(Math.floor(i / 20), 5) })
      }
      if (!scanRef.current) return
      const mock = mockScan(activeTab)
      const mockSummary = { totalScanned: mock.scanned, suspiciousFiles: mock.results.length, highRiskCount: mock.results.filter(r => r.risk === 'high').length, scanTimeMs: 1500 }
      setResults(mock.results); setSummary(mockSummary)
      tabCache.set(activeTab, { results: mock.results, summary: mockSummary })
      setTabCounts(prev => { const n = new Map(prev); n.set(activeTab, mock.results.length); return n })
      setPhase('done'); scanRef.current = false
      submitToServer(activeTab, mockSummary, mock.results, tokenId)
      return
    }

    const unsub = api.onScanProgress(data => { if (scanRef.current) setProgress({ ...data }) })
    try {
      const response = await api.startScan(activeTab, tokenId ?? undefined)
      if (scanRef.current) {
        setResults(response.results); setSummary(response.summary)
        tabCache.set(activeTab, { results: response.results, summary: response.summary })
        setTabCounts(prev => { const n = new Map(prev); n.set(activeTab, response.results.length); return n })
        setPhase('done')
        submitToServer(activeTab, response.summary, response.results, tokenId)
      }
    } catch (err) {
      if (scanRef.current) { setError(err instanceof Error ? err.message : 'Scan error'); setPhase('idle') }
    } finally { scanRef.current = false; if (typeof unsub === 'function') unsub() }
  }, [activeTab, tokenId])

  const handleClear = useCallback(() => {
    tabCache.clear(); setResults([]); setSummary(null); setProgress(null); setPhase('idle'); scanRef.current = false; setSearchQuery('')
  }, [])

  const handleTabChange = useCallback((tab: ScanMode) => {
    if (tab === activeTab) return
    scanRef.current = false
    if (phase === 'done' && summary) tabCache.set(activeTab, { results, summary })
    const cached = tabCache.get(tab)
    setActiveTab(tab)
    if (cached) { setResults(cached.results); setSummary(cached.summary); setPhase('done') }
    else { setPhase('idle'); setResults([]); setSummary(null) }
    setProgress(null); setError(''); setSearchQuery('')
  }, [activeTab, phase, results, summary])

  return { activeTab, setActiveTab, phase, progress, results, filteredResults, summary, error, searchQuery, setSearchQuery, tabCounts, handleStartScan, handleClear, handleTabChange }
}

async function submitToServer(mode: string, summary: ScanResponse['summary'], results: ScanResult[], tokenId: number | null) {
  try {
    let pcName = 'unknown'
    try { if (window.electronAPI?.getPCName) pcName = await window.electronAPI.getPCName() } catch { /* ignore */ }
    await submitScan({
      token_id: tokenId ?? undefined, pc_username: pcName, mode,
      total_scanned: summary.totalScanned, suspicious_files: summary.suspiciousFiles,
      high_risk_count: summary.highRiskCount, scan_time_ms: summary.scanTimeMs,
      results: results.slice(0, 50).map(r => ({ path: r.path, fileName: r.fileName, type: r.type, risk: r.risk, matches: r.matches.slice(0, 5) })),
    })
  } catch { /* ignore */ }
}
