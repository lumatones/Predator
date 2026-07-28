import { useState, useRef, useCallback, useEffect, useMemo } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import type { ScanResult, ScanProgress, ScanResponse, ScanMode } from '../types/electron'

// ── Per-tab cache ──
interface TabCacheEntry {
  results: ScanResult[]
  summary: ScanResponse['summary']
}
const tabCache = new Map<ScanMode, TabCacheEntry>()
import { exportHtml, exportJson, exportMarkdown, exportPdf, sendToTelegram } from '../utils/export-report'
import { submitScan } from '../api'
import { groupResults } from '../utils/result-grouper'
import { Magnetic } from '../components/ui/Magnetic'
import { Button } from '../components/ui/Button'
import PredatorLogo3D from '../components/ui/PredatorLogo3D'
import { ScanTerminal } from '../components/ui/ScanTerminal'
import { FileDetailModal } from '../components/ui/FileDetailModal'
import { ThreatMap } from '../components/ui/ThreatMap'
import { ApcDashboard } from '../components/ui/ApcDashboard'
import { CompactScanOverlay } from '../components/ui/CompactScanOverlay'
import { ScanningDots } from '../components/ui/AnimatedIcons'
import { useSound } from '../hooks/useSound'
import {
  IconFolder,
  IconGear,
  IconCrosshair,
  IconUSB,
  IconShield,
  IconGlobe,
  IconRegistry,
  IconMonitor,
  IconLock,
  IconDNA,
  IconChart,
} from '../icons'

// Import the eraser/broom icon for cleaner scan
const IconEraser = ({ size = 24, color = '#fff' }: { size?: number; color?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 20H7L3 16c-.8-.8-.8-2 0-2.8L14.6 1.6c.8-.8 2-.8 2.8 0L21 5.2c.8.8.8 2 0 2.8L12 17" />
    <line x1="6" y1="20" x2="10" y2="20" />
    <line x1="18" y1="8" x2="14" y2="12" />
  </svg>
)

interface CheckerProps {
  lang: 'ru' | 'en'
  tokenId: number | null
  onBack: () => void
  accent: string
  light: string
  dark: string
}

const T: Record<string, Record<string, string>> = {
  ru: {
    title: 'Сканирование системы',
    startBtn: 'Начать проверку',
    scanning: 'Сканирование...',
    analyzing: 'Анализ результатов...',
    done: 'Проверка завершена',
    found: 'Найдено',
    high: 'Высокий', medium: 'Средний', low: 'Низкий',
    risk: 'Риск',
    noThreats: 'Подозрительных элементов не обнаружено',
    threatsFound: 'обнаружено',
    filesScanned: 'просканировано',
    time: 'Время', sec: 'сек',
    clear: 'Очистить',
    file: 'Файл', matches: 'Совпадения', path: 'Путь',
    scanAgain: 'Проверить снова',
    browser: 'История браузера',
    tabFull: 'Полное сканирование', tabFullDesc: 'Все модули: файлы, процессы, реестр, сеть, DMA, браузер, эвристика',
    tabQuick: 'Быстрая проверка', tabQuickDesc: 'Процессы, Prefetch, реестр и история браузера — без обхода диска',
    tabDma: 'DMA-устройства', tabDmaDesc: 'Обнаружение DMA-карт и FPGA-устройств',
    tabCleaner: 'Детект чистки ПК', tabCleanerDesc: 'Следы очистки системы, USN-журнал, таймстомпинг, ShellBags, HWID',
    riskHigh: 'Высокий риск', riskMedium: 'Средний риск', riskLow: 'Низкий риск',
    processRunning: 'Запущен', processRecent: 'Недавние', processPrefetch: 'Prefetch', processMem: 'Память',
    cheatFiles: 'Файлы', cheatBrowser: 'История', cheatRegistry: 'Реестр',
    dmaPci: 'PCI-устройства', dmaSoftware: 'ПО', dmaDriver: 'Драйверы', dmaRegistry: 'Реестр',
    typeFile: 'Файл', typeBrowser: 'Браузер', typeProcess: 'Процесс', typeRegistry: 'Реестр',
    typeHardware: 'Оборудование', typeSoftware: 'ПО',
    typeSystem: 'Система',
    noData: 'Нет данных для отображения',
    dmaDetected: 'Обнаружено DMA-устройств',
    cheatsFound: 'Найдено следов читов',
    processesFound: 'Подозрительных процессов',
    cheatFilesUnit: 'файлов', cheatProcUnit: 'процессов', cheatRegUnit: 'реестр',
    cheatBrowserUnit: 'браузер', cheatHwUnit: 'устройств', cheatOtherUnit: 'другое',
    cheatConfidence: 'уверенность',
    cheatOtherActivity: 'Другая подозрительная активность',
    devicesTitle: 'Подключенные устройства',
    devicesSafe: 'Обычные устройства',
    devicesSuspicious: '⚠ Подозрительные устройства',
    devicesHistory: '⏳ История DMA',
    devicesPhone: 'Телефон', devicesFlash: 'Флешка', devicesDma: 'DMA',
    devicesUnknown: 'Неизвестно',
    groupHigh: 'Высокий риск', groupMedium: 'Средний риск', groupLow: 'Низкий риск',
    showAll: 'Показать все', collapse: 'Свернуть',
    groupHidden: 'ещё скрыто',
    searchPlaceholder: 'Поиск по имени, пути или совпадениям...',
    searchNoResults: 'Ничего не найдено',
    exportReport: 'Экспорт',
    exportHtml: 'HTML отчёт',
    exportJson: 'JSON отчёт',
    exportCopied: 'Скопировано!',
  },
  en: {
    title: 'System Scan',
    startBtn: 'Start Scan',
    scanning: 'Scanning...',
    analyzing: 'Analyzing results...',
    done: 'Scan complete',
    found: 'Found',
    high: 'High', medium: 'Medium', low: 'Low',
    risk: 'Risk',
    noThreats: 'No suspicious items detected',
    threatsFound: 'found',
    filesScanned: 'scanned',
    time: 'Time', sec: 'sec',
    clear: 'Clear',
    file: 'File', matches: 'Matches', path: 'Path',
    scanAgain: 'Scan Again',
    browser: 'Browser History',
    tabFull: 'Full Scan', tabFullDesc: 'All modules: files, processes, registry, network, DMA, browser, heuristics',
    tabQuick: 'Quick Check', tabQuickDesc: 'Processes, Prefetch, registry & browser history — no disk walk',
    tabDma: 'DMA Devices', tabDmaDesc: 'Detect DMA cards & FPGA devices',
    tabCleaner: 'PC Cleaner Detection', tabCleanerDesc: 'System cleaning traces, USN journal, timestomping, ShellBags, HWID changes',
    riskHigh: 'High risk', riskMedium: 'Medium risk', riskLow: 'Low risk',
    processRunning: 'Running', processRecent: 'Recent', processPrefetch: 'Prefetch', processMem: 'Memory',
    cheatFiles: 'Files', cheatBrowser: 'History', cheatRegistry: 'Registry',
    dmaPci: 'PCI devices', dmaSoftware: 'Software', dmaDriver: 'Drivers', dmaRegistry: 'Registry',
    typeFile: 'File', typeBrowser: 'Browser', typeProcess: 'Process', typeRegistry: 'Registry',
    typeHardware: 'Hardware', typeSoftware: 'Software',
    typeSystem: 'System',
    noData: 'No data to display',
    dmaDetected: 'DMA devices detected',
    cheatsFound: 'Cheat traces found',
    processesFound: 'Suspicious processes',
    cheatFilesUnit: 'files', cheatProcUnit: 'processes', cheatRegUnit: 'registry',
    cheatBrowserUnit: 'browser', cheatHwUnit: 'hardware', cheatOtherUnit: 'other',
    cheatConfidence: 'confidence',
    cheatOtherActivity: 'Other suspicious activity',
    devicesTitle: 'Connected Devices',
    devicesSafe: 'Normal Devices',
    devicesSuspicious: '⚠ Suspicious Devices',
    devicesHistory: '⏳ DMA History',
    devicesPhone: 'Phone', devicesFlash: 'Flash Drive', devicesDma: 'DMA',
    devicesUnknown: 'Unknown',
    groupHigh: 'High risk', groupMedium: 'Medium risk', groupLow: 'Low risk',
    showAll: 'Show all', collapse: 'Collapse',
    groupHidden: 'more hidden',
    searchPlaceholder: 'Search by name, path or matches...',
    searchNoResults: 'Nothing found',
    exportReport: 'Export',
    exportHtml: 'HTML Report',
    exportJson: 'JSON Report',
    exportCopied: 'Copied!',
  },
}

interface TabConfig {
  id: ScanMode
  icon: string
  label: string
  desc: string
  color: string
}

const TABS: TabConfig[] = [
  { id: 'full',     icon: 'Shield',     label: 'tabFull',     desc: 'tabFullDesc',     color: '#22c55e' },
  { id: 'quick',    icon: 'Crosshair',  label: 'tabQuick',    desc: 'tabQuickDesc',    color: '#F59E0B' },
  { id: 'dma',      icon: 'USB',        label: 'tabDma',      desc: 'tabDmaDesc',      color: '#8B5CF6' },
  { id: 'cleaner',  icon: 'Eraser',     label: 'tabCleaner',  desc: 'tabCleanerDesc',  color: '#EF4444' },
]

// ── Realistic mock data per mode ──

function generateMockData(mode: ScanMode): { results: ScanResult[]; summary: ScanResponse['summary'] } {
  const now = new Date().toISOString()

  const mockSets: Record<ScanMode, { results: ScanResult[]; scanned: number }> = {
    full: {
      results: [
        { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine', 'suspicious debugger', 'module:CreateRemoteThread (injector)'], size: 0, modifiedAt: now },
        { path: '~/Downloads/cheat_loader.js', fileName: '[Score:95] cheat_loader.js', type: 'file', risk: 'high', matches: ['Name → [injector]: DLL injector', 'Extension .js: JavaScript', 'Signatures [menu]: ImGui'], size: 15234, modifiedAt: now },
        { path: '~/Desktop/menu.dll', fileName: '[Score:87] menu.dll', type: 'file', risk: 'high', matches: ['High entropy (7.82)', 'Name → [menu]: Game menu'], size: 245760, modifiedAt: now },
        { path: '~/AppData/Local/FiveM/mods/', fileName: '[Score:80] eulen.asi', type: 'file', risk: 'high', matches: ['Extension .asi: ASI mod GTA', 'No digital signature'], size: 320512, modifiedAt: now },
        { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx (VEN_10ee)', 'FPGA device detected'], size: 0, modifiedAt: now },
        { path: 'HKCU\\...\\Run', fileName: 'Registry [injector]: inject', type: 'registry', risk: 'high', matches: ['registry-deep:inject', 'risk:CRITICAL'], size: 0, modifiedAt: now },
        { path: 'C:\\Windows\\Prefetch\\DMA_TOOL.EXE-*.pf', fileName: 'Prefetch [dma]: DMA_TOOL.EXE', type: 'file', risk: 'high', matches: ['prefetch:dma', 'last-run:2026-07-20'], size: 0, modifiedAt: now },
        { path: 'Browser History', fileName: 'Chrome History', type: 'browser', risk: 'medium', matches: ['browser:nightfall', 'browser:dma', 'browser:injector'], size: 4096, modifiedAt: now },
      ],
      scanned: 2487,
    },
    quick: {
      results: [
        { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine', 'suspicious debugger'], size: 0, modifiedAt: now },
        { path: 'C:\\Windows\\Prefetch\\DMA_TOOL.EXE-*.pf', fileName: 'Prefetch [dma]: DMA_TOOL.EXE', type: 'file', risk: 'high', matches: ['prefetch:dma', 'last-run:2026-07-20'], size: 0, modifiedAt: now },
        { path: 'HKCU\\...\\Run', fileName: 'Registry [injector]: inject', type: 'registry', risk: 'high', matches: ['registry-deep:inject', 'risk:CRITICAL'], size: 0, modifiedAt: now },
        { path: 'Browser History', fileName: 'Chrome History', type: 'browser', risk: 'medium', matches: ['browser:nightfall', 'browser:dma'], size: 4096, modifiedAt: now },
      ],
      scanned: 45,
    },
    dma: {
      results: [
        { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx (VEN_10ee)', 'FPGA device detected'], size: 0, modifiedAt: now },
        { path: '~/Downloads/pcileech/', fileName: 'pcileech.exe', type: 'software', risk: 'high', matches: ['dma-software:pcileech.exe', 'DMA memory tool'], size: 0, modifiedAt: now },
        { path: 'System32/drivers/', fileName: 'leeched.sys', type: 'software', risk: 'high', matches: ['dma-driver:leeched.sys', 'DMA kernel driver'], size: 0, modifiedAt: now },
      ],
      scanned: 8,
    },
    cleaner: {
      results: [
        { path: 'C:\\$Extend\\$UsnJrnl', fileName: '🚨 USN Journal Deleted — Evidence Destruction', type: 'system', risk: 'high', matches: ['usn-journal:deleted', 'All file change history destroyed'], size: 0, modifiedAt: now },
        { path: 'C:\\Windows\\Prefetch\\SDELETE.EXE-*.pf', fileName: '🚨 Secure Deletion Tool: SDELETE', type: 'file', risk: 'high', matches: ['prefetch:sdelete', 'Secure file wiping detected'], size: 0, modifiedAt: now },
        { path: 'HKCU\\Software\\...\\Shell\\BagMRU', fileName: '🚨 ShellBags Registry Keys Wiped', type: 'registry', risk: 'high', matches: ['shellbags:missing', 'Folder browsing history wiped'], size: 0, modifiedAt: now },
        { path: 'C:\\Users\\...\\Downloads', fileName: '🚨 Timestomping Detected', type: 'system', risk: 'high', matches: ['timestomp:5+ files', 'File timestamps manipulated'], size: 0, modifiedAt: now },
      ],
      scanned: 42,
    },

  }

  const data = mockSets[mode]
  return {
    results: data.results,
    summary: {
      totalScanned: data.scanned,
      suspiciousFiles: data.results.length,
      highRiskCount: data.results.filter(r => r.risk === 'high').length,
      scanTimeMs: 1500 + Math.random() * 2000,
    },
  }
}

const INITIAL_SHOW = 5

// ── Pure helpers extracted OUTSIDE component (not recreated on every render) ──

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(ms: number, secLabel: string): string {
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(1)} ${secLabel}`
}

function riskClass(risk: string): string {
  return risk === 'high' ? 'risk-high' : risk === 'medium' ? 'risk-medium' : 'risk-low'
}

function riskLabel(risk: string, lang: 'ru' | 'en'): string {
  const t = (k: string) => T[lang][k] || k
  return risk === 'high' ? t('high') : risk === 'medium' ? t('medium') : t('low')
}

function typeName(type: string, lang: 'ru' | 'en'): string {
  const t = (k: string) => T[lang][k] || k
  switch (type) {
    case 'file': return t('typeFile')
    case 'browser': return t('typeBrowser')
    case 'process': return t('typeProcess')
    case 'registry': return t('typeRegistry')
    case 'hardware': return t('typeHardware')
    case 'software': return t('typeSoftware')
    case 'system': return t('typeSystem')
    default: return type
  }
}

function typeIcon(type: string, size = 14) {
  const c = 'var(--text-secondary)'
  switch (type) {
    case 'file': return <IconFolder size={size} color={c} />
    case 'browser': return <IconGlobe size={size} color={c} />
    case 'process': return <IconGear size={size} color={c} />
    case 'registry': return <IconRegistry size={size} color={c} />
    case 'hardware': return <IconUSB size={size} color={c} />
    case 'software': return <IconMonitor size={size} color={c} />
    case 'system': return <IconMonitor size={size} color={c} />
    default: return <IconFolder size={size} color={c} />
  }
}

function calcScanPercent(progress: ScanProgress | null): number {
  if (!progress) return 0
  if (progress.phase === 'done') return 100
  if (progress.phase === 'analyzing') return 85 + Math.min(progress.filesFound * 2, 14)
  const dirWeight = progress.totalDirs > 0
    ? Math.min(progress.dirsDone / progress.totalDirs, 1)
    : 0
  const fileWeight = Math.min(progress.filesScanned / 300, 1)
  return Math.min(dirWeight * 70 + fileWeight * 14, 84)
}

// ── Component ──

export default function Checker({ lang, tokenId, onBack, accent, light, dark }: CheckerProps) {
  const prefersReducedMotion = useReducedMotion()

  const containerVariants = prefersReducedMotion
    ? { hidden: {}, visible: {} }
    : { hidden: {}, visible: { transition: { staggerChildren: 0.03 } } }

  const itemVariants = prefersReducedMotion
    ? { hidden: {}, visible: {} }
    : { hidden: { opacity: 0 }, visible: { opacity: 1, transition: { duration: 0.3 } } }

  const t = useMemo(() => (key: string) => T[lang][key] || key, [lang])
  const [activeTab, setActiveTab] = useState<ScanMode>('full')
  const cachedEntry = tabCache.get(activeTab)
  const [phase, setPhase] = useState<'idle' | 'scanning' | 'done'>(cachedEntry ? 'done' : 'idle')
  const [progress, setProgress] = useState<ScanProgress | null>(null)

  const [results, setResults] = useState<ScanResult[]>(cachedEntry?.results ?? [])
  const [summary, setSummary] = useState<ScanResponse['summary'] | null>(cachedEntry?.summary ?? null)
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')
  const [tabTransition, setTabTransition] = useState<'enter' | 'idle' | 'exit'>('idle')
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(['high']))
  const [showAllGroups, setShowAllGroups] = useState<Set<string>>(new Set())
  const [searchQuery, setSearchQuery] = useState('')
  const [exportMsg, setExportMsg] = useState('')
  const [serverMsg, setServerMsg] = useState('')
  const [copiedPath, setCopiedPath] = useState('')
  const [tabCounts, setTabCounts] = useState<Map<ScanMode, number>>(new Map())
  const [detailModalOpen, setDetailModalOpen] = useState(false)
  const [compactMode, setCompactMode] = useState(false)
  const [telegramSending, setTelegramSending] = useState(false)
  const { play: playSound } = useSound()
  const scanRef = useRef<boolean>(false)
  const isMounted = useRef(true)

  useEffect(() => {
    return () => {
      isMounted.current = false
    }
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

  // ── Grouped results for clean cheat display ──
  const groupedResults = useMemo(() => groupResults(results), [results])
  const [cheatExpandedGroups, setCheatExpandedGroups] = useState<Set<string>>(new Set())
  const [showOtherItems, setShowOtherItems] = useState(false)
  const [showSafeDevices, setShowSafeDevices] = useState(false)

  // Auto-expand high-risk cheat groups on first load
  useEffect(() => {
    if (groupedResults.cheatGroups.length > 0 && cheatExpandedGroups.size === 0) {
      const highRiskGroups = groupedResults.cheatGroups
        .filter(g => g.risk === 'high')
        .map(g => g.cheatName)
      if (highRiskGroups.length > 0) {
        setCheatExpandedGroups(new Set(highRiskGroups))
      }
    }
  }, [groupedResults.cheatGroups])
  const transitionTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const currentTab = TABS.find(t => t.id === activeTab)!
  const activeTabIndex = TABS.findIndex(t => t.id === activeTab)

  useEffect(() => {
    return () => {
      scanRef.current = false
      if (transitionTimer.current) clearTimeout(transitionTimer.current)
    }
  }, [])

  const handleStartScan = useCallback(async () => {
    const api = window.electronAPI
    if (scanRef.current) return
    scanRef.current = true

    tabCache.delete(activeTab)

    playSound('swoosh')
    setPhase('scanning')
    setError('')
    setResults([])
    setSummary(null)
    setSelectedResult(null)
    setProgress(null)

    if (!api?.startScan) {
      for (let i = 0; i <= 100; i += 10) {
        if (!scanRef.current) return
        await new Promise(r => setTimeout(r, 150))
        setProgress({
          phase: i < 80 ? 'scanning' : i < 100 ? 'analyzing' : 'done',
          currentDir: i < 80 ? `${t(currentTab.label)} scanning...` : 'Analyzing...',
          filesFound: Math.floor(i / 20),
          filesScanned: Math.floor(i * 3),
          totalDirs: 5,
          dirsDone: Math.min(Math.floor(i / 20), 5),
        })
      }
      if (!scanRef.current) return

      const mock = generateMockData(activeTab)
      setResults(mock.results)
      setSummary(mock.summary)
      tabCache.set(activeTab, { results: mock.results, summary: mock.summary })
      playSound(mock.summary.suspiciousFiles > 0 ? 'alarm' : 'complete')
      setPhase('done')
      scanRef.current = false
      setTabCounts(prev => { const next = new Map(prev); next.set(activeTab, mock.results.length); return next; })
      submitToServer(activeTab, mock.summary, mock.results)
      return
    }

    const progressHandler = (data: ScanProgress) => {
      if (scanRef.current && isMounted.current) setProgress({ ...data })
    }
    const unsubscribeProgress = api.onScanProgress(progressHandler)

    try {
      const response = await api.startScan(activeTab, tokenId !== null ? tokenId : undefined)
      if (scanRef.current) {
        setResults(response.results)
        setSummary(response.summary)
        tabCache.set(activeTab, { results: response.results, summary: response.summary })
        setTabCounts(prev => { const next = new Map(prev); next.set(activeTab, response.results.length); return next; })
        playSound(response.summary.suspiciousFiles > 0 ? 'alarm' : 'complete')
        setPhase('done')
        submitToServer(activeTab, response.summary, response.results)
      }
    } catch (err) {
      if (scanRef.current) {
        setError(err instanceof Error ? err.message : 'Scan error')
        setPhase('idle')
      }
    } finally {
      scanRef.current = false
      if (typeof unsubscribeProgress === 'function') unsubscribeProgress()
    }
  }, [activeTab, currentTab, t, tokenId, playSound])

  const handleClear = useCallback(() => {
    tabCache.clear()
    setResults([])
    setSummary(null)
    setProgress(null)
    setSelectedResult(null)
    setPhase('idle')
    scanRef.current = false
    setExpandedGroups(new Set(['high']))
    setShowAllGroups(new Set())
    setCheatExpandedGroups(new Set())
    setShowOtherItems(false)
    setShowSafeDevices(false)
    setSearchQuery('')
  }, [])

  const handleExport = useCallback((format: 'html' | 'json' | 'md') => {
    if (!summary) return
    let content: string
    let ext: string
    let mime: string
    if (format === 'html') {
      content = exportHtml(results, summary)
      ext = 'html'
      mime = 'text/html'
    } else if (format === 'md') {
      content = exportMarkdown(results, summary)
      ext = 'md'
      mime = 'text/markdown'
    } else {
      content = exportJson(results, summary)
      ext = 'json'
      mime = 'application/json'
    }
    const blob = new Blob([content], { type: mime })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `predator_scan_${new Date().toISOString().slice(0, 10)}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
    setExportMsg('✓')
    setTimeout(() => setExportMsg(''), 2000)
  }, [results, summary])

  const handleExportPdf = useCallback(() => {
    if (!summary) return
    exportPdf(results, summary)
    setExportMsg('✓')
    setTimeout(() => setExportMsg(''), 2000)
  }, [results, summary])

  const handleTelegramExport = useCallback(async () => {
    if (!summary || telegramSending) return
    setTelegramSending(true)
    try {
      let botToken = ''
      let chatId = ''
      if (window.electronAPI?.getConfig) {
        const cfg = await window.electronAPI.getConfig()
        botToken = (cfg as any).telegramBotToken || ''
        chatId = (cfg as any).telegramChatId || ''
      }
      if (!botToken || !chatId) {
        setExportMsg('⚙ Настройте Telegram бота в конфиге')
        setTimeout(() => setExportMsg(''), 3000)
        return
      }
      const res = await sendToTelegram(botToken, chatId, results, summary)
      setExportMsg(res.success ? '✓ TG' : '✗ Ошибка')
      setTimeout(() => setExportMsg(''), 3000)
    } catch {
      setExportMsg('✗ Ошибка')
      setTimeout(() => setExportMsg(''), 3000)
    } finally {
      setTelegramSending(false)
    }
  }, [results, summary, telegramSending])

  const handleTabChange = useCallback((tab: ScanMode) => {
    if (tab === activeTab) return
    scanRef.current = false

    if (phase === 'done' && summary) {
      tabCache.set(activeTab, { results, summary })
    }

    setTabTransition('exit')
    if (transitionTimer.current) clearTimeout(transitionTimer.current)

    transitionTimer.current = setTimeout(() => {
      setActiveTab(tab)
      const cached = tabCache.get(tab)
      if (cached) {
        setResults(cached.results)
        setSummary(cached.summary)
        setPhase('done')
      } else {
        setPhase('idle')
        setResults([])
        setSummary(null)
      }
      setProgress(null)
      setSelectedResult(null)
      setError('')
      setSearchQuery('')

      setTabTransition('enter')
      setTimeout(() => setTabTransition('idle'), 200)
    }, 150)
  }, [activeTab, phase, results, summary])

  const submitToServer = useCallback(async (mode: string, summary: ScanResponse['summary'], results: ScanResult[]) => {
    try {
      let pcName = 'unknown'
      try {
        if (window.electronAPI?.getPCName) {
          pcName = await window.electronAPI.getPCName()
        }
      } catch { /* ignore */ }

      await submitScan({
        token_id: tokenId ?? undefined,
        pc_username: pcName,
        mode,
        total_scanned: summary.totalScanned,
        suspicious_files: summary.suspiciousFiles,
        high_risk_count: summary.highRiskCount,
        scan_time_ms: summary.scanTimeMs,
        results: results.slice(0, 50).map(r => ({
          path: r.path,
          fileName: r.fileName,
          type: r.type,
          risk: r.risk,
          matches: r.matches.slice(0, 5),
        })),
      })
      if (isMounted.current) {
        setServerMsg('✓')
        setTimeout(() => {
          if (isMounted.current) setServerMsg('')
        }, 3000)
      }
    } catch { /* ignore */ }
  }, [tokenId, t])

  return (
    <div className="checker-wrapper">
      <div className="checker-header">
        <div className="checker-title-row">
          <Button className="checker-back-btn" variant="ghost" size="sm" onClick={onBack} title="Back">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </Button>
          <h2 className="checker-title">{t('title')}</h2>
          <div className="checker-status-dot" data-phase={phase} />
        </div>
      </div>

      {/* Tabs */}
      <div className="checker-tabs" role="tablist">
        {TABS.map(tab => (
          <Magnetic key={tab.id} strength={0.15}>
          <button
            className={`checker-tab${activeTab === tab.id ? ' active' : ''}`}
            onClick={() => { playSound('tick'); handleTabChange(tab.id) }}
            role="tab"
            aria-selected={activeTab === tab.id}
            data-color={tab.color}
            style={{ '--tab-accent': tab.color, width: '100%' } as React.CSSProperties}
          >
            <span className="checker-tab-icon">
              {tab.icon === 'Folder' ? <IconFolder size={16} color={tab.color} /> :
               tab.icon === 'Gear' ? <IconGear size={16} color={tab.color} /> :
               tab.icon === 'Crosshair' ? <IconCrosshair size={16} color={tab.color} /> :
               tab.icon === 'USB' ? <IconUSB size={16} color={tab.color} /> :
               tab.icon === 'Shield' ? <IconShield size={16} color={tab.color} /> :
               tab.icon === 'Globe' ? <IconGlobe size={16} color={tab.color} /> :
               tab.icon === 'Eraser' ? <IconEraser size={16} color={tab.color} /> :
               tab.icon}
            </span>
            <div className="checker-tab-text">
              <span className="checker-tab-label">{t(tab.label)}</span>
              <span className="checker-tab-desc">{t(tab.desc)}</span>
            </div>
            {tabCounts.get(tab.id) && tabCounts.get(tab.id)! > 0 && (
              <span className="checker-tab-badge" style={{ '--tab-accent': tab.color } as React.CSSProperties}>
                {tabCounts.get(tab.id)}
              </span>
            )}
          </button>
          </Magnetic>
        ))}
      </div>

      {phase !== 'scanning' && <p className="checker-desc" style={{ marginBottom: 16 }}>{t(currentTab.desc)}</p>}

      {/* Tab content with transitions */}
      <div className={`tab-content${tabTransition === 'exit' ? ' exit' : ''}${tabTransition === 'enter' ? ' enter' : ''}`}>

      {/* Idle */}
      {phase === 'idle' && (
        <div className="checker-idle">
          <div className="checker-idle-icon" style={{ animationDelay: `${activeTabIndex * -0.8}s` }}>
            {currentTab.icon === 'Folder' ? <IconFolder size={24} color={currentTab.color} animated /> :
             currentTab.icon === 'Gear' ? <IconGear size={24} color={currentTab.color} animated /> :
             currentTab.icon === 'Crosshair' ? <IconCrosshair size={24} color={currentTab.color} animated /> :
             currentTab.icon === 'USB' ? <IconUSB size={24} color={currentTab.color} animated /> :
             currentTab.icon === 'Shield' ? <IconShield size={24} color={currentTab.color} animated /> :
             currentTab.icon === 'Globe' ? <IconGlobe size={24} color={currentTab.color} animated /> :
             currentTab.icon === 'Eraser' ? <IconEraser size={24} color={currentTab.color} /> : null}
          </div>
          <Button className="checker-start-btn" onClick={handleStartScan}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
            </svg>
            {t('startBtn')}
          </Button>
        </div>
      )}

      {/* Scanning: Live terminal */}
      {phase === 'scanning' && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <ScanningDots size={20} color={accent} />
            <button
              className={`checker-compact-toggle${compactMode ? ' active' : ''}`}
              onClick={() => setCompactMode(c => !c)}
              title="Компактный режим"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                {compactMode ? (
                  <><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></>
                ) : (
                  <><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" y1="10" x2="21" y2="3"/><line x1="3" y1="21" x2="10" y2="14"/></>
                )}
              </svg>
              {compactMode ? (lang === 'ru' ? 'Развернуть' : 'Expand') : (lang === 'ru' ? 'Компактно' : 'Compact')}
            </button>
          </div>
          {!compactMode && (
            <ScanTerminal
              progress={progress}
              phase={progress?.phase || 'scanning'}
              accent={accent}
              light={light}
            />
          )}
        </>
      )}

      {/* Error */}
      {error && <div className="checker-error">{error}</div>}

      {/* Results */}
      {phase === 'done' && (
        <div className="checker-results">
          {summary && (
            <div className={`checker-summary${summary.suspiciousFiles > 0 ? ' warning-active' : ' safe'}`}>
              <div className={`checker-summary-icon ${summary.suspiciousFiles > 0 ? 'warning' : 'safe'}`}>
                {summary.suspiciousFiles > 0 ? (
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                  </svg>
                ) : (
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/>
                    <polyline points="22 4 12 14.01 9 11.01"/>
                  </svg>
                )}
              </div>
              {summary.suspiciousFiles > 0 ? (
                <div className="checker-summary-text" style={{ marginBottom: 8 }}>
                  {`${summary.suspiciousFiles} ${t('threatsFound')}`}
                </div>
              ) : (
                <div className="checker-empty-state">
                  <div className="checker-empty-logo">
                    <PredatorLogo3D accent={accent} light={light} dark={dark} size={72} phase="done" threatCount={0} />
                  </div>
                  <div className="checker-empty-check">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  </div>
                  <div className="checker-empty-title">Система чиста</div>
                  <div className="checker-empty-desc">Проверены следующие модули:</div>
                  <div className="checker-empty-modules">
                    <span className="checker-empty-module"><IconFolder size={12} /> Файловая система</span>
                    <span className="checker-empty-module"><IconGear size={12} /> Процессы</span>
                    <span className="checker-empty-module"><IconRegistry size={12} /> Реестр</span>
                    <span className="checker-empty-module"><IconUSB size={12} /> DMA-устройства</span>
                    <span className="checker-empty-module"><IconGlobe size={12} /> Сеть</span>
                    <span className="checker-empty-module"><IconLock size={12} /> Цифровые подписи</span>
                    <span className="checker-empty-module"><IconDNA size={12} /> Поведенческий анализ</span>
                    <span className="checker-empty-module"><IconGlobe size={12} /> История браузера</span>
                    <span className="checker-empty-module"><IconChart size={12} /> Энтропия файлов</span>
                  </div>
                </div>
              )}
              <div className="checker-summary-stats" style={{ animationDelay: '0.3s', animation: 'phaseFadeIn 0.5s 0.3s var(--ease-out) both' }}>
                <span>{summary.totalScanned} {t('filesScanned')}</span>
                <span className="checker-summary-dot">•</span><span>{t('time')}: {formatTime(summary.scanTimeMs, t('sec'))}</span>
              </div>
            </div>
          )}

          {results.length > 0 && summary && summary.suspiciousFiles > 0 && (
            <>
              <ThreatMap results={results} />
              <ApcDashboard results={results} lang={lang} />
            </>
          )}

          {/* ── Connected Devices Section ── */}
          {(groupedResults.deviceSummary.hasSuspiciousDevices || groupedResults.deviceSummary.hasDmaHistory || groupedResults.deviceSummary.connectedSafe.length > 0) && (
            <div className="devices-section">
              <div className="devices-header">
                <span className="devices-title">🔌 {t('devicesTitle')}</span>
              </div>

              {/* Suspicious devices (DMA/FPGA) */}
              {groupedResults.deviceSummary.connectedSuspicious.length > 0 && (
                <div className="devices-group suspicious">
                  <div className="devices-group-header">
                    <span>{t('devicesSuspicious')} ({groupedResults.deviceSummary.connectedSuspicious.length})</span>
                  </div>
                  {groupedResults.deviceSummary.connectedSuspicious.map((r, i) => (
                    <div key={`dma-${i}`} className="device-item danger"
                      onClick={() => { setSelectedResult(r); setDetailModalOpen(true) }}>
                      <span className="device-item-icon">⚠️</span>
                      <div className="device-item-info">
                        <span className="device-item-name">{r.fileName}</span>
                        {r.matches.slice(0, 2).map((m, j) => (
                          <span key={j} className="device-item-detail">{m}</span>
                        ))}
                      </div>
                      <span className="device-item-risk high">HIGH</span>
                    </div>
                  ))}
                </div>
              )}

              {/* DMA history */}
              {groupedResults.deviceSummary.dmaHistory.length > 0 && (
                <div className="devices-group history">
                  <div className="devices-group-header">
                    <span>{t('devicesHistory')} ({groupedResults.deviceSummary.dmaHistory.length})</span>
                  </div>
                  {groupedResults.deviceSummary.dmaHistory.map((r, i) => (
                    <div key={`dmahist-${i}`} className="device-item warning"
                      onClick={() => { setSelectedResult(r); setDetailModalOpen(true) }}>
                      <span className="device-item-icon">⏳</span>
                      <div className="device-item-info">
                        <span className="device-item-name">{r.fileName}</span>
                        {r.matches.slice(0, 2).map((m, j) => (
                          <span key={j} className="device-item-detail">{m}</span>
                        ))}
                      </div>
                      <span className="device-item-risk high">WAS CONNECTED</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Safe devices (collapsible) */}
              {groupedResults.deviceSummary.connectedSafe.length > 0 && (
                <div className="devices-group safe">
                  <div className="devices-group-header" style={{ cursor: 'pointer' }}
                    onClick={() => setShowSafeDevices(o => !o)}>
                    <span>{t('devicesSafe')} ({groupedResults.deviceSummary.connectedSafe.length})</span>
                    <span className={`cheat-group-chevron ${showSafeDevices ? 'open' : ''}`}>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </span>
                  </div>
                  {showSafeDevices && (
                    <div className="devices-safe-list">
                      {groupedResults.deviceSummary.connectedSafe.map((r, i) => (
                        <div key={`safe-${i}`} className="device-item safe"
                          onClick={() => { setSelectedResult(r); setDetailModalOpen(true) }}>
                          <span className="device-item-icon">
                            {r.fileName.includes('📱') ? '📱' : r.fileName.includes('💾') ? '💾' : r.fileName.includes('⌨️') ? '⌨️' : r.fileName.includes('📹') ? '📹' : r.fileName.includes('🎵') ? '🎵' : r.fileName.includes('📶') ? '📶' : '🔌'}
                          </span>
                          <span className="device-item-name">{r.fileName}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── Grouped Cheat Detection Cards ── */}
          {groupedResults.cheatGroups.length > 0 && (
            <div className="cheat-groups-section">
              <div className="cheat-groups-header">
                <span className="cheat-groups-title">
                  🎯 {t('cheatsFound')}: {groupedResults.summary.totalCheatsDetected}
                </span>
                <span className="cheat-groups-subtitle">
                  {groupedResults.summary.totalHighRisk} HIGH · {groupedResults.summary.totalMediumRisk} MEDIUM
                </span>
              </div>
              {groupedResults.cheatGroups.map(group => {
                const isExpanded = cheatExpandedGroups.has(group.cheatName)
                const toggleGroup = () => {
                  setCheatExpandedGroups(prev => {
                    const next = new Set(prev)
                    if (next.has(group.cheatName)) next.delete(group.cheatName)
                    else next.add(group.cheatName)
                    return next
                  })
                }
                const parts: string[] = []
                if (group.counts.files > 0) parts.push(`${group.counts.files} ${t('cheatFilesUnit')}`)
                if (group.counts.processes > 0) parts.push(`${group.counts.processes} ${t('cheatProcUnit')}`)
                if (group.counts.registry > 0) parts.push(`${group.counts.registry} ${t('cheatRegUnit')}`)
                if (group.counts.browser > 0) parts.push(`${group.counts.browser} ${t('cheatBrowserUnit')}`)
                if (group.counts.hardware > 0) parts.push(`${group.counts.hardware} ${t('cheatHwUnit')}`)
                if (group.counts.other > 0) parts.push(`${group.counts.other} ${t('cheatOtherUnit')}`)
                const findingSummary = parts.join(', ')
                const confColor = group.confidence >= 70 ? '#22c55e' : group.confidence >= 40 ? '#f59e0b' : '#ef4444'
                return (
                  <div key={group.cheatName} className={`cheat-group-card ${group.risk}`}>
                    <button className="cheat-group-header" onClick={toggleGroup}>
                      <div className="cheat-group-header-left">
                        <span className={`cheat-group-risk-dot ${group.risk}`} />
                        <span className="cheat-group-name">{group.cheatName}</span>
                        <span className={`cheat-group-badge ${group.risk}`}>{riskLabel(group.risk, lang)}</span>
                      </div>
                      <div className="cheat-group-header-right">
                        <span className="cheat-group-count">{group.findings.length}</span>
                        <span className={`cheat-group-chevron ${isExpanded ? 'open' : ''}`}>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="6 9 12 15 18 9" />
                          </svg>
                        </span>
                      </div>
                    </button>
                    <div className="cheat-group-meta">
                      <span className="cheat-group-summary">{findingSummary}</span>
                      <span className="cheat-group-confidence" style={{ color: confColor }}>
                        {group.confidence}% {t('cheatConfidence')}
                      </span>
                    </div>
                    {isExpanded && (
                      <div className="cheat-group-body">
                        {group.tags.length > 0 && (
                          <div className="cheat-group-tags">
                            {group.tags.map((tag, i) => (
                              <span key={i} className="cheat-group-tag">{tag}</span>
                            ))}
                          </div>
                        )}
                        {group.findings.map((r, i) => (
                          <div key={`${r.path}-${i}`}
                            className={`cheat-group-item ${selectedResult?.path === r.path && selectedResult?.fileName === r.fileName ? 'selected' : ''}`}
                            data-risk={r.risk}
                            onClick={() => { setSelectedResult(r); setDetailModalOpen(true) }}
                          >
                            <span className="cheat-group-item-type">{typeIcon(r.type, 12)}</span>
                            <div className="cheat-group-item-info">
                              <span className="cheat-group-item-name">{r.fileName}</span>
                              <span className="cheat-group-item-path">{r.path.length > 50 ? r.path.slice(0, 47) + '...' : r.path}</span>
                            </div>
                            <span className="cheat-group-item-risk" data-risk={r.risk}>{riskLabel(r.risk, lang)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {/* ── Other suspicious items (ungrouped) ── */}
          {(groupedResults.otherHigh.length > 0 || groupedResults.otherMedium.length > 0) && (
            <div className="cheat-other-section">
              <button className="cheat-other-header" onClick={() => setShowOtherItems(o => !o)}>
                <span>🔍 {t('cheatOtherActivity')} ({groupedResults.otherHigh.length + groupedResults.otherMedium.length})</span>
                <span className={`cheat-group-chevron ${showOtherItems ? 'open' : ''}`}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </span>
              </button>
              {showOtherItems && (
                <div className="cheat-other-body">
                  {[...groupedResults.otherHigh, ...groupedResults.otherMedium].map((r, i) => (
                    <div key={`other-${i}`}
                      className={`result-row${selectedResult?.path === r.path && selectedResult?.fileName === r.fileName ? ' selected' : ''}`}
                      data-risk={r.risk}
                      onClick={() => { setSelectedResult(r); setDetailModalOpen(true) }}
                    >
                      <div className="result-row-main">
                        <div className="result-info">
                          <span className="result-name">{r.fileName}</span>
                          <span className="result-path">{r.path.length > 55 ? r.path.slice(0, 52) + '...' : r.path}</span>
                        </div>
                        <div className="result-matches">
                          {r.matches.slice(0, 1).map((m, j) => (
                            <span key={j} className="match-tag">{m.includes(':') ? m.split(':').slice(1).join(':') : m}</span>
                          ))}
                          {r.matches.length > 1 && <span className="match-more">+{r.matches.length - 1}</span>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {results.length > 0 && (
            <div className="checker-search">
              <svg className="search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
              </svg>
              <input
                type="text"
                className="search-input"
                placeholder={t('searchPlaceholder')}
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
              {searchQuery && (
                <button className="search-clear" onClick={() => setSearchQuery('')}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                </button>
              )}
            </div>
          )}

          {results.length > 0 && (
            <div className="checker-results-split">
              <div className="checker-results-list">
                <motion.div className="checker-groups" variants={containerVariants} initial="hidden" animate="visible">
                  {filteredResults.length > 0 ? (
                    (['high', 'medium', 'low'] as const).map(riskLevel => {
                    const group = filteredResults.filter(r => r.risk === riskLevel)
                    if (group.length === 0) return null
                    const isExpanded = expandedGroups.has(riskLevel)
                    const isShowAll = showAllGroups.has(riskLevel)
                    const visible = isShowAll ? group : group.slice(0, INITIAL_SHOW)
                    const hidden = group.length - INITIAL_SHOW

                    const toggleGroup = () => {
                      setExpandedGroups(prev => {
                        const next = new Set(prev)
                        if (next.has(riskLevel)) next.delete(riskLevel)
                        else next.add(riskLevel)
                        return next
                      })
                    }
                    const toggleShowAll = () => {
                      setShowAllGroups(prev => {
                        const next = new Set(prev)
                        if (next.has(riskLevel)) next.delete(riskLevel)
                        else next.add(riskLevel)
                        return next
                      })
                    }

                    return (
                      <motion.div key={riskLevel} className={`result-group group-${riskLevel}`} variants={itemVariants}>
                        <button className="group-header" onClick={toggleGroup}>
                          <div className="group-header-left">
                            <span className={`group-risk-dot dot-${riskLevel}`} />
                            <span className="group-title">{
                              riskLevel === 'high' ? t('groupHigh') :
                              riskLevel === 'medium' ? t('groupMedium') : t('groupLow')
                            }</span>
                          </div>
                          <div className="group-header-right">
                            <span className="group-count">{group.length}</span>
                            <span className={`group-chevron ${isExpanded ? 'open' : ''}`}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <polyline points="6 9 12 15 18 9" />
                              </svg>
                            </span>
                          </div>
                        </button>

                        {isExpanded && (
                          <motion.div className="group-body" variants={containerVariants} initial="hidden" animate="visible">
                            {visible.map((r, i) => (
                              <motion.div key={`${r.path}-${i}`}
                                className={`result-row${selectedResult?.path === r.path && selectedResult?.fileName === r.fileName ? ' selected' : ''}`}
                                data-risk={r.risk}
                                variants={itemVariants}
                                onClick={() => { setSelectedResult(r); setDetailModalOpen(true) }}
                              >
                                <div className="result-row-main">
                                  <div className="result-info">
                                    <span className="result-name">{r.fileName}</span>
                                    <span className="result-path">{r.path.length > 55 ? r.path.slice(0, 52) + '...' : r.path}</span>
                                  </div>
                                  <div className="result-matches">
                                    {r.matches.slice(0, 1).map((m, j) => (
                                      <span key={j} className="match-tag">{m.includes(':') ? m.split(':').slice(1).join(':') : m}</span>
                                    ))}
                                    {r.matches.length > 1 && <span className="match-more">+{r.matches.length - 1}</span>}
                                  </div>
                                </div>
                              </motion.div>
                            ))}

                            {hidden > 0 && !isShowAll && (
                              <button className="group-show-btn" onClick={toggleShowAll}>
                                {t('showAll')} {group.length} ({hidden} {t('groupHidden')})
                              </button>
                            )}
                            {isShowAll && group.length > INITIAL_SHOW && (
                              <button className="group-show-btn collapse" onClick={toggleShowAll}>
                                {t('collapse')}
                              </button>
                            )}
                          </motion.div>
                        )}
                      </motion.div>
                    )
                  })
                  ) : (
                    searchQuery && <div className="search-no-results">{t('searchNoResults')}</div>
                  )}
                </motion.div>
              </div>

              <div className="checker-results-detail">
                {selectedResult ? (
                  <>
                    <div className="checker-detail-title-row">
                      <span className="checker-type-icon-large">{typeIcon(selectedResult.type)}</span>
                      <div>
                        <div className="checker-detail-filename">{selectedResult.fileName}</div>
                        <div className="checker-detail-type">{typeName(selectedResult.type, lang)} · {riskLabel(selectedResult.risk, lang)}</div>
                      </div>
                    </div>
                    <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <div className="checker-detail-section">
                        <span className="checker-detail-label">{t('path')}</span>
                        <span className="checker-detail-value" style={{ wordBreak: 'break-all', fontSize: 11 }}>{selectedResult.path}</span>
                        <button
                          className={`checker-copy-btn${copiedPath === selectedResult.path ? ' copied' : ''}`}
                          onClick={() => {
                            navigator.clipboard.writeText(selectedResult.path).catch(() => {})
                            setCopiedPath(selectedResult.path)
                            setTimeout(() => setCopiedPath(''), 2000)
                          }}
                        >
                          {copiedPath === selectedResult.path ?
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5">
                            <polyline points="20 6 9 17 4 12" />
                          </svg> :
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                          </svg>}
                        </button>
                      </div>
                      {selectedResult.size > 0 && (
                        <div className="checker-detail-section">
                          <span className="checker-detail-label">Size</span>
                          <span className="checker-detail-value">{formatSize(selectedResult.size)}</span>
                        </div>
                      )}
                      <div className="checker-detail-section">
                        <span className="checker-detail-label">{t('matches')}</span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                          {selectedResult.matches.map((m, j) => (
                            <span key={j} className="match-tag">{m}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="checker-detail-empty">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" strokeWidth="1.5" style={{ opacity: 0.3 }}>
                      <path d="M7 11L12 6l5 5M12 6v12"/>
                    </svg>
                    <span>Выберите элемент из списка</span>
                    <span style={{ fontSize: 11, opacity: 0.5 }}>Нажмите на строку для просмотра деталей</span>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="checker-actions">
            <Button className="checker-action-btn secondary" size="sm" onClick={handleClear}>{t('clear')}</Button>
            <div className="checker-export-group">
              <Button className="checker-action-btn export" size="sm" onClick={() => handleExport('html')} title={t('exportHtml')}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                {t('exportHtml')}
              </Button>
              <Button className="checker-action-btn export" size="sm" onClick={() => handleExport('md')} title="Markdown">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                MD
              </Button>
              <Button className="checker-action-btn export" size="sm" onClick={handleExportPdf} title="PDF (печать)">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                PDF
              </Button>
              <Button className="checker-action-btn export" size="sm" onClick={handleTelegramExport} title="Отправить в Telegram">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/>
                </svg>
                {telegramSending ? '...' : 'TG'}
              </Button>
              <span className="checker-export-msg">{exportMsg}</span>
            </div>
            <Button className="checker-action-btn primary" size="sm" onClick={handleStartScan}>{t('scanAgain')}</Button>
          </div>
        </div>
      )}
      </div>{/* /tab-content */}

      {/* File Detail Modal */}
      {selectedResult && (
        <FileDetailModal
          open={detailModalOpen}
          onClose={() => setDetailModalOpen(false)}
          fileName={selectedResult.fileName}
          filePath={selectedResult.path}
          fileType={selectedResult.type}
          risk={selectedResult.risk}
          matches={selectedResult.matches}
          size={selectedResult.size}
          sha256={selectedResult.sha256}
        />
      )}

      {/* Compact Scan Overlay */}
      <CompactScanOverlay
        open={compactMode && phase === 'scanning'}
        onClose={() => setCompactMode(false)}
        onExpand={() => setCompactMode(false)}
        progress={progress}
        mode={activeTab}
        modeLabel={t(currentTab.label)}
        accent={accent}
        light={light}
        lang={lang}
      />
    </div>
  )
}