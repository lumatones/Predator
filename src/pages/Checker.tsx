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
import { Magnetic } from '../components/ui/Magnetic'
import { Button } from '../components/ui/Button'
import { ScanTerminal } from '../components/ui/ScanTerminal'
import { Skeleton } from '../components/ui/Skeleton'
import { FileDetailModal } from '../components/ui/FileDetailModal'
import { BinaryTriagePanel } from '../components/ui/BinaryTriagePanel'
import type { BinaryTriageReport } from '../../types/binary-triage'
import { ResultsView } from '../components/ui/ResultsView'
import { CompactScanOverlay } from '../components/ui/CompactScanOverlay'
import { Tooltip } from '../components/ui/Tooltip'
import { ScanningDots } from '../components/ui/AnimatedIcons'
import { useSound } from '../hooks/useSound'
import {
  IconFolder,
  IconGear,
  IconCrosshair,
  IconUSB,
  IconShield,
  IconGlobe,
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
    groupCritical: 'Критический риск', groupHigh: 'Высокий риск', groupMedium: 'Средний риск', groupLow: 'Низкий риск',
    showAll: 'Показать все', collapse: 'Свернуть',
    groupHidden: 'ещё скрыто',
    searchPlaceholder: 'Поиск по имени, пути или совпадениям...',
    searchNoResults: 'Ничего не найдено',
    exportReport: 'Экспорт',
    exportHtml: 'HTML отчёт',
    exportJson: 'JSON отчёт',
    scanError: 'Ошибка сканирования',
    scanErrorHint: 'Попробуйте другой режим или перезапустите приложение',
    scanInconclusive: 'Проверка завершена не полностью',
    scanInconclusiveHint: 'Некоторые модули не смогли получить данные. Результат нельзя считать подтверждённо чистым.',
    backBtn: 'Назад',
    binaryTriage: 'Хардкор-разбор бинарника',
    binaryTriageHint: 'PE / TLS / API / packing — без запуска файла',
    binaryTriageError: 'Не удалось выполнить статический разбор',
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
    groupCritical: 'Critical risk', groupHigh: 'High risk', groupMedium: 'Medium risk', groupLow: 'Low risk',
    showAll: 'Show all', collapse: 'Collapse',
    groupHidden: 'more hidden',
    searchPlaceholder: 'Search by name, path or matches...',
    searchNoResults: 'Nothing found',
    exportReport: 'Export',
    exportHtml: 'HTML Report',
    exportJson: 'JSON Report',
    exportCopied: 'Copied!',
    scanError: 'Scan error',
    scanErrorHint: 'Try another scan mode or restart the app',
    scanInconclusive: 'Scan completed with gaps',
    scanInconclusiveHint: 'Some modules could not collect data. This result is not confirmed clean.',
    backBtn: 'Back',
    binaryTriage: 'Hardcore binary triage',
    binaryTriageHint: 'PE / TLS / API / packing — file is not executed',
    binaryTriageError: 'Static triage failed',
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
  const now = '2026-08-01T10:00:00.000Z'

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
      scanTimeMs: 1800 + data.results.length * 100,
    },
  }
}

// ── Component ──

export default function Checker({ lang, tokenId, onBack, accent, light, dark }: CheckerProps) {
  const prefersReducedMotion = useReducedMotion()

  const t = useMemo(() => (key: string) => T[lang][key] || key, [lang])
  const [activeTab, setActiveTab] = useState<ScanMode>('full')
  const cachedEntry = tabCache.get(activeTab)
  const [phase, setPhase] = useState<'idle' | 'scanning' | 'done'>(cachedEntry ? 'done' : 'idle')
  const [progress, setProgress] = useState<ScanProgress | null>(null)

  const [results, setResults] = useState<ScanResult[]>(cachedEntry?.results ?? [])
  const [summary, setSummary] = useState<ScanResponse['summary'] | null>(cachedEntry?.summary ?? null)
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null)
  const findingTriggerRef = useRef<HTMLElement | null>(null)
  const [error, setError] = useState('')
  const [tabTransition, setTabTransition] = useState<'enter' | 'idle' | 'exit'>('idle')
  const [exportMsg, setExportMsg] = useState('')
  const [copiedPath, setCopiedPath] = useState('')
  const [tabCounts, setTabCounts] = useState<Map<ScanMode, number>>(new Map())
  const [detailModalOpen, setDetailModalOpen] = useState(false)
  const [compactMode, setCompactMode] = useState(false)
  const [telegramSending, setTelegramSending] = useState(false)
  const [triageReport, setTriageReport] = useState<BinaryTriageReport | null>(null)
  const [triageLoading, setTriageLoading] = useState(false)
  const [triageError, setTriageError] = useState('')
  const { play: playSound } = useSound()
  const scanRef = useRef<boolean>(false)
  const isMounted = useRef(true)
  const transitionTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const currentTab = TABS.find(tab => tab.id === activeTab)!
  const activeTabIndex = TABS.findIndex(tab => tab.id === activeTab)

  const openFinding = useCallback((result: ScanResult, event: React.MouseEvent<HTMLElement>) => {
    findingTriggerRef.current = event.currentTarget
    setSelectedResult(result)
    setDetailModalOpen(true)
  }, [])

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
      }
    } catch (err) {
      if (scanRef.current) {
        const baseMsg = err instanceof Error ? err.message : ''
        setError(baseMsg ? `${baseMsg}. ${t('scanErrorHint')}` : t('scanError'))
        setPhase('idle')
      }
    } finally {
      scanRef.current = false
      if (typeof unsubscribeProgress === 'function') unsubscribeProgress()
    }
  }, [activeTab, currentTab, t, tokenId, playSound])

  const handleBinaryTriage = useCallback(async () => {
    if (!window.electronAPI?.triageBinary || triageLoading) return
    setTriageLoading(true)
    setTriageError('')
    try {
      const report = await window.electronAPI.triageBinary()
      if (report) setTriageReport(report)
    } catch (err) {
      setTriageError(err instanceof Error ? err.message : t('binaryTriageError'))
    } finally {
      setTriageLoading(false)
    }
  }, [t, triageLoading])

  const handleClear = useCallback(() => {
    tabCache.clear()
    setResults([])
    setSummary(null)
    setProgress(null)
    setSelectedResult(null)
    setPhase('idle')
    scanRef.current = false
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
        botToken = cfg.telegramBotToken || ''
        chatId = cfg.telegramChatId || ''
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
      setTabTransition('enter')
      setTimeout(() => setTabTransition('idle'), 200)
    }, 150)
  }, [activeTab, phase, results, summary])

  return (
    <div className="checker-wrapper">
      <div className="checker-header">
        <div className="checker-title-row">
          <Button className="checker-back-btn" variant="ghost" size="sm" onClick={onBack} title="Back">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
            <span>{t('backBtn')}</span>
          </Button>
          <h2 className="checker-title">{t('title')}</h2>
          <div className="checker-status-dot status-dot" data-phase={phase} />
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

      {/* Skeleton during tab transitions — outside animated container for visibility */}
      {tabTransition !== 'idle' && (
        <div className="checker-skeleton" aria-hidden="true">
          <div className="checker-skeleton-search">
            <Skeleton width="100%" height="36px" radius="var(--radius-md)" />
          </div>
          {['70%','55%','80%','45%','65%'].map((w, i) => (
            <div key={i} className="checker-skeleton-row">
              <Skeleton width="3px" height="100%" radius="2px" style={{ position: 'absolute', left: 0, top: 6, bottom: 6 }} />
              <div style={{ paddingLeft: 16, width: '100%', display: 'flex', flexDirection: 'column', gap: 6 }}>
                <Skeleton width={w} height="14px" />
                <Skeleton width={`${parseInt(w) - 15}%`} height="11px" />
              </div>
            </div>
          ))}
        </div>
      )}

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
          <motion.button
            className="checker-start-btn"
            data-testid="checker-start-scan"
            onClick={handleStartScan}
            whileHover={prefersReducedMotion ? undefined : { scale: 1.02, y: -1 }}
            whileTap={prefersReducedMotion ? undefined : { scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 400, damping: 25 }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
            </svg>
            {t('startBtn')}
          </motion.button>
          <button
            type="button"
            className="binary-triage-launch"
            data-testid="checker-binary-triage"
            onClick={handleBinaryTriage}
            disabled={triageLoading}
          >
            <span className="binary-triage-launch-mark">{triageLoading ? '…' : '⌁'}</span>
            <span>
              <strong>{triageLoading ? t('analyzing') : t('binaryTriage')}</strong>
              <small>{t('binaryTriageHint')}</small>
            </span>
          </button>
          {triageError && <div className="checker-error" role="alert">{triageError}</div>}
        </div>
      )}

      {/* Scanning: Live terminal */}
      {phase === 'scanning' && (
        <>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <ScanningDots size={20} color={accent} />
            <Tooltip content={lang === 'ru' ? 'Компактный режим: скрывает терминал сканирования и показывает мини-окно с прогрессом. Удобно для фонового сканирования.' : 'Compact mode: hides the scan terminal and shows a mini progress window. Ideal for background scanning.'}>
              <button
              className={`checker-compact-toggle${compactMode ? ' active' : ''}`}
              onClick={() => setCompactMode(c => !c)}
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
            </Tooltip>
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
        <ResultsView
          results={results}
          summary={summary}
          lang={lang}
          accent={accent}
          light={light}
          dark={dark}
          selectedResult={selectedResult}
          onSelectResult={openFinding}
          onClear={handleClear}
          exportMsg={exportMsg}
          copiedPath={copiedPath}
          onCopyPath={(path) => { navigator.clipboard.writeText(path).catch(() => {}); setCopiedPath(path); setTimeout(() => setCopiedPath(''), 2000); }}
          telegramSending={telegramSending}
          onExportHtml={() => handleExport('html')}
          onExportJson={() => handleExport('json')}
          onExportMd={() => handleExport('md')}
          onExportPdf={handleExportPdf}
          onTelegramExport={handleTelegramExport}
        />
      )}
      {phase === 'done' && (
        <motion.button
          className="checker-start-btn"
          onClick={handleStartScan}
          whileHover={prefersReducedMotion ? undefined : { scale: 1.02, y: -1 }}
          whileTap={prefersReducedMotion ? undefined : { scale: 0.95 }}
          transition={{ type: 'spring', stiffness: 400, damping: 25 }}
          style={{ marginTop: 16, maxWidth: 300 }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10" />
          </svg>
          {t('scanAgain')}
        </motion.button>
      )}
      </div>{/* /tab-content */}

      {triageReport && (
        <BinaryTriagePanel
          report={triageReport}
          lang={lang}
          onClose={() => setTriageReport(null)}
        />
      )}

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
          evidence={selectedResult.evidence}
          riskScore={selectedResult.riskScore}
          riskExplanation={selectedResult.riskExplanation}
          lang={lang}
          returnFocusRef={findingTriggerRef}
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