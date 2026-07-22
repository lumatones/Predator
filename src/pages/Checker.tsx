import { useState, useRef, useCallback, useEffect, useMemo } from 'react'
import type { ScanResult, ScanProgress, ScanResponse, ScanMode } from '../types/electron'

interface CheckerProps {
  lang: 'ru' | 'en'
  onBack: () => void
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
    tabFiles: 'Файлы', tabFilesDesc: 'Поиск подозрительных файлов и скриптов',
    tabProcesses: 'Процессы', tabProcessesDesc: 'Запущенные и недавние процессы',
    tabCheats: 'Читы', tabCheatsDesc: 'Поиск Nightfall, DMA, 0Xcheat и других',
    tabDma: 'DMA', tabDmaDesc: 'Обнаружение DMA-карт и FPGA-устройств',
    tabExtended: 'Расширенный', tabExtendedDesc: 'Полное сканирование системы — файлы, процессы, реестр, Prefetch, DMA',
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
    groupHigh: 'Высокий риск', groupMedium: 'Средний риск', groupLow: 'Низкий риск',
    showAll: 'Показать все', collapse: 'Свернуть',
    groupHidden: 'ещё скрыто',
    searchPlaceholder: 'Поиск по имени, пути или совпадениям...',
    searchNoResults: 'Ничего не найдено',
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
    tabFiles: 'Files', tabFilesDesc: 'Search suspicious files & scripts',
    tabProcesses: 'Processes', tabProcessesDesc: 'Running and recent processes',
    tabCheats: 'Cheats', tabCheatsDesc: 'Search Nightfall, DMA, 0Xcheat & more',
    tabDma: 'DMA', tabDmaDesc: 'Detect DMA cards & FPGA devices',
    tabExtended: 'Extended', tabExtendedDesc: 'Full system scan — files, processes, registry, Prefetch, DMA',
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
    groupHigh: 'High risk', groupMedium: 'Medium risk', groupLow: 'Low risk',
    showAll: 'Show all', collapse: 'Collapse',
    groupHidden: 'more hidden',
    searchPlaceholder: 'Search by name, path or matches...',
    searchNoResults: 'Nothing found',
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
  { id: 'files',     icon: '📁', label: 'tabFiles',     desc: 'tabFilesDesc',     color: '#ff4444' },
  { id: 'processes', icon: '⚙️', label: 'tabProcesses', desc: 'tabProcessesDesc', color: '#3B82F6' },
  { id: 'cheats',    icon: '🎯', label: 'tabCheats',    desc: 'tabCheatsDesc',    color: '#F59E0B' },
  { id: 'dma',       icon: '🔌', label: 'tabDma',       desc: 'tabDmaDesc',       color: '#8B5CF6' },
  { id: 'extended',  icon: '🛡️', label: 'tabExtended',  desc: 'tabExtendedDesc',  color: '#22c55e' },
]

// ── Realistic mock data per mode ──

function generateMockData(mode: ScanMode): { results: ScanResult[]; summary: ScanResponse['summary'] } {
  const now = new Date().toISOString()

  const mockSets: Record<ScanMode, { results: ScanResult[]; scanned: number }> = {
    files: {
      results: [
        { path: '~/Downloads/cheat_loader.js', fileName: 'cheat_loader.js', type: 'file', risk: 'high', matches: ['filename:cheat', 'content:inject', 'content:hack'], size: 15234, modifiedAt: now },
        { path: '~/Desktop/menu.dll', fileName: 'menu.dll', type: 'file', risk: 'high', matches: ['pattern:mod menu', 'dll inject'], size: 245760, modifiedAt: now },
        { path: '~/.config/script_hook.lua', fileName: 'script_hook.lua', type: 'file', risk: 'medium', matches: ['filename:script hook'], size: 8912, modifiedAt: now },
      ],
      scanned: 340,
    },
    processes: {
      results: [
        { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine', 'suspicious debugger'], size: 0, modifiedAt: now },
        { path: 'process:Injector Helper (PID: 0)', fileName: 'Injector Helper', type: 'process', risk: 'high', matches: ['process:inject', 'recent:injector'], size: 0, modifiedAt: now },
        { path: 'Prefetch/DMA_TOOL.EXE-*.pf', fileName: 'DMA_TOOL.EXE-*.pf', type: 'file', risk: 'medium', matches: ['prefetch:dma last run'], size: 0, modifiedAt: now },
      ],
      scanned: 45,
    },
    cheats: {
      results: [
        { path: '~/Downloads/Nightfall', fileName: 'Nightfall Loader', type: 'file', risk: 'high', matches: ['cheat:nightfall → nightfall', 'filename:nightfall'], size: 0, modifiedAt: now },
        { path: 'HKCU\\...\\Uninstall', fileName: 'Registry: Nightfall', type: 'registry', risk: 'high', matches: ['registry:nightfall installed'], size: 0, modifiedAt: now },
        { path: 'Browser History', fileName: 'Chrome History', type: 'browser', risk: 'medium', matches: ['browser:nightfall', 'browser:dma'], size: 4096, modifiedAt: now },
      ],
      scanned: 12,
    },
    dma: {
      results: [
        { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx (VEN_10ee)', 'FPGA device detected'], size: 0, modifiedAt: now },
        { path: '~/Downloads/pcileech/', fileName: 'pcileech.exe', type: 'software', risk: 'high', matches: ['dma-software:pcileech.exe', 'DMA memory tool'], size: 0, modifiedAt: now },
        { path: 'System32/drivers/', fileName: 'leeched.sys', type: 'software', risk: 'high', matches: ['dma-driver:leeched.sys', 'DMA kernel driver'], size: 0, modifiedAt: now },
      ],
      scanned: 8,
    },
    extended: {
      results: [
        { path: 'process:Cheat Engine (PID: 4821)', fileName: 'Cheat Engine', type: 'process', risk: 'high', matches: ['process:cheat engine', 'suspicious debugger'], size: 0, modifiedAt: now },
        { path: '~/Downloads/cheat_loader.js', fileName: 'cheat_loader.js', type: 'file', risk: 'high', matches: ['filename:cheat', 'content:inject'], size: 15234, modifiedAt: now },
        { path: '~/AppData/Local/FiveM/mods/', fileName: 'eulen.asi', type: 'file', risk: 'high', matches: ['file:eulen', 'gta cheat menu'], size: 245760, modifiedAt: now },
        { path: 'HKCU\\...\\Uninstall\\Nightfall', fileName: 'Registry: Nightfall', type: 'registry', risk: 'high', matches: ['registry:nightfall installed'], size: 0, modifiedAt: now },
        { path: '~/Documents/Cheats/', fileName: 'mod_menu.lua', type: 'file', risk: 'medium', matches: ['lua:mod menu', 'script hook'], size: 8912, modifiedAt: now },
        { path: 'C:\\Windows\\Prefetch\\DMA_TOOL.EXE-*.pf', fileName: 'DMA_TOOL.EXE-*.pf', type: 'file', risk: 'medium', matches: ['prefetch:dma last run', 'process:dma'], size: 0, modifiedAt: now },
        { path: 'PCI Bus', fileName: 'Xilinx FPGA Device', type: 'hardware', risk: 'high', matches: ['pci:Xilinx (VEN_10ee)', 'FPGA device detected'], size: 0, modifiedAt: now },
        { path: 'Browser History', fileName: 'Chrome History', type: 'browser', risk: 'medium', matches: ['browser:nightfall', 'browser:dma', 'browser:cheat'], size: 4096, modifiedAt: now },
        { path: '~/Downloads/pcileech/', fileName: 'pcileech.exe', type: 'software', risk: 'high', matches: ['dma-software:pcileech.exe', 'DMA memory tool'], size: 0, modifiedAt: now },
      ],
      scanned: 1847,
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

// ── Component ──

export default function Checker({ lang, onBack }: CheckerProps) {
  const t = (key: string) => T[lang][key] || key
  const [activeTab, setActiveTab] = useState<ScanMode>('files')
  const [phase, setPhase] = useState<'idle' | 'scanning' | 'done'>('idle')
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [results, setResults] = useState<ScanResult[]>([])
  const [summary, setSummary] = useState<ScanResponse['summary'] | null>(null)
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')
  const [tabTransition, setTabTransition] = useState<'enter' | 'idle' | 'exit'>('idle')
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(['high']))
  const [showAllGroups, setShowAllGroups] = useState<Set<string>>(new Set())
  const [searchQuery, setSearchQuery] = useState('')
  const scanRef = useRef<boolean>(false)

  // Filtered results (client-side search, memoised)
  const filteredResults = useMemo(() => {
    const q = searchQuery.toLowerCase().trim()
    if (!q) return results
    return results.filter(r =>
      r.fileName.toLowerCase().includes(q) ||
      r.path.toLowerCase().includes(q) ||
      r.matches.some(m => m.toLowerCase().includes(q))
    )
  }, [results, searchQuery])
  const transitionTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const currentTab = TABS.find(t => t.id === activeTab)!
  const activeTabIndex = TABS.findIndex(t => t.id === activeTab)

  // Cleanup scan + transition timer on unmount
  useEffect(() => {
    return () => {
      scanRef.current = false
      if (transitionTimer.current) clearTimeout(transitionTimer.current)
    }
  }, [])

  const handleStartScan = useCallback(async () => {
    const api = window.electronAPI

    // Prevent double-start
    if (scanRef.current) return
    scanRef.current = true

    setPhase('scanning')
    setError('')
    setResults([])
    setSummary(null)
    setSelectedResult(null)
    setProgress(null)

    if (!api?.startScan) {
      for (let i = 0; i <= 100; i += 10) {
        if (!scanRef.current) return // aborted by tab switch
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
      setPhase('done')
      scanRef.current = false
      return
    }

    // Real scan
    const progressHandler = (data: ScanProgress) => {
      if (scanRef.current) setProgress({ ...data })
    }
    api.onScanProgress(progressHandler)

    try {
      const response = await api.startScan(activeTab)
      if (scanRef.current) {
        setResults(response.results)
        setSummary(response.summary)
        setPhase('done')
      }
    } catch (err) {
      if (scanRef.current) {
        setError(err instanceof Error ? err.message : 'Scan error')
        setPhase('idle')
      }
    } finally {
      scanRef.current = false
    }
  }, [activeTab, currentTab])

  const handleClear = useCallback(() => {
    setResults([])
    setSummary(null)
    setProgress(null)
    setSelectedResult(null)
    setPhase('idle')
    scanRef.current = false
    setExpandedGroups(new Set(['high']))
    setShowAllGroups(new Set())
    setSearchQuery('')
  }, [])

  const handleTabChange = useCallback((tab: ScanMode) => {
    if (tab === activeTab) return
    // Abort any running scan
    scanRef.current = false

    // Start exit animation
    setTabTransition('exit')
    if (transitionTimer.current) clearTimeout(transitionTimer.current)

    transitionTimer.current = setTimeout(() => {
      setActiveTab(tab)
      setPhase('idle')
      setResults([])
      setSummary(null)
      setProgress(null)
      setSelectedResult(null)
      setError('')
      setSearchQuery('')

      // Start enter animation after state is updated
      setTabTransition('enter')
      setTimeout(() => setTabTransition('idle'), 200)
    }, 150)
  }, [activeTab])

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const formatTime = (ms: number) => {
    if (ms < 1000) return `${ms} ms`
    return `${(ms / 1000).toFixed(1)} ${t('sec')}`
  }

  const riskClass = (risk: string) =>
    risk === 'high' ? 'risk-high' : risk === 'medium' ? 'risk-medium' : 'risk-low'

  const riskLabel = (risk: string) =>
    risk === 'high' ? t('high') : risk === 'medium' ? t('medium') : t('low')

  const typeIcon = (type: string) => {
    switch (type) {
      case 'file': return '📄'
      case 'browser': return '🌐'
      case 'process': return '⚙️'
      case 'registry': return '📋'
      case 'hardware': return '🔌'
      case 'software': return '💻'
      case 'system': return '🖥️'
      default: return '📄'
    }
  }

  const typeName = (type: string) => {
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

  const calcPercent = () => {
    if (!progress) return 0
    if (progress.phase === 'done') return 100
    // Анализ: 85-99% (зависит от количества найденного)
    if (progress.phase === 'analyzing') return 85 + Math.min(progress.filesFound * 2, 14)

    // Сканирование: 0-84% — монотонно, без сбросов
    // dirsDone/totalDirs — вклад пройденных директорий (0-70%)
    // filesScanned — плавный вклад внутри и между директориями (0-14%)
    const dirWeight = progress.totalDirs > 0
      ? Math.min(progress.dirsDone / progress.totalDirs, 1)
      : 0
    // filesScanned монотонно растёт, не сбрасывается каждые 100
    const fileWeight = Math.min(progress.filesScanned / 300, 1)

    return Math.min(dirWeight * 70 + fileWeight * 14, 84)
  }

  return (
    <div className="checker-wrapper">
      <div className="checker-header">
        <div className="checker-title-row">
          <button className="checker-back-btn" onClick={onBack} title="Back">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </button>
          <h2 className="checker-title">{t('title')}</h2>
          <div className="checker-status-dot" data-phase={phase} />
        </div>
      </div>

      {/* Tabs */}
      <div className="checker-tabs" role="tablist">
        {TABS.map(tab => (
          <button
            key={tab.id}
            className={`checker-tab${activeTab === tab.id ? ' active' : ''}`}
            onClick={() => handleTabChange(tab.id)}
            role="tab"
            aria-selected={activeTab === tab.id}
            data-color={tab.color}
            style={{ '--tab-accent': tab.color } as React.CSSProperties}
          >
            <span className="checker-tab-icon">{tab.icon}</span>
            <div className="checker-tab-text">
              <span className="checker-tab-label">{t(tab.label)}</span>
              <span className="checker-tab-desc">{t(tab.desc)}</span>
            </div>
          </button>
        ))}
      </div>

      <p className="checker-desc" style={{ marginBottom: 16 }}>{t(currentTab.desc)}</p>

      {/* Tab content with transitions */}
      <div className={`tab-content${tabTransition === 'exit' ? ' exit' : ''}${tabTransition === 'enter' ? ' enter' : ''}`}>

      {/* Idle */}
      {phase === 'idle' && (
        <div className="checker-idle">
          <div className="checker-idle-icon" style={{ animationDelay: `${activeTabIndex * -0.8}s` }}>{currentTab.icon}</div>
          <button className="checker-start-btn" data-tab={activeTab} onClick={handleStartScan}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
            </svg>
            {t('startBtn')}
          </button>
        </div>
      )}

      {/* Scanning */}
      {phase === 'scanning' && (
        <div className="checker-scanning">
          <div className="checker-radar">
            <div className="radar-ring" />
            <div className="radar-ring" />
            <div className="radar-ring" />
            <div className="radar-dot" />
          </div>

          <div className="checker-progress-header">
            <span className="checker-progress-label">
              <span key={progress?.phase || 'scanning'} className="progress-label-text">
                {progress?.phase === 'analyzing' ? t('analyzing') : t('scanning')}
              </span>
            </span>
            <span className="checker-progress-pct"><span key={Math.round(calcPercent())} className="pct-num">{Math.round(calcPercent())}</span>%</span>
          </div>

          <div className="checker-progress-bar">
            <div className="checker-progress-fill" style={{ width: `${calcPercent()}%` }} />
          </div>

          <div className="checker-progress-info">
            <span>{t('found')}: <span key={progress?.filesFound ?? 0} className="found-num">{progress?.filesFound || 0}</span></span>
            <span>{progress?.filesScanned || 0} {t('filesScanned')}</span>
          </div>

          {progress?.currentDir && (
            <div className="checker-current-dir">{progress.currentDir}</div>
          )}
        </div>
      )}

      {/* Error */}
      {error && <div className="checker-error">{error}</div>}

      {/* Results */}
      {phase === 'done' && (
        <div className="checker-results">
          {summary && (
            <div className="checker-summary stagger-summary">
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
              <div className="checker-summary-text">
                {summary.suspiciousFiles > 0
                  ? `${summary.suspiciousFiles} ${t('threatsFound')}`
                  : t('noThreats')}
              </div>
              <div className="checker-summary-stats">
                <span>{summary.totalScanned} {t('filesScanned')}</span>
                <span className="checker-summary-dot">•</span>
                <span>{t('time')}: {formatTime(summary.scanTimeMs)}</span>
              </div>
            </div>
          )}

          {/* Search input — only show when there are results */}
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
            <div className="checker-groups">
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
                  <div key={riskLevel} className={`result-group group-${riskLevel}`}>
                    {/* Group header */}
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

                    {/* Collapsible body */}
                    {isExpanded && (
                      <div className="group-body">
                        {visible.map((r, i) => (
                          <div key={`${r.path}-${i}`}
                            className={`result-row`}
                            style={{ animationDelay: `${i * 0.06}s` }}
                            onClick={() => setSelectedResult(
                              selectedResult?.path === r.path && selectedResult?.fileName === r.fileName ? null : r
                            )}
                          >
                            <div className="result-row-main">
                              <span className="result-icon" title={typeName(r.type)}>{typeIcon(r.type)}</span>
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
                              <span className="result-expand">{selectedResult?.path === r.path && selectedResult?.fileName === r.fileName ? '▲' : '▼'}</span>
                            </div>

                            {/* Detail panel */}
                            {selectedResult?.path === r.path && selectedResult?.fileName === r.fileName && (
                              <div className="result-detail">
                                <div className="result-detail-row">
                                  <span className="detail-label">{t('path')}</span>
                                  <span className="detail-value path">{r.path}</span>
                                </div>
                                {r.size > 0 && (
                                  <div className="result-detail-row">
                                    <span className="detail-label">Size</span>
                                    <span className="detail-value">{formatSize(r.size)}</span>
                                  </div>
                                )}
                                <div className="result-detail-row">
                                  <span className="detail-label">{t('matches')}</span>
                                  <div className="detail-tags">
                                    {r.matches.map((m, j) => (
                                      <span key={j} className="match-tag">{m}</span>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            )}
                          </div>
                        ))}

                        {/* Show more / collapse */}
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
                      </div>
                    )}
                  </div>
                )
              })
              ) : (
                searchQuery && <div className="search-no-results">{t('searchNoResults')}</div>
              )}
            </div>
          )}

          <div className="checker-actions">
            <button className="checker-action-btn secondary" onClick={handleClear}>{t('clear')}</button>
            <button className="checker-action-btn primary" onClick={handleStartScan}>{t('scanAgain')}</button>
          </div>
        </div>
      )}
      </div>{/* /tab-content */}
    </div>
  )
}
