import { useState, useCallback, useEffect, useMemo, memo } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import type { ScanResult, ScanResponse } from '../../types/electron'
import { groupResults } from '../../utils/result-grouper'
import { Button } from './Button'
import PredatorLogo3D from './PredatorLogo3D'
import { ThreatMap } from './ThreatMap'
import { ApcDashboard } from './ApcDashboard'
import {
  IconFolder, IconGear, IconUSB,
  IconGlobe, IconRegistry, IconMonitor, IconLock, IconDNA, IconChart,
} from '../../icons'
import { Tooltip } from './Tooltip'

// ── Types ──

type RiskFilter = 'critical' | 'high' | 'medium' | 'low'
type TypeFilter = 'file' | 'process' | 'registry' | 'browser' | 'hardware' | 'software' | 'system'
type SourceFilter = typeof ALL_SOURCES[number]
const ALL_SOURCES = ['process', 'file', 'registry', 'browser', 'dma', 'network', 'forensic', 'prefetch', 'heuristic'] as const

interface ResultsViewProps {
  results: ScanResult[]
  summary: ScanResponse['summary'] | null
  lang: 'ru' | 'en'
  accent: string
  light: string
  dark: string
  selectedResult: ScanResult | null
  onSelectResult: (result: ScanResult, event: React.MouseEvent<HTMLElement>) => void
  onClear: () => void
  exportMsg: string
  copiedPath: string
  onCopyPath: (path: string) => void
  telegramSending: boolean
  onExportHtml: () => void
  onExportJson: () => void
  onExportMd: () => void
  onExportPdf: () => void
  onTelegramExport: () => void
}

// ── Translations ──

const T: Record<string, Record<string, string>> = {
  ru: {
    // Summary
    done: 'Проверка завершена',
    found: 'Найдено',
    noThreats: 'Подозрительных элементов не обнаружено',
    threatsFound: 'обнаружено',
    filesScanned: 'просканировано',
    time: 'Время', sec: 'сек',
    scanInconclusive: 'Проверка завершена не полностью',
    scanInconclusiveHint: 'Некоторые модули не смогли получить данные. Результат нельзя считать подтверждённо чистым.',
    // Filters
    filterRisk: 'Риск',
    filterType: 'Тип',
    filterSource: 'Источник',
    searchPlaceholder: 'Поиск по имени, пути или совпадениям...',
    searchNoResults: 'Ничего не найдено',
    // Risk labels
    critical: 'Крит.',
    high: 'Высокий',
    medium: 'Средний',
    low: 'Низкий',
    // Type labels
    typeFile: 'Файл', typeBrowser: 'Браузер', typeProcess: 'Процесс',
    typeRegistry: 'Реестр', typeHardware: 'Оборудование', typeSoftware: 'ПО', typeSystem: 'Система',
    // Source labels
    srcProcess: 'Процессы', srcFile: 'Файлы', srcRegistry: 'Реестр',
    srcBrowser: 'Браузер', srcDma: 'DMA', srcNetwork: 'Сеть',
    srcForensic: 'Форензика', srcPrefetch: 'Prefetch', srcHeuristic: 'Эвристика',
    // Groups
    groupCritical: 'Критический риск', groupHigh: 'Высокий риск',
    groupMedium: 'Средний риск', groupLow: 'Низкий риск',
    showAll: 'Показать все', collapse: 'Свернуть', groupHidden: 'ещё скрыто',
    // Cheats
    cheatsFound: 'Найдено следов читов',
    cheatFilesUnit: 'файлов', cheatProcUnit: 'процессов', cheatRegUnit: 'реестр',
    cheatBrowserUnit: 'браузер', cheatHwUnit: 'устройств', cheatOtherUnit: 'другое',
    cheatConfidence: 'уверенность',
    cheatOtherActivity: 'Другая подозрительная активность',
    // Devices
    devicesTitle: 'Подключенные устройства',
    devicesSafe: 'Обычные устройства',
    devicesSuspicious: '⚠ Подозрительные устройства',
    devicesHistory: '⏳ История DMA',
    // Detail
    path: 'Путь', file: 'Файл', matches: 'Совпадения', risk: 'Риск',
    // Actions
    clear: 'Очистить', exportReport: 'Экспорт',
    exportHtml: 'HTML отчёт', exportJson: 'JSON отчёт',
  },
  en: {
    done: 'Scan complete', found: 'Found', noThreats: 'No suspicious items detected',
    threatsFound: 'found', filesScanned: 'scanned', time: 'Time', sec: 'sec',
    scanInconclusive: 'Scan completed with gaps',
    scanInconclusiveHint: 'Some modules could not collect data. This result is not confirmed clean.',
    filterRisk: 'Risk', filterType: 'Type', filterSource: 'Source',
    searchPlaceholder: 'Search by name, path or matches...', searchNoResults: 'Nothing found',
    critical: 'Crit.', high: 'High', medium: 'Medium', low: 'Low',
    typeFile: 'File', typeBrowser: 'Browser', typeProcess: 'Process',
    typeRegistry: 'Registry', typeHardware: 'Hardware', typeSoftware: 'Software', typeSystem: 'System',
    srcProcess: 'Processes', srcFile: 'Files', srcRegistry: 'Registry',
    srcBrowser: 'Browser', srcDma: 'DMA', srcNetwork: 'Network',
    srcForensic: 'Forensic', srcPrefetch: 'Prefetch', srcHeuristic: 'Heuristic',
    groupCritical: 'Critical risk', groupHigh: 'High risk',
    groupMedium: 'Medium risk', groupLow: 'Low risk',
    showAll: 'Show all', collapse: 'Collapse', groupHidden: 'more hidden',
    cheatsFound: 'Cheat traces found',
    cheatFilesUnit: 'files', cheatProcUnit: 'processes', cheatRegUnit: 'registry',
    cheatBrowserUnit: 'browser', cheatHwUnit: 'hardware', cheatOtherUnit: 'other',
    cheatConfidence: 'confidence', cheatOtherActivity: 'Other suspicious activity',
    devicesTitle: 'Connected Devices', devicesSafe: 'Normal Devices',
    devicesSuspicious: '⚠ Suspicious Devices', devicesHistory: '⏳ DMA History',
    path: 'Path', file: 'File', matches: 'Matches', risk: 'Risk',
    clear: 'Clear', exportReport: 'Export', exportHtml: 'HTML Report', exportJson: 'JSON Report',
  },
}

// ── Helpers ──

const INITIAL_SHOW = 5

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(ms: number, secLabel: string): string {
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(1)} ${secLabel}`
}

function riskLabel(risk: ScanResult['risk'], lang: 'ru' | 'en'): string {
  if (risk === 'critical') return lang === 'ru' ? 'Крит.' : 'Crit.'
  return T[lang][risk] || risk
}

function typeName(type: string, lang: 'ru' | 'en'): string {
  const key = `type${type.charAt(0).toUpperCase()}${type.slice(1)}` as keyof typeof T['en']
  return T[lang][key] || type
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

function extractSources(result: ScanResult): SourceFilter[] {
  const sources = new Set<SourceFilter>()
  for (const match of result.matches) {
    const m = match.toLowerCase()
    if (m.startsWith('process:')) sources.add('process')
    else if (m.startsWith('file:') || m.startsWith('folder:') || m.startsWith('lua:') || m.startsWith('archive:')) sources.add('file')
    else if (m.startsWith('registry') || m.startsWith('hkc') || m.startsWith('hklm')) sources.add('registry')
    else if (m.startsWith('browser:') || m.includes('browser history')) sources.add('browser')
    else if (m.startsWith('dma') || m.startsWith('pci:') || m.includes('fpga')) sources.add('dma')
    else if (m.startsWith('network') || m.startsWith('wmi') || m.startsWith('pipe')) sources.add('network')
    else if (m.startsWith('usn-') || m.startsWith('shellbags') || m.startsWith('timestomp') || m.startsWith('hwid')) sources.add('forensic')
    else if (m.startsWith('prefetch')) sources.add('prefetch')
    else if (m.startsWith('yara') || m.startsWith('content:') || m.startsWith('signatures') || m.startsWith('binary-sig:') || m.includes('entropy')) sources.add('heuristic')
  }
  // Fallback: use result type as source
  if (sources.size === 0) {
    if (result.type === 'process') sources.add('process')
    else if (result.type === 'file' || result.type === 'software') sources.add('file')
    else if (result.type === 'registry') sources.add('registry')
    else if (result.type === 'browser') sources.add('browser')
    else if (result.type === 'hardware') sources.add('dma')
    else if (result.type === 'system') sources.add('forensic')
  }
  return [...sources]
}

// ── Filter Chip ──

const FilterChip = memo(function FilterChip({
  label, active, onClick, color,
}: { label: string; active: boolean; onClick: () => void; color?: string }) {
  return (
    <button
      type="button"
      className={`results-filter-chip${active ? ' active' : ''}`}
      onClick={onClick}
      style={active && color ? { '--chip-color': color } as React.CSSProperties : undefined}
    >
      {label}
    </button>
  )
})

// ── Main Component ──

export function ResultsView({
  results, summary, lang, accent, light, dark,
  selectedResult, onSelectResult, onClear,
  exportMsg, copiedPath, onCopyPath, telegramSending,
  onExportHtml, onExportJson, onExportMd, onExportPdf, onTelegramExport,
}: ResultsViewProps) {
  const prefersReducedMotion = useReducedMotion()
  const t = useMemo(() => (key: string) => T[lang][key] || key, [lang])

  // Filter state — all active by default
  const [riskFilters, setRiskFilters] = useState<Set<RiskFilter>>(new Set(['critical', 'high', 'medium', 'low']))
  const [typeFilters, setTypeFilters] = useState<Set<TypeFilter>>(new Set(['file', 'process', 'registry', 'browser', 'hardware', 'software', 'system']))
  const [sourceFilters, setSourceFilters] = useState<Set<SourceFilter>>(new Set(ALL_SOURCES))
  const [searchQuery, setSearchQuery] = useState('')

  // Display state
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set(['critical', 'high']))
  const [showAllGroups, setShowAllGroups] = useState<Set<string>>(new Set())
  const [cheatExpandedGroups, setCheatExpandedGroups] = useState<Set<string>>(new Set())
  const [showOtherItems, setShowOtherItems] = useState(false)
  const [showSafeDevices, setShowSafeDevices] = useState(false)
  // Auto-expand high-risk cheat groups on first render
  const groupedResults = useMemo(() => groupResults(results), [results])
  useEffect(() => {
    if (groupedResults.cheatGroups.length > 0 && cheatExpandedGroups.size === 0) {
      const highRisk = groupedResults.cheatGroups.filter(g => g.risk === 'high').map(g => g.cheatName)
      if (highRisk.length > 0) setCheatExpandedGroups(new Set(highRisk))
    }
  }, [groupedResults.cheatGroups, cheatExpandedGroups.size])

  const itemVariants = prefersReducedMotion
    ? { hidden: {}, visible: {} }
    : { hidden: { opacity: 0 }, visible: { opacity: 1, transition: { duration: 0.3 } } }

  const containerVariants = prefersReducedMotion
    ? { hidden: {}, visible: {} }
    : { hidden: {}, visible: { transition: { staggerChildren: 0.03 } } }

  // ── Filter toggle helpers ──
  const toggleRisk = useCallback((r: RiskFilter) => {
    setRiskFilters(prev => { const next = new Set(prev); if (next.has(r)) next.delete(r); else next.add(r); return next })
  }, [])
  const toggleType = useCallback((tp: TypeFilter) => {
    setTypeFilters(prev => { const next = new Set(prev); if (next.has(tp)) next.delete(tp); else next.add(tp); return next })
  }, [])
  const toggleSource = useCallback((s: SourceFilter) => {
    setSourceFilters(prev => { const next = new Set(prev); if (next.has(s)) next.delete(s); else next.add(s); return next })
  }, [])

  // ── Filtered results ──
  const filteredResults = useMemo(() => {
    let filtered = results

    // Risk filter
    filtered = filtered.filter(r => riskFilters.has(r.risk))

    // Type filter
    filtered = filtered.filter(r => typeFilters.has(r.type as TypeFilter))

    // Source filter
    if (sourceFilters.size < ALL_SOURCES.length) {
      filtered = filtered.filter(r => {
        const sources = extractSources(r)
        return sources.some(s => sourceFilters.has(s))
      })
    }

    // Search
    const q = searchQuery.toLowerCase().trim()
    if (q) {
      filtered = filtered.filter(r =>
        r.fileName.toLowerCase().includes(q) ||
        r.path.toLowerCase().includes(q) ||
        r.matches.some(m => m.toLowerCase().includes(q))
      )
    }

    return filtered
  }, [results, riskFilters, typeFilters, sourceFilters, searchQuery])

  const isInconclusive = summary?.status === 'inconclusive'

  // ── Risk chip colors ──
  const riskColors: Record<RiskFilter, string> = {
    critical: 'var(--accent-red)',
    high: '#ef4444',
    medium: 'var(--color-warning)',
    low: '#6b7280',
  }

  // ── Active filter count (for badge) ──
  const activeFilterCount = (4 - riskFilters.size) + (7 - typeFilters.size) + (ALL_SOURCES.length - sourceFilters.size)

  return (
    <div className="results-view" data-testid="checker-results">
      {/* ── Summary ── */}
      {summary && (
        <div className={`checker-summary card-section${summary.suspiciousFiles > 0 ? ' warning-active' : isInconclusive ? ' warning-active inconclusive' : ' safe'}`}>
          <div className={`checker-summary-icon ${summary.suspiciousFiles > 0 || isInconclusive ? 'warning' : 'safe'}`}>
            {summary.suspiciousFiles > 0 || isInconclusive ? (
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            ) : (
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
              </svg>
            )}
          </div>
          {isInconclusive && (
            <div className="checker-empty-state checker-inconclusive-state" role="status" style={{ marginBottom: 12 }}>
              <div className="checker-empty-title">{t('scanInconclusive')}</div>
              <div className="checker-empty-desc">{t('scanInconclusiveHint')}</div>
              {summary.diagnostics && summary.diagnostics.length > 0 && (
                <div className="checker-inconclusive-details">
                  {summary.diagnostics.map(d => d.errorMessage || d.errorCode || d.detectorId).join(' · ')}
                </div>
              )}
            </div>
          )}
          {summary.suspiciousFiles > 0 ? (
            <div className="checker-summary-text" style={{ marginBottom: 8 }}>
              {`${summary.suspiciousFiles} ${t('threatsFound')}`}
            </div>
          ) : !isInconclusive ? (
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
          ) : null}
          <div className="checker-summary-stats" style={{ animation: 'phaseFadeIn 0.5s 0.3s var(--ease-out) both' }}>
            <span>{summary.totalScanned} {t('filesScanned')}</span>
            <span className="checker-summary-dot">•</span>
            <span>{t('time')}: {formatTime(summary.scanTimeMs, t('sec'))}</span>
          </div>
        </div>
      )}

      {/* ── ThreatMap + ApcDashboard ── */}
      {results.length > 0 && summary && summary.suspiciousFiles > 0 && (
        <>
          <ThreatMap results={results} />
          <ApcDashboard results={results} lang={lang} />
        </>
      )}

      {/* ════════════════════════════════════════════
          FILTER BAR
          ════════════════════════════════════════════ */}
      {results.length > 0 && (
        <div className="results-filter-bar">
          {/* Search */}
          <div className="results-search">
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

          {/* Filter row */}
          <div className="results-filter-row">
            {/* Risk */}
            <div className="results-filter-group">
              <span className="results-filter-label">{t('filterRisk')}</span>
              <div className="results-filter-chips">
                {(['critical', 'high', 'medium', 'low'] as RiskFilter[]).map(r => (
                  <FilterChip key={r} label={t(r)} active={riskFilters.has(r)} onClick={() => toggleRisk(r)} color={riskColors[r]} />
                ))}
              </div>
            </div>

            {/* Type */}
            <div className="results-filter-group">
              <span className="results-filter-label">{t('filterType')}</span>
              <div className="results-filter-chips">
                {(['file', 'process', 'registry', 'browser', 'hardware', 'software', 'system'] as TypeFilter[]).map(tp => (
                  <FilterChip key={tp} label={t(`type${tp.charAt(0).toUpperCase()}${tp.slice(1)}`)} active={typeFilters.has(tp)} onClick={() => toggleType(tp)} />
                ))}
              </div>
            </div>

            {/* Source */}
            <div className="results-filter-group">
              <span className="results-filter-label">{t('filterSource')}</span>
              <div className="results-filter-chips">
                {([...ALL_SOURCES] as SourceFilter[]).map(s => (
                  <FilterChip key={s} label={t(`src${s.charAt(0).toUpperCase()}${s.slice(1)}`)} active={sourceFilters.has(s)} onClick={() => toggleSource(s)} />
                ))}
              </div>
            </div>
          </div>

          {/* Active filter count + clear all */}
          {activeFilterCount > 0 && (
            <div className="results-filter-info">
              <span>{filteredResults.length} / {results.length} {lang === 'ru' ? 'результатов' : 'results'}</span>
              <button type="button" className="results-filter-reset" onClick={() => {
                setRiskFilters(new Set(['critical', 'high', 'medium', 'low']))
                setTypeFilters(new Set(['file', 'process', 'registry', 'browser', 'hardware', 'software', 'system']))
                setSourceFilters(new Set(ALL_SOURCES))
              }}>
                {lang === 'ru' ? 'Сбросить фильтры' : 'Reset filters'}
              </button>
            </div>
          )}
        </div>
      )}

      {/* ════════════════════════════════════════════
          DEVICES SECTION
          ════════════════════════════════════════════ */}
      {(groupedResults.deviceSummary.hasSuspiciousDevices || groupedResults.deviceSummary.hasDmaHistory || groupedResults.deviceSummary.connectedSafe.length > 0) && (
        <div className="devices-section">
          <div className="devices-header">
            <span className="devices-title">🔌 {t('devicesTitle')}</span>
          </div>

          {groupedResults.deviceSummary.connectedSuspicious.length > 0 && (
            <div className="devices-group suspicious">
              <div className="devices-group-header">
                <span>{t('devicesSuspicious')} ({groupedResults.deviceSummary.connectedSuspicious.length})</span>
              </div>
              {groupedResults.deviceSummary.connectedSuspicious.map((r, i) => (
                <div key={`dma-${i}`} className="device-item danger" onClick={(e) => onSelectResult(r, e)}>
                  <span className="device-item-icon">⚠️</span>
                  <div className="device-item-info">
                    <span className="device-item-name">{r.fileName}</span>
                    {r.matches.slice(0, 2).map((m, j) => <span key={j} className="device-item-detail">{m}</span>)}
                  </div>
                  <span className="device-item-risk high">HIGH</span>
                </div>
              ))}
            </div>
          )}

          {groupedResults.deviceSummary.dmaHistory.length > 0 && (
            <div className="devices-group history">
              <div className="devices-group-header">
                <span>{t('devicesHistory')} ({groupedResults.deviceSummary.dmaHistory.length})</span>
              </div>
              {groupedResults.deviceSummary.dmaHistory.map((r, i) => (
                <div key={`dmah-${i}`} className="device-item warning" onClick={(e) => onSelectResult(r, e)}>
                  <span className="device-item-icon">⏳</span>
                  <div className="device-item-info">
                    <span className="device-item-name">{r.fileName}</span>
                    {r.matches.slice(0, 2).map((m, j) => <span key={j} className="device-item-detail">{m}</span>)}
                  </div>
                  <span className="device-item-risk high">WAS CONNECTED</span>
                </div>
              ))}
            </div>
          )}

          {groupedResults.deviceSummary.connectedSafe.length > 0 && (
            <div className="devices-group safe">
              <div className="devices-group-header" style={{ cursor: 'pointer' }} onClick={() => setShowSafeDevices(o => !o)}>
                <span>{t('devicesSafe')} ({groupedResults.deviceSummary.connectedSafe.length})</span>
                <span className={`cheat-group-chevron ${showSafeDevices ? 'open' : ''}`}>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9" /></svg>
                </span>
              </div>
              {showSafeDevices && (
                <div className="devices-safe-list">
                  {groupedResults.deviceSummary.connectedSafe.map((r, i) => (
                    <div key={`safe-${i}`} className="device-item safe" onClick={(e) => onSelectResult(r, e)}>
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

      {/* ════════════════════════════════════════════
          CHEAT GROUPS
          ════════════════════════════════════════════ */}
      {groupedResults.cheatGroups.length > 0 && (
        <div className="cheat-groups-section">
          <div className="cheat-groups-header">
            <span className="cheat-groups-title">🎯 {t('cheatsFound')}: {groupedResults.summary.totalCheatsDetected}</span>
            <span className="cheat-groups-subtitle">
              {groupedResults.summary.totalHighRisk} HIGH · {groupedResults.summary.totalMediumRisk} MEDIUM
            </span>
          </div>
          {groupedResults.cheatGroups.map(group => {
            const isExpanded = cheatExpandedGroups.has(group.cheatName)
            const toggleGroup = () => setCheatExpandedGroups(prev => {
              const next = new Set(prev)
              if (next.has(group.cheatName)) next.delete(group.cheatName); else next.add(group.cheatName)
              return next
            })
            const parts: string[] = []
            if (group.counts.files > 0) parts.push(`${group.counts.files} ${t('cheatFilesUnit')}`)
            if (group.counts.processes > 0) parts.push(`${group.counts.processes} ${t('cheatProcUnit')}`)
            if (group.counts.registry > 0) parts.push(`${group.counts.registry} ${t('cheatRegUnit')}`)
            if (group.counts.browser > 0) parts.push(`${group.counts.browser} ${t('cheatBrowserUnit')}`)
            if (group.counts.hardware > 0) parts.push(`${group.counts.hardware} ${t('cheatHwUnit')}`)
            if (group.counts.other > 0) parts.push(`${group.counts.other} ${t('cheatOtherUnit')}`)
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
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9" /></svg>
                    </span>
                  </div>
                </button>
                <div className="cheat-group-meta">
                  <span className="cheat-group-summary">{parts.join(', ')}</span>
                  <span className="cheat-group-confidence" style={{ color: confColor }}>{group.confidence}% {t('cheatConfidence')}</span>
                </div>
                {isExpanded && (
                  <div className="cheat-group-body">
                    {group.tags.length > 0 && (
                      <div className="cheat-group-tags">{group.tags.map((tag, i) => <span key={i} className="cheat-group-tag">{tag}</span>)}</div>
                    )}
                    {group.findings.map((r, i) => (
                      <div key={`${r.path}-${i}`}
                        className={`cheat-group-item${selectedResult?.path === r.path && selectedResult?.fileName === r.fileName ? ' selected' : ''}`}
                        data-risk={r.risk} onClick={(e) => onSelectResult(r, e)}
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

      {/* ════════════════════════════════════════════
          OTHER ITEMS (ungrouped)
          ════════════════════════════════════════════ */}
      {(groupedResults.otherHigh.length > 0 || groupedResults.otherMedium.length > 0) && (
        <div className="cheat-other-section">
          <button className="cheat-other-header" onClick={() => setShowOtherItems(o => !o)}>
            <span>🔍 {t('cheatOtherActivity')} ({groupedResults.otherHigh.length + groupedResults.otherMedium.length})</span>
            <span className={`cheat-group-chevron ${showOtherItems ? 'open' : ''}`}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9" /></svg>
            </span>
          </button>
          {showOtherItems && (
            <div className="cheat-other-body">
              {[...groupedResults.otherHigh, ...groupedResults.otherMedium].map((r, i) => (
                <div key={`other-${i}`}
                  className={`result-row${selectedResult?.path === r.path && selectedResult?.fileName === r.fileName ? ' selected' : ''}`}
                  data-risk={r.risk} onClick={(e) => onSelectResult(r, e)}
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

      {/* ════════════════════════════════════════════
          RESULTS SPLIT: Groups + Detail panel
          ════════════════════════════════════════════ */}
      {results.length > 0 && (
        <div className="checker-results-split">
          <div className="checker-results-list">
            <motion.div className="checker-groups" variants={containerVariants} initial="hidden" animate="visible">
              {filteredResults.length > 0 ? (
                (['critical', 'high', 'medium', 'low'] as const).map(riskLevel => {
                  const group = filteredResults.filter(r => r.risk === riskLevel)
                  if (group.length === 0) return null
                  const isExpanded = expandedGroups.has(riskLevel)
                  const isShowAll = showAllGroups.has(riskLevel)
                  const visible = isShowAll ? group : group.slice(0, INITIAL_SHOW)
                  const hidden = group.length - INITIAL_SHOW

                  return (
                    <motion.div key={riskLevel} className={`result-group group-${riskLevel}`} variants={itemVariants}>
                      <button className="group-header" onClick={() => setExpandedGroups(prev => {
                        const next = new Set(prev)
                        if (next.has(riskLevel)) next.delete(riskLevel); else next.add(riskLevel)
                        return next
                      })}>
                        <div className="group-header-left">
                          <span className={`group-risk-dot dot-${riskLevel}`} />
                          <span className="group-title">{t(`group${riskLevel.charAt(0).toUpperCase()}${riskLevel.slice(1)}`)}</span>
                        </div>
                        <div className="group-header-right">
                          <span className="group-count">{group.length}</span>
                          <span className={`group-chevron ${isExpanded ? 'open' : ''}`}>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9" /></svg>
                          </span>
                        </div>
                      </button>
                      {isExpanded && (
                        <motion.div className="group-body" variants={containerVariants} initial="hidden" animate="visible">
                          {visible.map((r, i) => (
                            <motion.div key={`${r.path}-${i}`}
                              className={`result-row${selectedResult?.path === r.path && selectedResult?.fileName === r.fileName ? ' selected' : ''}`}
                              data-risk={r.risk} variants={itemVariants} onClick={(e) => onSelectResult(r, e)}
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
                            <button className="group-show-btn" onClick={() => setShowAllGroups(prev => {
                              const next = new Set(prev); next.add(riskLevel); return next
                            })}>
                              {t('showAll')} {group.length} ({hidden} {t('groupHidden')})
                            </button>
                          )}
                          {isShowAll && group.length > INITIAL_SHOW && (
                            <button className="group-show-btn collapse" onClick={() => setShowAllGroups(prev => {
                              const next = new Set(prev); next.delete(riskLevel); return next
                            })}>
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

          {/* Detail panel */}
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
                      onClick={() => onCopyPath(selectedResult.path)}
                    >
                      {copiedPath === selectedResult.path ? '✓' : '📋'}
                    </button>
                  </div>
                  {selectedResult.size > 0 && (
                    <div className="checker-detail-section">
                      <span className="checker-detail-label">{lang === 'ru' ? 'Размер' : 'Size'}</span>
                      <span className="checker-detail-value">{formatSize(selectedResult.size)}</span>
                    </div>
                  )}
                  <div className="checker-detail-section">
                    <span className="checker-detail-label">{t('matches')}</span>
                    <div className="result-matches" style={{ flexWrap: 'wrap' }}>
                      {selectedResult.matches.map((m, j) => (
                        <span key={j} className="match-tag">{m}</span>
                      ))}
                    </div>
                  </div>
                  {selectedResult.riskExplanation && (
                    <div className="checker-detail-section">
                      <span className="checker-detail-label">{t('risk')}</span>
                      <span className="checker-detail-value">{selectedResult.riskExplanation}</span>
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="checker-detail-empty">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
                  <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
                </svg>
                <span>{lang === 'ru' ? 'Выберите результат для просмотра деталей' : 'Select a result to view details'}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ════════════════════════════════════════════
          ACTION BAR
          ════════════════════════════════════════════ */}
      {results.length > 0 && (
        <div className="checker-actions" style={{ display: 'flex', gap: 8, marginTop: 16 }}>
          <Button variant="ghost" size="sm" onClick={onClear}>{t('clear')}</Button>
          <Tooltip content={lang === 'ru' ? 'HTML-отчёт с графиками для модератора' : 'HTML report with charts for moderators'}>
            <Button variant="ghost" size="sm" onClick={onExportHtml}>{t('exportHtml')}</Button>
          </Tooltip>
          <Tooltip content={lang === 'ru' ? 'JSON для серверной обработки' : 'JSON for server processing'}>
            <Button variant="ghost" size="sm" onClick={onExportJson}>{t('exportJson')}</Button>
          </Tooltip>
          <Button variant="ghost" size="sm" onClick={onExportMd}>MD</Button>
          <Button variant="ghost" size="sm" onClick={onExportPdf}>PDF</Button>
          <Button variant="ghost" size="sm" onClick={onTelegramExport} disabled={telegramSending}>TG</Button>
          {exportMsg && <span className="export-msg">{exportMsg}</span>}
        </div>
      )}
    </div>
  )
}
