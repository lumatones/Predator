import { useState, useRef, useCallback, useMemo } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import type { ScanResult, ScanMode } from '../types/electron'
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
import { useCheckerScan } from '../hooks/useCheckerScan'
import { useCheckerTabs } from '../hooks/useCheckerTabs'
import { T, TABS, IconEraser } from './checker-config'
import type { TabConfig } from './checker-config'
import { tabCache } from './checker-config'
import {
  IconFolder, IconGear, IconCrosshair,
  IconUSB, IconShield, IconGlobe,
} from '../icons'

// ── Icon resolver ──

const iconMap: Record<string, React.FC<{ size?: number; color?: string; animated?: boolean }>> = {
  Folder: IconFolder, Gear: IconGear, Crosshair: IconCrosshair,
  USB: IconUSB, Shield: IconShield, Globe: IconGlobe, Eraser: IconEraser,
}

function renderTabIcon(tab: TabConfig, size: number, animated?: boolean) {
  const Icon = iconMap[tab.icon]
  return Icon ? <Icon size={size} color={tab.color} animated={animated} /> : tab.icon
}

// ── Props ──

interface CheckerProps {
  lang: 'ru' | 'en'
  tokenId: number | null
  onBack: () => void
  accent: string
  light: string
  dark: string
}

// ── Component ──

export default function Checker({ lang, tokenId, onBack, accent, light, dark }: CheckerProps) {
  const prefersReducedMotion = useReducedMotion()
  const { play: playSound } = useSound()

  // Translation helper
  const t = useMemo(() => (key: string) => T[lang][key] || key, [lang])

  // ── Scan + export hook ──
  const {
    scanState, exportState, scanRef,
    initFromCache, handleStartScan, handleClear,
    handleExport, handleExportPdf, handleTelegramExport,
  } = useCheckerScan({ t, tokenId, playSound })
  const { phase, progress, results, summary, error } = scanState
  const { exportMsg, telegramSending } = exportState

  // ── Tab switching hook ──
  const {
    activeTab, tabTransition, handleTabChange,
  } = useCheckerTabs({ phase, results, summary, scanRef, onInitFromCache: initFromCache })

  const currentTab = TABS.find(tab => tab.id === activeTab)!
  const activeTabIndex = TABS.findIndex(tab => tab.id === activeTab)

  // ── Local UI state ──
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null)
  const findingTriggerRef = useRef<HTMLElement | null>(null)
  const [detailModalOpen, setDetailModalOpen] = useState(false)
  const [compactMode, setCompactMode] = useState(false)
  const [copiedPath, setCopiedPath] = useState('')

  // Binary triage state
  const [triageReport, setTriageReport] = useState<BinaryTriageReport | null>(null)
  const [triageLoading, setTriageLoading] = useState(false)
  const [triageError, setTriageError] = useState('')

  // ── Callbacks ──

  const openFinding = useCallback((result: ScanResult, event: React.MouseEvent<HTMLElement>) => {
    findingTriggerRef.current = event.currentTarget
    setSelectedResult(result)
    setDetailModalOpen(true)
  }, [])

  const onCopyPath = useCallback((path: string) => {
    navigator.clipboard.writeText(path).catch(() => {})
    setCopiedPath(path)
    setTimeout(() => setCopiedPath(''), 2000)
  }, [])

  const onTabClick = useCallback((tab: ScanMode) => {
    playSound('tick')
    // Save current tab cache + clear transient UI state
    if (phase === 'done' && summary) {
      tabCache.set(activeTab, { results, summary })
    }
    setSelectedResult(null)
    handleTabChange(tab)
  }, [activeTab, phase, results, summary, playSound, handleTabChange])

  const onStartScan = useCallback(() => {
    handleStartScan(activeTab, t(currentTab.label))
  }, [activeTab, currentTab, t, handleStartScan])

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

  // ── Render ──
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
            onClick={() => onTabClick(tab.id)}
            role="tab"
            aria-selected={activeTab === tab.id}
            data-color={tab.color}
            style={{ '--tab-accent': tab.color, width: '100%' } as React.CSSProperties}
          >
            <span className="checker-tab-icon">{renderTabIcon(tab, 16)}</span>
            <div className="checker-tab-text">
              <span className="checker-tab-label">{t(tab.label)}</span>
              <span className="checker-tab-desc">{t(tab.desc)}</span>
            </div>
            {scanState.tabCounts.has(tab.id) && scanState.tabCounts.get(tab.id)! > 0 && (
              <span className="checker-tab-badge" style={{ '--tab-accent': tab.color } as React.CSSProperties}>
                {scanState.tabCounts.get(tab.id)}
              </span>
            )}
          </button>
          </Magnetic>
        ))}
      </div>

      {phase !== 'scanning' && <p className="checker-desc" style={{ marginBottom: 16 }}>{t(currentTab.desc)}</p>}

      {/* Skeleton during tab transitions */}
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

      {/* Tab content */}
      <div className={`tab-content${tabTransition === 'exit' ? ' exit' : ''}${tabTransition === 'enter' ? ' enter' : ''}`}>

      {/* Idle */}
      {phase === 'idle' && (
        <div className="checker-idle">
          <div className="checker-idle-icon" style={{ animationDelay: `${activeTabIndex * -0.8}s` }}>
            {renderTabIcon(currentTab, 24, true)}
          </div>
          <motion.button
            className="checker-start-btn"
            data-testid="checker-start-scan"
            onClick={onStartScan}
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
            <span className="binary-triage-launch-mark">{triageLoading ? '\u2026' : '\u2301'}</span>
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
            <Tooltip content={lang === 'ru' ? '\u041a\u043e\u043c\u043f\u0430\u043a\u0442\u043d\u044b\u0439 \u0440\u0435\u0436\u0438\u043c: \u0441\u043a\u0440\u044b\u0432\u0430\u0435\u0442 \u0442\u0435\u0440\u043c\u0438\u043d\u0430\u043b \u0441\u043a\u0430\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u044f \u0438 \u043f\u043e\u043a\u0430\u0437\u044b\u0432\u0430\u0435\u0442 \u043c\u0438\u043d\u0438-\u043e\u043a\u043d\u043e \u0441 \u043f\u0440\u043e\u0433\u0440\u0435\u0441\u0441\u043e\u043c. \u0423\u0434\u043e\u0431\u043d\u043e \u0434\u043b\u044f \u0444\u043e\u043d\u043e\u0432\u043e\u0433\u043e \u0441\u043a\u0430\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u044f.' : 'Compact mode: hides the scan terminal and shows a mini progress window. Ideal for background scanning.'}>
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
              {compactMode ? (lang === 'ru' ? '\u0420\u0430\u0437\u0432\u0435\u0440\u043d\u0443\u0442\u044c' : 'Expand') : (lang === 'ru' ? '\u041a\u043e\u043c\u043f\u0430\u043a\u0442\u043d\u043e' : 'Compact')}
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
          onCopyPath={onCopyPath}
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
          onClick={onStartScan}
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
      </div>

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
