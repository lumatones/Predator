import { useState, useRef, useCallback } from 'react'
import type { ScanResult, ScanProgress, ScanResponse, ScanMode } from '../types/electron'
import { exportHtml, exportJson, exportMarkdown, exportPdf, sendToTelegram } from '../utils/export-report'
import { tabCache, generateMockData } from '../pages/checker-config'

interface UseCheckerScanOpts {
  t: (key: string) => string
  tokenId: number | null
  playSound: (sound: 'swoosh' | 'alarm' | 'complete' | 'tick') => void
}

export interface CheckerScanState {
  phase: 'idle' | 'scanning' | 'done'
  progress: ScanProgress | null
  results: ScanResult[]
  summary: ScanResponse['summary'] | null
  error: string
  tabCounts: Map<ScanMode, number>
}

interface ExportState {
  exportMsg: string
  telegramSending: boolean
}

export function useCheckerScan({ t, tokenId, playSound }: UseCheckerScanOpts) {
  const scanRef = useRef(false)
  const isMounted = useRef(true)

  const [phase, setPhase] = useState<'idle' | 'scanning' | 'done'>('idle')
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [results, setResults] = useState<ScanResult[]>([])
  const [summary, setSummary] = useState<ScanResponse['summary'] | null>(null)
  const [error, setError] = useState('')
  const [tabCounts, setTabCounts] = useState<Map<ScanMode, number>>(new Map())

  // Export state
  const [exportMsg, setExportMsg] = useState('')
  const [telegramSending, setTelegramSending] = useState(false)

  const initFromCache = useCallback((mode: ScanMode) => {
    setProgress(null)
    setError('')
    const cached = tabCache.get(mode)
    if (cached) {
      setResults(cached.results)
      setSummary(cached.summary)
      setPhase('done')
    } else {
      setPhase('idle')
      setResults([])
      setSummary(null)
    }
  }, [])

  const handleStartScan = useCallback(async (activeTab: ScanMode, currentTabLabel: string) => {
    const api = window.electronAPI
    if (scanRef.current) return
    scanRef.current = true

    tabCache.delete(activeTab)

    playSound('swoosh')
    setPhase('scanning')
    setError('')
    setResults([])
    setSummary(null)
    setProgress(null)

    if (!api?.startScan) {
      for (let i = 0; i <= 100; i += 10) {
        if (!scanRef.current) return
        await new Promise(r => setTimeout(r, 150))
        setProgress({
          phase: i < 80 ? 'scanning' : i < 100 ? 'analyzing' : 'done',
          currentDir: i < 80 ? `${currentTabLabel} scanning...` : 'Analyzing...',
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
      setTabCounts(prev => { const next = new Map(prev); next.set(activeTab, mock.results.length); return next })
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
        setTabCounts(prev => { const next = new Map(prev); next.set(activeTab, response.results.length); return next })
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
  }, [t, tokenId, playSound])

  const handleClear = useCallback(() => {
    tabCache.clear()
    setResults([])
    setSummary(null)
    setProgress(null)
    setPhase('idle')
    scanRef.current = false
  }, [])

  const handleExport = useCallback((format: 'html' | 'json' | 'md') => {
    if (!summary) return
    let content: string; let ext: string; let mime: string
    if (format === 'html') { content = exportHtml(results, summary); ext = 'html'; mime = 'text/html' }
    else if (format === 'md') { content = exportMarkdown(results, summary); ext = 'md'; mime = 'text/markdown' }
    else { content = exportJson(results, summary); ext = 'json'; mime = 'application/json' }
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
      let botToken = ''; let chatId = ''
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

  const scanState: CheckerScanState = { phase, progress, results, summary, error, tabCounts }
  const exportState: ExportState = { exportMsg, telegramSending }

  return {
    scanState, exportState, scanRef,
    initFromCache, handleStartScan, handleClear,
    handleExport, handleExportPdf, handleTelegramExport,
  }
}
