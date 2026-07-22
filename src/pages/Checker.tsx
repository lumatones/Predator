import { useState, useRef, useCallback, useEffect } from 'react'
import type { ScanResult, ScanProgress, ScanResponse } from '../types/electron'

interface CheckerProps {
  lang: 'ru' | 'en'
  onBack: () => void
}

const T: Record<string, Record<string, string>> = {
  ru: {
    title: 'Сканирование системы',
    desc: 'Поиск подозрительных файлов и скриптов',
    startBtn: 'Начать проверку',
    scanning: 'Сканирование файлов...',
    analyzing: 'Анализ результатов...',
    done: 'Проверка завершена',
    found: 'Найдено',
    high: 'Высокий',
    medium: 'Средний',
    low: 'Низкий',
    risk: 'Риск',
    noThreats: 'Подозрительных файлов не обнаружено',
    threatsFound: 'обнаруженных угроз',
    filesScanned: 'файлов просканировано',
    time: 'Время',
    sec: 'сек',
    clear: 'Очистить результаты',
    file: 'Файл',
    matches: 'Совпадения',
    path: 'Путь',
    scanAgain: 'Проверить снова',
    browser: 'История браузера',
  },
  en: {
    title: 'System Scan',
    desc: 'Searching for suspicious files and scripts',
    startBtn: 'Start Scan',
    scanning: 'Scanning files...',
    analyzing: 'Analyzing results...',
    done: 'Scan complete',
    found: 'Found',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    risk: 'Risk',
    noThreats: 'No suspicious files detected',
    threatsFound: 'threats found',
    filesScanned: 'files scanned',
    time: 'Time',
    sec: 'sec',
    clear: 'Clear results',
    file: 'File',
    matches: 'Matches',
    path: 'Path',
    scanAgain: 'Scan Again',
    browser: 'Browser History',
  },
}

export default function Checker({ lang, onBack }: CheckerProps) {
  const t = (key: string) => T[lang][key] || key

  const [phase, setPhase] = useState<'idle' | 'scanning' | 'done'>('idle')
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [results, setResults] = useState<ScanResult[]>([])
  const [summary, setSummary] = useState<ScanResponse['summary'] | null>(null)
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState('')

  const handleStartScan = useCallback(async () => {
    const api = window.electronAPI
    if (!api?.startScan) {
      // Dev mode — simulate scan
      setPhase('scanning')
      setError('')
      setResults([])
      setSummary(null)
      setSelectedResult(null)

      const mockResults: ScanResult[] = [
        { path: '~/Downloads/cheat_loader.js', fileName: 'cheat_loader.js', type: 'file', risk: 'high', matches: ['filename:cheat', 'content:inject', 'content:hack'], size: 15234, modifiedAt: new Date().toISOString() },
        { path: '~/Desktop/mod_menu.dll', fileName: 'mod_menu.dll', type: 'file', risk: 'high', matches: ['filename:mod menu', 'pattern:mod menu'], size: 245760, modifiedAt: new Date().toISOString() },
      ]

      // Simulate progress
      for (let i = 0; i <= 100; i += 10) {
        await new Promise(r => setTimeout(r, 200))
        setProgress({
          phase: i < 80 ? 'scanning' : i < 100 ? 'analyzing' : 'done',
          currentDir: i < 80 ? '~/Downloads/...' : 'Browser history',
          filesFound: i < 80 ? Math.floor(i / 20) : mockResults.length,
          filesScanned: Math.floor(i * 3),
          totalDirs: 5,
          dirsDone: Math.min(Math.floor(i / 20), 5),
        })
      }

      setResults(mockResults)
      setSummary({ totalScanned: 300, suspiciousFiles: 2, highRiskCount: 2, scanTimeMs: 3200 })
      setPhase('done')
      return
    }

    // Real scan via Electron
    setPhase('scanning')
    setError('')
    setResults([])
    setSummary(null)
    setSelectedResult(null)

    api.onScanProgress((data: ScanProgress) => {
      setProgress({ ...data })
    })

    try {
      const response: ScanResponse = await api.startScan()
      setResults(response.results)
      setSummary(response.summary)
      setPhase('done')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка сканирования')
      setPhase('idle')
    }
  }, [])

  const handleClear = useCallback(() => {
    setResults([])
    setSummary(null)
    setProgress(null)
    setSelectedResult(null)
    setPhase('idle')
  }, [])

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const formatTime = (ms: number) => {
    if (ms < 1000) return `${ms} мс`
    return `${(ms / 1000).toFixed(1)} ${t('sec')}`
  }

  const riskClass = (risk: string) =>
    risk === 'high' ? 'risk-high' : risk === 'medium' ? 'risk-medium' : 'risk-low'

  const riskLabel = (risk: string) =>
    risk === 'high' ? t('high') : risk === 'medium' ? t('medium') : t('low')

  // Progress percentage
  const calcPercent = () => {
    if (!progress) return 0
    if (progress.phase === 'done') return 100
    if (progress.phase === 'analyzing') return 85 + Math.min(progress.filesFound * 2, 15)
    return Math.min(
      (progress.dirsDone / Math.max(progress.totalDirs, 1)) * 70 +
      (progress.filesScanned % 100) * 0.1,
      84
    )
  }

  return (
    <div className="checker-wrapper">
      <div className="checker-header">
        <div className="checker-title-row">
          <button className="checker-back-btn" onClick={onBack} title="Назад">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
          </button>
          <h2 className="checker-title">{t('title')}</h2>
          <div className="checker-status-dot" data-phase={phase} />
        </div>
        <p className="checker-desc">{t('desc')}</p>
      </div>

      {/* Scan button / progress */}
      {phase === 'idle' && (
        <button className="checker-start-btn" onClick={handleStartScan}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
          </svg>
          {t('startBtn')}
        </button>
      )}

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
              {progress?.phase === 'analyzing' ? t('analyzing') : t('scanning')}
            </span>
            <span className="checker-progress-pct">{Math.round(calcPercent())}%</span>
          </div>
          <div className="checker-progress-bar">
            <div className="checker-progress-fill" style={{ width: `${calcPercent()}%` }} />
          </div>
          <div className="checker-progress-info">
            <span>{t('found')}: {progress?.filesFound || 0}</span>
            <span>{progress?.filesScanned || 0} {t('filesScanned').split(' ')[0]}</span>
          </div>
          {progress?.currentDir && (
            <div className="checker-current-dir">{progress.currentDir}</div>
          )}
        </div>
      )}

      {error && (
        <div className="checker-error">{error}</div>
      )}

      {/* Results */}
      {phase === 'done' && (
        <div className="checker-results">
          {/* Summary */}
          {summary && (
            <div className="checker-summary">
              <div className={`checker-summary-icon ${summary.suspiciousFiles > 0 ? 'warning' : 'safe'}`}>
                {summary.suspiciousFiles > 0 ? '⚠️' : '✅'}
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

          {/* Results table */}
          {results.length > 0 && (
            <div className="checker-table-wrap">
              <table className="checker-table">
                <thead>
                  <tr>
                    <th>{t('risk')}</th>
                    <th>{t('file')}</th>
                    <th>{t('matches')}</th>
                    <th>Размер</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r, i) => (
                    <tr key={i} className={riskClass(r.risk)} onClick={() => setSelectedResult(selectedResult?.path === r.path ? null : r)}>
                      <td>
                        <span className={`risk-badge ${riskClass(r.risk)}`}>
                          {riskLabel(r.risk)}
                        </span>
                      </td>
                      <td className="checker-file-cell">
                        <span className={`checker-file-icon ${r.type === 'browser' ? 'browser-icon' : ''}`}>
                          {r.type === 'browser' ? '🌐' : '📄'}
                        </span>
                        <span className="checker-file-name">{r.fileName}</span>
                      </td>
                      <td>
                        <div className="checker-matches">
                          {r.matches.slice(0, 3).map((m, j) => (
                            <span key={j} className="match-tag">{m}</span>
                          ))}
                          {r.matches.length > 3 && (
                            <span className="match-more">+{r.matches.length - 3}</span>
                          )}
                        </div>
                      </td>
                      <td className="checker-size">{formatSize(r.size)}</td>
                      <td>
                        <span className="checker-expand">{selectedResult?.path === r.path ? '▲' : '▼'}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {/* Selected file details */}
              {selectedResult && (
                <div className="checker-detail">
                  <div className="checker-detail-header">
                    <span className="checker-detail-title">{t('path')}</span>
                    <span className="checker-detail-path">{selectedResult.path}</span>
                  </div>
                  <div className="checker-detail-header">
                    <span className="checker-detail-title">{t('matches')}</span>
                    <div className="checker-matches" style={{ marginTop: 4 }}>
                      {selectedResult.matches.map((m, j) => (
                        <span key={j} className="match-tag">{m}</span>
                      ))}
                    </div>
                  </div>
                  <div className="checker-detail-header">
                    <span className="checker-detail-title">{t('risk')}</span>
                    <span className={`risk-badge ${riskClass(selectedResult.risk)}`} style={{ marginTop: 4 }}>
                      {riskLabel(selectedResult.risk)}
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Actions */}
          <div className="checker-actions">
            <button className="checker-action-btn secondary" onClick={handleClear}>
              {t('clear')}
            </button>
            <button className="checker-action-btn primary" onClick={handleStartScan}>
              {t('scanAgain')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
