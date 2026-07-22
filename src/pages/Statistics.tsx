import { useState, useEffect } from 'react'
import { aggregateStats, clearHistory, type AggregatedStats } from '../utils/stats-store'

interface StatisticsProps {
  lang: 'ru' | 'en'
  onBack: () => void
}

const T: Record<string, Record<string, string>> = {
  ru: {
    title: 'Статистика проверок',
    totalScans: 'Всего проверок',
    totalThreats: 'Найдено угроз',
    avgTime: 'Среднее время',
    threatsByDay: 'Угрозы по дням',
    topCheats: 'Топ-5 типов читов',
    hotDirs: 'Горячие директории',
    scansByMode: 'Проверки по режимам',
    clear: 'Очистить историю',
    noData: 'Нет данных',
    sec: 'сек',
    back: 'Назад',
    count: 'раз',
    riskHigh: 'Высокий',
    riskMedium: 'Средний',
    riskLow: 'Низкий',
    today: 'Сегодня',
    yesterday: 'Вчера',
    files: 'Файлы',
    processes: 'Процессы',
    cheats: 'Читы',
    dma: 'DMA',
    extended: 'Расширенный',
  },
  en: {
    title: 'Scan Statistics',
    totalScans: 'Total Scans',
    totalThreats: 'Threats Found',
    avgTime: 'Avg Time',
    threatsByDay: 'Threats by Day',
    topCheats: 'Top 5 Cheat Types',
    hotDirs: 'Hot Directories',
    scansByMode: 'Scans by Mode',
    clear: 'Clear History',
    noData: 'No data',
    sec: 'sec',
    back: 'Back',
    count: 'times',
    riskHigh: 'High',
    riskMedium: 'Medium',
    riskLow: 'Low',
    today: 'Today',
    yesterday: 'Yesterday',
    files: 'Files',
    processes: 'Processes',
    cheats: 'Cheats',
    dma: 'DMA',
    extended: 'Extended',
  },
}

const MODE_ICONS: Record<string, string> = {
  files: '📁',
  processes: '⚙️',
  cheats: '🎯',
  dma: '🔌',
  extended: '🛡️',
}

function formatDate(dateStr: string, lang: string): string {
  const date = new Date(dateStr)
  const today = new Date()
  const yesterday = new Date(today)
  yesterday.setDate(yesterday.getDate() - 1)

  if (date.toISOString().slice(0, 10) === today.toISOString().slice(0, 10)) {
    return lang === 'ru' ? 'Сегодня' : 'Today'
  }
  if (date.toISOString().slice(0, 10) === yesterday.toISOString().slice(0, 10)) {
    return lang === 'ru' ? 'Вчера' : 'Yesterday'
  }
  return date.toLocaleDateString(lang === 'ru' ? 'ru-RU' : 'en-US', {
    day: 'numeric',
    month: 'short',
  })
}

const MAX_BAR_HEIGHT = 80

export default function Statistics({ lang, onBack }: StatisticsProps) {
  const t = (key: string) => T[lang][key] || key
  const [stats, setStats] = useState<AggregatedStats>(() => aggregateStats())

  const handleClear = () => {
    clearHistory()
    setStats(aggregateStats())
  }

  const maxDayCount = Math.max(...stats.threatsByDay.map(d => d.count), 1)
  const maxCheatCount = Math.max(...stats.topCheatTypes.map(c => c.count), 1)
  const maxDirCount = Math.max(...stats.hotDirectories.map(d => d.count), 1)
  const maxModeCount = Math.max(...stats.scanCountByMode.map(m => m.count), 1)

  return (
    <div className="stats-wrapper">
      <div className="dash-header">
        <button className="checker-back-btn" onClick={onBack} title={t('back')}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="15 18 9 12 15 6" />
          </svg>
        </button>
        <h2 className="dash-title">{t('title')}</h2>
        <button className="stats-clear-btn" onClick={handleClear} title={t('clear')}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
          </svg>
        </button>
      </div>

      {/* ── Summary cards ── */}
      <div className="stats-summary-row">
        <div className="stats-card">
          <span className="stats-card-value">{stats.totalScans}</span>
          <span className="stats-card-label">{t('totalScans')}</span>
        </div>
        <div className="stats-card">
          <span className="stats-card-value" style={{ color: '#ff4444' }}>{stats.totalThreats}</span>
          <span className="stats-card-label">{t('totalThreats')}</span>
        </div>
        <div className="stats-card">
          <span className="stats-card-value">{(stats.avgScanTimeMs / 1000).toFixed(1)}</span>
          <span className="stats-card-label">{t('avgTime')} ({t('sec')})</span>
        </div>
      </div>

      {/* ── Threats by Day Chart ── */}
      <div className="stats-section">
        <span className="stats-section-title">{t('threatsByDay')}</span>
        <div className="stats-chart">
          {stats.threatsByDay.map((day) => (
            <div key={day.date} className="stats-bar-col">
              <span className={`stats-bar-value ${day.count > 0 ? 'has' : ''}`}>{day.count}</span>
              <div className="stats-bar-track">
                <div
                  className="stats-bar-fill"
                  style={{ height: `${(day.count / maxDayCount) * MAX_BAR_HEIGHT}px` }}
                />
              </div>
              <span className="stats-bar-label">{formatDate(day.date, lang)}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Top 5 Cheat Types ── */}
      <div className="stats-section">
        <span className="stats-section-title">{t('topCheats')}</span>
        <div className="stats-list">
          {stats.topCheatTypes.map((cheat, i) => (
            <div key={cheat.name} className="stats-list-row">
              <span className="stats-list-rank">#{i + 1}</span>
              <div className="stats-list-bar-track">
                <div
                  className="stats-list-bar-fill"
                  style={{ width: `${(cheat.count / maxCheatCount) * 100}%` }}
                />
              </div>
              <span className="stats-list-name">{cheat.name}</span>
              <span className="stats-list-count">{cheat.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Hot Directories ── */}
      <div className="stats-section">
        <span className="stats-section-title">{t('hotDirs')}</span>
        <div className="stats-dir-list">
          {stats.hotDirectories.map((dir, i) => (
            <div key={dir.path} className="stats-dir-row" style={{ animationDelay: `${i * 0.04}s` }}>
              <div className="stats-dir-risk">
                <span className={`stats-dir-dot dot-${dir.risk}`} />
              </div>
              <div className="stats-dir-info">
                <span className="stats-dir-path">{dir.path.length > 40 ? dir.path.slice(0, 37) + '...' : dir.path}</span>
                <span className="stats-dir-bar-track">
                  <span className="stats-dir-bar-fill" style={{ width: `${(dir.count / maxDirCount) * 100}%` }} />
                </span>
              </div>
              <span className="stats-dir-count">{dir.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Scans by Mode ── */}
      <div className="stats-section">
        <span className="stats-section-title">{t('scansByMode')}</span>
        <div className="stats-mode-list">
          {stats.scanCountByMode.map((m) => (
            <div key={m.mode} className="stats-mode-row">
              <span className="stats-mode-icon">{MODE_ICONS[m.mode] || '📋'}</span>
              <span className="stats-mode-name">{t(m.mode) || m.mode}</span>
              <div className="stats-mode-bar-track">
                <div className="stats-mode-bar-fill" style={{ width: `${(m.count / maxModeCount) * 100}%` }} />
              </div>
              <span className="stats-mode-count">{m.count} {t('count')}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
