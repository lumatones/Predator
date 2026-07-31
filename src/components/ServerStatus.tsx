import { useState, useEffect, useCallback } from 'react'
import { getApiBase, setApiBase } from '../api'

type ServerStatusType = 'checking' | 'online' | 'offline'

const COLORS: Record<ServerStatusType, { dot: string; pulse: string; bg: string }> = {
  checking: { dot: '#F59E0B', pulse: 'rgba(245,158,11,0.3)', bg: 'rgba(245,158,11,0.08)' },
  online:   { dot: '#22c55e', pulse: 'rgba(34,197,94,0.3)',  bg: 'rgba(34,197,94,0.08)' },
  offline:  { dot: '#EF4444', pulse: 'rgba(239,68,68,0.3)', bg: 'rgba(239,68,68,0.08)' },
}

const LABELS: Record<string, Record<string, string>> = {
  ru: {
    checking: 'Проверка...', online: 'Сервер онлайн', offline: 'Сервер недоступен',
    url: 'Сервер', change: 'Сменить', apply: 'Применить', cancel: 'Отмена',
    placeholder: 'http://ip:3001', saved: 'Сохранено! Перезагрузка...',
  },
  en: {
    checking: 'Checking...', online: 'Server online', offline: 'Server offline',
    url: 'Server', change: 'Change', apply: 'Apply', cancel: 'Cancel',
    placeholder: 'http://ip:3001', saved: 'Saved! Reloading...',
  },
}

export default function ServerStatus({ lang }: { lang: 'ru' | 'en' }) {
  const [status, setStatus] = useState<ServerStatusType>('checking')
  const [editing, setEditing] = useState(false)
  const [inputUrl, setInputUrl] = useState('')
  const [saving, setSaving] = useState(false)
  const [displayUrl, setDisplayUrl] = useState(getApiBase())
  const t = (k: string) => LABELS[lang][k] || k

  const checkHealth = useCallback(async () => {
    setStatus('checking')
    try {
      const res = await fetch(`${getApiBase()}/api/health`, { signal: AbortSignal.timeout(5000) })
      setStatus(res.ok ? 'online' : 'offline')
    } catch {
      setStatus('offline')
    }
  }, [])

  useEffect(() => {
    setDisplayUrl(getApiBase())
    checkHealth()
    const interval = setInterval(checkHealth, 30000)
    return () => clearInterval(interval)
  }, [checkHealth])

  const handleStartEdit = () => {
    setInputUrl(getApiBase())
    setEditing(true)
  }

  const handleApply = async () => {
    if (!inputUrl.trim()) return
    setSaving(true)
    const clean = inputUrl.trim().replace(/\/$/, '')
    try {
      if (window.electronAPI?.setApiBase) {
        await window.electronAPI.setApiBase(clean)
      } else {
        localStorage.setItem('predator_api_url', clean)
      }
      setApiBase(clean)
      setDisplayUrl(clean)
    } catch { /* ignore */ }
    setTimeout(() => window.location.reload(), 600)
  }

  const colors = COLORS[status]
  const shortUrl = displayUrl.replace(/^https?:\/\//, '')

  return (
    <div
      className="server-status"
      style={{
        '--ss-dot': colors.dot,
        '--ss-pulse': colors.pulse,
      } as React.CSSProperties}
    >
      <div className="server-status-header" onClick={handleStartEdit} title="Click to change server">
        <span className="server-status-dot">
          <span className="server-status-dot-inner status-dot" />
        </span>
        <span className="server-status-label">{t(status)}</span>
        <span className="server-status-url" title={displayUrl}>{shortUrl}</span>
        <button
          className="server-status-change"
          onClick={(e) => { e.stopPropagation(); handleStartEdit() }}
        >
          {t('change')}
        </button>
      </div>

      {editing && (
        <div className="server-status-edit">
          <input
            type="text"
            className="server-status-input"
            value={inputUrl}
            onChange={e => setInputUrl(e.target.value)}
            placeholder={t('placeholder')}
            disabled={saving}
            autoFocus
            onKeyDown={e => {
              if (e.key === 'Enter') handleApply()
              if (e.key === 'Escape') setEditing(false)
            }}
          />
          <div className="server-status-edit-actions">
            <button
              className="server-status-btn secondary"
              onClick={() => setEditing(false)}
              disabled={saving}
            >
              {t('cancel')}
            </button>
            <button
              className="server-status-btn primary"
              onClick={handleApply}
              disabled={saving || !inputUrl.trim()}
            >
              {saving ? t('saved') : t('apply')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
