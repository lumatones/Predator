import React, { useEffect, useState, useCallback, useRef } from 'react'
import { validateToken, useToken, requestAccess, checkRequestStatus } from './api'
import Checker from './pages/Checker'
import Dashboard from './pages/Dashboard'
import Statistics from './pages/Statistics'

// ── Types ──────────────────────────────────────

type AppPhase =
  | 'loading' | 'onboarding-lang'
  | 'onboarding-theme' | 'onboarding-auth' | 'requesting-access'
  | 'main' | 'checker' | 'dashboard' | 'statistics'

type ThemeId = 'predator' | 'ocean' | 'stealth' | 'nebula'

interface ThemeColors {
  accent: string; light: string; dark: string
  bg: string; card: string; name: string; icon: string
}

const THEMES: Record<ThemeId, ThemeColors> = {
  predator: { accent: '#ff4444', light: '#ff6b35', dark: '#cc0000', bg: '#0a0a0f', card: '#12121a', name: 'Predator Red', icon: '🔴' },
  ocean:    { accent: '#3B82F6', light: '#60A5FA', dark: '#1D4ED8', bg: '#0a0f1a', card: '#121a2a', name: 'Ocean Blue', icon: '🔵' },
  stealth:  { accent: '#6B7280', light: '#9CA3AF', dark: '#374151', bg: '#0a0a0c', card: '#121214', name: 'Stealth Black', icon: '⚫' },
  nebula:   { accent: '#8B5CF6', light: '#A78BFA', dark: '#6D28D9', bg: '#0f0a1a', card: '#1a122a', name: 'Nebula Purple', icon: '🟣' },
}

type Lang = 'ru' | 'en'

const T: Record<Lang, Record<string, string>> = {
  ru: {
    title: 'Система проверки безопасности',
    close: 'Закрыть', updateAvailable: 'Доступно обновление', download: 'Скачать',
    downloading: 'Загрузка обновления...', downloaded: 'Обновление готово!',
    installRestart: 'Установить и перезапустить',
    ready: 'Система готова', startCheck: 'Начать проверку',    dashboard: 'Мониторинг', statistics: 'Статистика', continue: 'Продолжить',
    langTitle: 'Выберите язык', langDesc: 'Язык интерфейса приложения',
    langRu: 'Русский', langEn: 'English', next: 'Далее',
    themeTitle: 'Выберите тему', themeDesc: 'Оформление приложения',
    authTitle: 'Авторизация', authDesc: 'Введите токен доступа, полученный от администратора',
    authPlaceholder: 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',
    authError: 'Токен должен содержать 32 символа',
    authBtn: 'Подтвердить', authAlt: 'Запросить доступ через сайт',
    tokenLabel: 'Токен доступа',
    requestSent: 'Запрос отправлен!', requestPending: 'Ожидание подтверждения администратором...',
    requestApproved: 'Запрос одобрен!', requestRejected: 'Запрос отклонён',
    requestId: 'ID запроса', requesting: 'Отправка запроса...', cancel: 'Отмена',
  },
  en: {
    title: 'Security Check System',
    close: 'Close', updateAvailable: 'Update Available', download: 'Download',
    downloading: 'Downloading update...', downloaded: 'Update Ready!',
    installRestart: 'Install & Restart',
    ready: 'System Ready', startCheck: 'Start Check',    dashboard: 'Dashboard', statistics: 'Statistics', continue: 'Continue',
    langTitle: 'Choose Language', langDesc: 'Application interface language',
    langRu: 'Русский', langEn: 'English', next: 'Next',
    themeTitle: 'Choose Theme', themeDesc: 'Application appearance',
    authTitle: 'Authorization', authDesc: 'Enter the access token from your administrator',
    authPlaceholder: 'XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX',
    authError: 'Token must contain 32 characters',
    authBtn: 'Confirm', authAlt: 'Request access via website',
    tokenLabel: 'Access Token',
    requestSent: 'Request sent!', requestPending: 'Waiting for admin approval...',
    requestApproved: 'Request approved!', requestRejected: 'Request rejected',
    requestId: 'Request ID', requesting: 'Sending request...', cancel: 'Cancel',
  },
}

// ── App ────────────────────────────────────────

const App: React.FC = () => {
  const [phase, setPhase] = useState<AppPhase>('loading')
  const [version, setVersion] = useState('')
  const [lang, setLang] = useState<Lang>('ru')
  const [theme, setTheme] = useState<ThemeId>('predator')
  const [token, setToken] = useState('')
  const [tokenError, setTokenError] = useState('')
  const [authLoading, setAuthLoading] = useState(false)
  const [authError, setAuthError] = useState('')
  const [pcName, setPCName] = useState('')
  const [requestId, setRequestId] = useState<number | null>(null)
  const [requestStatus, setRequestStatus] = useState<'pending' | 'approved' | 'rejected' | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval>>(undefined)

  // Update indicator (footer dot)
  const [updateAvailable, setUpdateAvailable] = useState(false)

  // Update modal state (separate from phase — overlay)
  const [updateModal, setUpdateModal] = useState<{
    show: boolean
    version: string
    state: 'available' | 'downloading' | 'done' | 'error'
    percent: number
    speed: string
    size: string
    errorMsg: string
  }>({
    show: false,
    version: '',
    state: 'available',
    percent: 0,
    speed: '',
    size: '',
    errorMsg: '',
  })

  const t = (key: string) => T[lang][key] || key

  // ── Apply theme to CSS variables ──
  useEffect(() => {
    const c = THEMES[theme]
    const r = document.documentElement
    r.style.setProperty('--accent-red', c.accent)
    r.style.setProperty('--accent-orange', c.light)
    r.style.setProperty('--accent-gradient', `linear-gradient(135deg, ${c.accent}, ${c.light}, ${c.dark})`)
    r.style.setProperty('--bg-primary', c.bg)
    r.style.setProperty('--bg-secondary', c.card)
  }, [theme])

  // ── Get PC name (for auth) ──
  useEffect(() => {
    if (window.electronAPI?.getPCName) {
      window.electronAPI.getPCName().then(setPCName).catch(() => setPCName('unknown'))
    } else {
      setPCName('dev-' + Math.random().toString(36).slice(2, 8))
    }
  }, [])

  // ── Cleanup poll timer on unmount ──
  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  // ── Init ──
  useEffect(() => {
    const api = window.electronAPI
    if (!api) {
      // Dev mode or no Electron — skip updates, go to onboarding
      setPhase('onboarding-lang')
      return
    }

    let fallbackTimer: ReturnType<typeof setTimeout> | null = null

    api.getAppVersion().then(setVersion)
    api.onUpdateAvailable((info) => {
      setUpdateAvailable(true)
      setUpdateModal(prev => ({ ...prev, show: true, version: info.version, state: 'available' }))
      setPhase('onboarding-lang')
      if (fallbackTimer) clearTimeout(fallbackTimer)
    })
    api.onUpdateNotAvailable(() => {
      setPhase('onboarding-lang')
      if (fallbackTimer) clearTimeout(fallbackTimer)
    })
    api.onDownloadProgress((data) => {
      setUpdateModal(prev => ({
        ...prev,
        show: true,
        state: 'downloading',
        percent: data.percent,
        speed: data.bytesPerSecond > 0 ? `${(data.bytesPerSecond / 1024 / 1024).toFixed(1)} MB/s` : '',
        size: `${(data.transferred / 1024 / 1024).toFixed(1)} / ${(data.total / 1024 / 1024).toFixed(1)} MB`,
      }))
      if (fallbackTimer) clearTimeout(fallbackTimer)
    })
    api.onUpdateDownloaded(() => {
      setUpdateModal(prev => ({ ...prev, show: true, state: 'done' }))
      if (fallbackTimer) clearTimeout(fallbackTimer)
    })
    api.onUpdateError((msg) => {
      setUpdateModal(prev => ({ ...prev, state: 'error', errorMsg: msg }))
      if (fallbackTimer) clearTimeout(fallbackTimer)
    })

    // Fallback: if no update event arrives within 4s (dev mode, offline, etc.)
    fallbackTimer = setTimeout(() => {
      setPhase('onboarding-lang')
    }, 4000)

    return () => {
      if (fallbackTimer) clearTimeout(fallbackTimer)
    }
  }, [])

  // ── Handlers ──
  const hInstallUpdate = useCallback(() => {
    setUpdateModal(prev => ({ ...prev, state: 'downloading', percent: 0 }))
    window.electronAPI?.startDownload()
  }, [])
  const hRestart = useCallback(() => window.electronAPI?.restartApp(), [])
  const hCloseModal = useCallback(() => setUpdateModal(prev => ({ ...prev, show: false })), [])

  const hStartChecker = useCallback(() => setPhase('checker'), [])
  const hStartDashboard = useCallback(() => setPhase('dashboard'), [])
  const hStartStatistics = useCallback(() => setPhase('statistics'), [])

  const hNextLang = useCallback(() => setPhase('onboarding-theme'), [])
  const hNextTheme = useCallback(() => setPhase('onboarding-auth'), [])
  const hNextAuth = useCallback(async () => {
    const clean = token.replace(/[-\s]/g, '')
    if (clean.length > 0 && clean.length !== 32) {
      setTokenError(t('authError'))
      return
    }
    if (clean.length === 0) {
      setTokenError(t('authError'))
      return
    }

    setAuthLoading(true)
    setAuthError('')
    setTokenError('')

    try {
      const validateResult = await validateToken(token)
      if (!validateResult.valid) {
        setAuthError(validateResult.error || 'Токен недействителен')
        setAuthLoading(false)
        return
      }

      // Mark token as used
      const useResult = await useToken(token, pcName || 'unknown')
      if (!useResult.valid) {
        setAuthError(useResult.error || 'Не удалось активировать токен')
        setAuthLoading(false)
        return
      }

      setPhase('main')
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Ошибка подключения к серверу')
    } finally {
      setAuthLoading(false)
    }
  }, [token, lang, pcName])

  const hRequestAccess = useCallback(async () => {
    setAuthLoading(true)
    setAuthError('')

    try {
      const result = await requestAccess(pcName || 'unknown')
      if (result.success && result.request_id) {
        setRequestId(result.request_id)
        setRequestStatus('pending')
        setPhase('requesting-access')

        // Start polling for status
        if (pollRef.current) clearInterval(pollRef.current)
        pollRef.current = setInterval(async () => {
          try {
            const reqId = result.request_id!
            const status = await checkRequestStatus(reqId)
            setRequestStatus(status.status as 'pending' | 'approved' | 'rejected')

            if (status.status === 'approved') {
              if (pollRef.current) clearInterval(pollRef.current)
              setPhase('main')
            } else if (status.status === 'rejected') {
              if (pollRef.current) clearInterval(pollRef.current)
              setAuthError('Запрос отклонён администратором')
              setRequestId(null)
              setRequestStatus(null)
              setPhase('onboarding-auth')
            }
          } catch {
            // Ignore poll errors — retry on next interval
          }
        }, 3000)
      } else {
        setAuthError(result.error || 'Ошибка отправки запроса')
      }
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : 'Ошибка подключения к серверу')
    } finally {
      setAuthLoading(false)
    }
  }, [pcName])

  // ── Shared: logo + footer ──
  const Logo = () => (
    <div className="logo-section">
      <div className="logo-icon">
        <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
          <circle cx="40" cy="40" r="38" stroke="url(#logo-grad)" strokeWidth="2" />
          <path d="M40 10C40 10 25 30 25 45C25 55 31.7 62 40 62C48.3 62 55 55 55 45C55 30 40 10 40 10Z" fill="url(#logo-grad)" opacity="0.9" />
          <path d="M28 50L16 68H64L52 50" stroke="url(#logo-grad)" strokeWidth="2" />
          <circle cx="40" cy="42" r="6" fill="white" opacity="0.3" />
          <defs><linearGradient id="logo-grad" x1="0" y1="0" x2="80" y2="80">
            <stop offset="0%" stopColor={THEMES[theme].accent} />
            <stop offset="50%" stopColor={THEMES[theme].light} />
            <stop offset="100%" stopColor={THEMES[theme].dark} />
          </linearGradient></defs>
        </svg>
      </div>
      <h1 className="title">Predator</h1>
      <p className="subtitle">{t('title')}</p>
    </div>
  )

  const Footer = () => (
    <div className="footer">
      <span className="version">
        v{version || '0.0.3'}
        {updateAvailable && <span className="update-indicator" title="Update Available" />}
      </span>
      <span className="dot">•</span>
      <span className="secure">Secure Connection</span>
    </div>
  )

  // ── Screens ──
  const renderCard = (children: React.ReactNode) => (
    <div className="status-section">
      <div className="status-card">{children}</div>
    </div>
  )

  // ── Render ──
  return (
    <div className="app">
      <div className="background-gradient">
        <div className="gradient-orb orb-1" />
        <div className="gradient-orb orb-2" />
        <div className="gradient-orb orb-3" />
      </div>
      <div className="scan-line" />

      <div className="container">
        <Logo />

        {/* Loading */}
        {phase === 'loading' && renderCard(
          <><div className="spinner"><div className="spinner-ring" /></div>
            <p className="status-text">Загрузка...</p>
            <div className="progress-bar indeterminate"><div className="progress-fill" /></div></>
        )}

        {/* Loading */}
        {phase === 'loading' && renderCard(
          <><div className="spinner"><div className="spinner-ring" /></div>
            <p className="status-text">Загрузка...</p>
            <div className="progress-bar indeterminate"><div className="progress-fill" /></div></>
        )}

        {/* ── ONBOARDING: Language ── */}
        {phase === 'onboarding-lang' && renderCard(
          <><p className="onb-label">{t('langTitle')}</p>
            <p className="onb-desc">{t('langDesc')}</p>
            <div className="lang-grid">
              <button className={`lang-btn${lang === 'ru' ? ' active' : ''}`} onClick={() => setLang('ru')}>
                <span className="lang-flag">🇷🇺</span>
                <span className="lang-name">{t('langRu')}</span>
              </button>
              <button className={`lang-btn${lang === 'en' ? ' active' : ''}`} onClick={() => setLang('en')}>
                <span className="lang-flag">🇬🇧</span>
                <span className="lang-name">{t('langEn')}</span>
              </button>
            </div>
            <button className="start-button" onClick={hNextLang} style={{ marginTop: 12 }}>{t('next')}</button></>
        )}

        {/* ── ONBOARDING: Theme ── */}
        {phase === 'onboarding-theme' && renderCard(
          <><p className="onb-label">{t('themeTitle')}</p>
            <p className="onb-desc">{t('themeDesc')}</p>
            <div className="theme-grid">
              {(Object.entries(THEMES) as [ThemeId, ThemeColors][]).map(([id, th]) => (
                <button key={id} className={`theme-btn${theme === id ? ' active' : ''}`}
                  style={{ '--theme-accent': th.accent, '--theme-bg': th.card } as React.CSSProperties}
                  onClick={() => setTheme(id)}>
                  <span className="theme-swatch" style={{ background: th.accent }} />
                  <span className="theme-name">{th.name}</span>
                </button>
              ))}
            </div>
            <button className="start-button" onClick={hNextTheme} style={{ marginTop: 12 }}>{t('next')}</button></>
        )}

        {/* ── ONBOARDING: Auth ── */}
        {phase === 'onboarding-auth' && renderCard(
          <><p className="onb-label">{t('authTitle')}</p>
            <p className="onb-desc">{t('authDesc')}</p>
            <div className="token-input-wrap">
              <label className="token-label">{t('tokenLabel')}</label>
              <div className="token-field">
                <input type="text" className="token-input" value={token}
                  onChange={(e) => {
                    const raw = e.target.value.replace(/[^A-Za-z0-9-]/g, '')
                    // Auto-format: groups of 8 with dashes
                    const clean = raw.replace(/-/g, '')
                    let formatted = ''
                    for (let i = 0; i < clean.length && i < 32; i++) {
                      if (i > 0 && i % 8 === 0) formatted += '-'
                      formatted += clean[i]
                    }
                    setToken(formatted)
                    setTokenError('')
                    setAuthError('')
                  }}
                  placeholder={t('authPlaceholder')}
                  maxLength={39} // 32 chars + 7 dashes
                />
              </div>
              {(tokenError || authError) && (
                <p className="token-error">{tokenError || authError}</p>
              )}
            </div>
            <button
              className="start-button"
              onClick={hNextAuth}
              disabled={authLoading}
              style={{ marginTop: 8 }}
            >
              {authLoading ? (
                <><span className="spinner" style={{ width: 16, height: 16, borderWidth: 2, position: 'relative', display: 'inline-block' }}><span className="spinner-ring" style={{ position: 'absolute', inset: 0 }} /></span> Проверка...</>
              ) : (
                t('authBtn')
              )}
            </button>
            <button
              className="skip-button"
              onClick={hRequestAccess}
              disabled={authLoading}
            >
              {t('authAlt')}
            </button></>
        )}

        {/* ── REQUESTING ACCESS ── */}
        {phase === 'requesting-access' && renderCard(
          <>
            {/* Default / pending — show waiting screen */}
            {(!requestStatus || requestStatus === 'pending') && (
              <><div className="spinner"><div className="spinner-ring" /></div>
                <p className="onb-label">{t('requestSent')}</p>
                <p className="status-text" style={{ animation: 'textPulse 1.5s ease-in-out infinite', margin: '4px 0' }}>
                  {t('requestPending')}
                </p>
                <div className="request-id-badge">
                  {t('requestId')}: #{requestId || '...'}
                </div>
                <div className="progress-bar indeterminate" style={{ marginTop: 8 }}>
                  <div className="progress-fill" />
                </div>
                <button className="skip-button" onClick={() => { if (pollRef.current) clearInterval(pollRef.current); setPhase('onboarding-auth'); setRequestId(null); setRequestStatus(null); }}>
                  {t('cancel')}
                </button></>
            )}
            {requestStatus === 'approved' && (
              <><div className="ready-icon">
                <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
                  <circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" />
                  <path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
                </svg></div>
                <p className="ready-text">{t('requestApproved')}</p>
                <p className="status-text" style={{ animation: 'none' }}>Перенаправление...</p></>
            )}
            {requestStatus === 'rejected' && (
              <><div className="error-icon-dl">
                <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
                  <circle cx="24" cy="24" r="22" stroke="#EF4444" strokeWidth="2" />
                  <line x1="16" y1="16" x2="32" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" />
                  <line x1="32" y1="16" x2="16" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" />
                </svg></div>
                <p className="status-text" style={{ color: '#EF4444', animation: 'none' }}>{t('requestRejected')}</p>
                <button className="start-button" onClick={() => setPhase('onboarding-auth')}>
                  {t('authBtn')}
                </button></>
            )}
          </>
        )}

        {/* ── MAIN SCREEN ── */}
        {phase === 'main' && renderCard(
          <><div className="ready-icon">
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
              <circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" />
              <path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
            </svg></div>
            <p className="ready-text">{t('ready')}</p>
            <div className="main-actions">
              <button className="start-button" onClick={hStartChecker}>{t('startCheck')}</button>
              <button className="start-button secondary" onClick={hStartDashboard}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" />
                </svg>
                {t('dashboard')}
              </button>
              <button className="start-button secondary" onClick={hStartStatistics}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 20V10M12 20V4M6 20v-6" strokeWidth="2" strokeLinecap="round" />
                </svg>
                {t('statistics')}
              </button>
            </div></>
        )}

        {/* ── CHECKER ── */}
        {phase === 'checker' && (
          <Checker lang={lang} onBack={() => setPhase('main')} />
        )}

        {/* ── DASHBOARD ── */}
        {phase === 'dashboard' && (
          <Dashboard lang={lang} onBack={() => setPhase('main')} />
        )}

        {/* ── STATISTICS ── */}
        {phase === 'statistics' && (
          <Statistics lang={lang} onBack={() => setPhase('main')} />
        )}

        {/* ═══ UPDATE MODAL (overlay) ═══ */}
        {updateModal.show && (
          <div className="update-modal-overlay" onClick={hCloseModal}>
            <div className="update-modal" onClick={e => e.stopPropagation()}>
              {/* Available */}
              {updateModal.state === 'available' && (
                <>
                  <div className="update-modal-icon">
                    <svg width="40" height="40" viewBox="0 0 48 48" fill="none">
                      <circle cx="24" cy="24" r="22" stroke={THEMES[theme].light} strokeWidth="2" />
                      <path d="M24 14V34M14 24H34" stroke={THEMES[theme].light} strokeWidth="3" strokeLinecap="round" />
                    </svg>
                  </div>
                  <p className="update-modal-title">{t('updateAvailable')}</p>
                  <p className="update-modal-version">{updateModal.version}</p>
                  <div className="update-modal-actions">
                    <button className="update-modal-btn secondary" onClick={hCloseModal}>
                      {t('close')}
                    </button>
                    <button className="update-modal-btn primary" onClick={hInstallUpdate}>
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                      </svg>
                      {t('download')}
                    </button>
                  </div>
                </>
              )}

              {/* Downloading */}
              {updateModal.state === 'downloading' && (
                <>
                  <div className="update-modal-icon">
                    <div className="spinner" style={{ width: 36, height: 36 }}>
                      <div className="spinner-ring" style={{ borderWidth: 2 }} />
                    </div>
                  </div>
                  <p className="update-modal-title">{t('downloading')}</p>
                  <div className="update-modal-actions" style={{ flexDirection: 'column', gap: 8 }}>
                    <div className="update-progress-bar">
                      <div className="update-progress-fill" style={{ width: `${updateModal.percent}%` }} />
                    </div>
                    <div className="progress-info">
                      <span>{updateModal.speed}</span>
                      <span>{updateModal.percent}%</span>
                    </div>
                    <span style={{ fontSize: 11, color: 'rgba(255,255,255,0.35)' }}>{updateModal.size}</span>
                  </div>
                </>
              )}

              {/* Done */}
              {updateModal.state === 'done' && (
                <>
                  <div className="update-modal-icon">
                    <svg width="40" height="40" viewBox="0 0 48 48" fill="none">
                      <circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" />
                      <path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                  <p className="update-modal-title">{t('downloaded')}</p>
                  <p className="update-modal-version">{updateModal.version}</p>
                  <div className="update-modal-actions">
                    <button className="update-modal-btn secondary" onClick={hCloseModal}>
                      {t('close')}
                    </button>
                    <button className="update-modal-btn primary restart" onClick={hRestart}>
                      {t('installRestart')}
                    </button>
                  </div>
                </>
              )}

              {/* Error */}
              {updateModal.state === 'error' && (
                <>
                  <div className="update-modal-icon error">
                    <svg width="40" height="40" viewBox="0 0 48 48" fill="none">
                      <circle cx="24" cy="24" r="22" stroke="#EF4444" strokeWidth="2" />
                      <line x1="16" y1="16" x2="32" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" />
                      <line x1="32" y1="16" x2="16" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" />
                    </svg>
                  </div>
                  <p className="update-modal-title" style={{ color: '#EF4444' }}>{t('updateAvailable')}</p>
                  <p className="update-modal-version" style={{ color: 'rgba(255,68,68,0.6)' }}>{updateModal.errorMsg}</p>
                  <div className="update-modal-actions">
                    <button className="update-modal-btn secondary" onClick={hCloseModal}>
                      {t('close')}
                    </button>
                    <button className="update-modal-btn primary" onClick={hInstallUpdate}>
                      {t('download')}
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        <Footer />
      </div>
    </div>
  )
}

export default App
