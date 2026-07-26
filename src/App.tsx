import React, { useEffect, useState, useCallback } from 'react'
import Checker from './pages/Checker'
import Dashboard from './pages/Dashboard'
import { IconShield, IconDashboard } from './icons'
import UpdateModal from './components/ui/UpdateModal'
import { useAuth } from './hooks/useAuth'
import type { AppPhase, ThemeId, Lang, UpdateModalState } from './types'
import { THEMES, T } from './types'

// ── Stable components ──

const Logo = React.memo(function Logo({ accent, light, dark, subtitle }: {
  accent: string; light: string; dark: string; subtitle: string
}) {
  return (
    <div className="logo-section">
      <div className="logo-icon">
        <svg width="80" height="80" viewBox="0 0 80 80" fill="none">
          <circle cx="40" cy="40" r="38" stroke="url(#logo-grad)" strokeWidth="2" />
          <path d="M40 10C40 10 25 30 25 45C25 55 31.7 62 40 62C48.3 62 55 55 55 45C55 30 40 10 40 10Z" fill="url(#logo-grad)" opacity="0.9" />
          <path d="M28 50L16 68H64L52 50" stroke="url(#logo-grad)" strokeWidth="2" />
          <circle cx="40" cy="42" r="6" fill="white" opacity="0.3" />
          <defs><linearGradient id="logo-grad" x1="0" y1="0" x2="80" y2="80">
            <stop offset="0%" stopColor={accent} /><stop offset="50%" stopColor={light} /><stop offset="100%" stopColor={dark} />
          </linearGradient></defs>
        </svg>
      </div>
      <h1 className="title">Predator</h1>
      <p className="subtitle">{subtitle}</p>
    </div>
  )
})

const Footer = React.memo(function Footer({ version, updateAvailable }: {
  version: string; updateAvailable: boolean
}) {
  return (
    <div className="footer">
      <span className="version">v{version || '0.0.3'}{updateAvailable && <span className="update-indicator" title="Update Available" />}</span>
      <span className="dot">•</span>
      <span className="secure">Secure Connection</span>
    </div>
  )
})

const renderCard = (children: React.ReactNode) => (
  <div className="status-section"><div className="status-card">{children}</div></div>
)

// ── App ──

const App: React.FC = () => {
  const [phase, setPhase] = useState<AppPhase>('loading')
  const [version, setVersion] = useState('')
  const [lang, setLang] = useState<Lang>('ru')
  const [theme, setTheme] = useState<ThemeId>('predator')
  const {
    token, setToken,
    tokenId,
    tokenError, setTokenError,
    authLoading,
    authError, setAuthError,
    pcName,
    requestId, requestStatus,
    handleAuth,
    handleRequestAccess,
    cancelRequest,
  } = useAuth(lang)

  const [updateAvailable, setUpdateAvailable] = useState(false)
  const [updateModal, setUpdateModal] = useState<UpdateModalState>({ show: false, version: '', state: 'available', percent: 0, speed: '', size: '', errorMsg: '' })

  const t = React.useMemo(() => (key: string) => T[lang][key] || key, [lang])

  useEffect(() => {
    const c = THEMES[theme]
    const r = document.documentElement
    r.style.setProperty('--accent-red', c.accent)
    r.style.setProperty('--accent-orange', c.light)
    r.style.setProperty('--accent-gradient', `linear-gradient(135deg, ${c.accent}, ${c.light}, ${c.dark})`)
    r.style.setProperty('--bg-primary', c.bg)
    r.style.setProperty('--bg-secondary', c.card)
  }, [theme])



  useEffect(() => {
    // Fallback: always move past loading after 5s max, even if everything breaks
    const forceTimer = setTimeout(() => setPhase(p => p === 'loading' ? 'onboarding-lang' : p), 5000)

    const api = window.electronAPI
    if (!api) { setPhase('onboarding-lang'); clearTimeout(forceTimer); return }

    let fallbackTimer: ReturnType<typeof setTimeout> | null = null

    try { api.getAppVersion().then(setVersion).catch(() => setVersion('unknown')) } catch { setVersion('unknown') }

    try {
      api.onUpdateAvailable(info => { setUpdateAvailable(true); setUpdateModal(p => ({ ...p, show: true, version: info.version, state: 'available' })); setPhase('onboarding-lang'); if (fallbackTimer) clearTimeout(fallbackTimer) })
    } catch { /* listener failed, continue */ }

    try {
      api.onUpdateNotAvailable(() => { setPhase('onboarding-lang'); if (fallbackTimer) clearTimeout(fallbackTimer) })
    } catch { /* listener failed, continue */ }

    try { api.onDownloadProgress(data => { setUpdateModal(p => ({ ...p, show: true, state: 'downloading', percent: data.percent, speed: data.bytesPerSecond > 0 ? `${(data.bytesPerSecond / 1024 / 1024).toFixed(1)} MB/s` : '', size: `${(data.transferred / 1024 / 1024).toFixed(1)} / ${(data.total / 1024 / 1024).toFixed(1)} MB` })); if (fallbackTimer) clearTimeout(fallbackTimer) }) } catch { /* skip */ }
    try { api.onUpdateDownloaded(() => { setUpdateModal(p => ({ ...p, show: true, state: 'done' })); if (fallbackTimer) clearTimeout(fallbackTimer) }) } catch { /* skip */ }
    try { api.onUpdateError(msg => { setUpdateModal(p => ({ ...p, state: 'error', errorMsg: msg })); if (fallbackTimer) clearTimeout(fallbackTimer) }) } catch { /* skip */ }

    fallbackTimer = setTimeout(() => { setPhase(p => p === 'loading' ? 'onboarding-lang' : p); clearTimeout(forceTimer) }, 4000)

    return () => {
      clearTimeout(forceTimer)
      if (fallbackTimer) clearTimeout(fallbackTimer)
    }
  }, [])

  const hInstallUpdate = useCallback(() => { setUpdateModal(p => ({ ...p, state: 'downloading', percent: 0 })); window.electronAPI?.startDownload() }, [])
  const hRestart = useCallback(() => window.electronAPI?.restartApp(), [])
  const hCloseModal = useCallback(() => setUpdateModal(p => ({ ...p, show: false })), [])
  const hStartChecker = useCallback(() => setPhase('checker'), [])
  const hStartDashboard = useCallback(() => setPhase('dashboard'), [])
  const hNextLang = useCallback(() => setPhase('onboarding-theme'), [])
  const hNextTheme = useCallback(() => setPhase('onboarding-auth'), [])
  const hBackToMain = useCallback(() => setPhase('main'), [])

  const hNextAuth = useCallback(async () => {
    const success = await handleAuth()
    if (success) setPhase('main')
  }, [handleAuth])

  // Auto-transition to main when access request is approved
  useEffect(() => {
    if (requestStatus === 'approved') {
      const timer = setTimeout(() => setPhase('main'), 1500)
      return () => clearTimeout(timer)
    }
  }, [requestStatus])

  const hRequestAccess = useCallback(async () => {
    const ok = await handleRequestAccess()
    if (ok) setPhase('requesting-access')
  }, [handleRequestAccess])

  const c = THEMES[theme]
  const subtitle = t('title')

  return (
    <div className="app">
      <div className="background-gradient">
        <div className="gradient-orb orb-1" /><div className="gradient-orb orb-2" /><div className="gradient-orb orb-3" />
      </div>
      <div className="scan-line" />
      <div className="container">
        <Logo accent={c.accent} light={c.light} dark={c.dark} subtitle={subtitle} />
        {/* Loading */}
        {phase === 'loading' && renderCard(<><div className="spinner"><div className="spinner-ring" /></div><p className="status-text">Загрузка...</p><div className="progress-bar indeterminate"><div className="progress-fill" /></div></>)}

        {(phase.startsWith('onboarding-') || phase === 'requesting-access') && (
          <div className="onb-steps">
            <div className={`onb-step${phase === 'onboarding-lang' ? ' active' : ' done'}`}><span className="onb-step-dot" /><span className="onb-step-label">{t('langTitle')}</span></div>
            <div className="onb-step-line" />
            <div className={`onb-step${phase === 'onboarding-theme' ? ' active' : phase === 'onboarding-auth' || phase === 'requesting-access' ? ' done' : ''}`}><span className="onb-step-dot" /><span className="onb-step-label">{t('themeTitle')}</span></div>
            <div className="onb-step-line" />
            <div className={`onb-step${phase === 'onboarding-auth' || phase === 'requesting-access' ? ' active' : ''}`}><span className="onb-step-dot" /><span className="onb-step-label">{t('authTitle')}</span></div>
          </div>
        )}

        {phase === 'onboarding-lang' && renderCard(<><p className="onb-label">{t('langTitle')}</p><p className="onb-desc">{t('langDesc')}</p>
          <div className="lang-grid">
            <button className={`lang-btn${lang === 'ru' ? ' active' : ''}`} onClick={() => setLang('ru')}><span className="lang-flag">🇷🇺</span><span className="lang-name">{t('langRu')}</span></button>
            <button className={`lang-btn${lang === 'en' ? ' active' : ''}`} onClick={() => setLang('en')}><span className="lang-flag">🇬🇧</span><span className="lang-name">{t('langEn')}</span></button>
          </div>
          <div className="onb-step-actions"><button className="start-button" onClick={hNextLang}>{t('next')}</button></div></>)}

        {phase === 'onboarding-theme' && renderCard(<><p className="onb-label">{t('themeTitle')}</p><p className="onb-desc">{t('themeDesc')}</p>
          <div className="theme-grid">
            {(Object.entries(THEMES) as [ThemeId, typeof c][]).map(([id, th]) => (
              <button key={id} className={`theme-btn${theme === id ? ' active' : ''}`} style={{ '--theme-accent': th.accent, '--theme-bg': th.card } as React.CSSProperties} onClick={() => setTheme(id)}>
                <span className="theme-swatch" style={{ background: th.accent }} /><span className="theme-name">{th.name}</span>
              </button>
            ))}
          </div>
          <div className="onb-step-actions"><button className="start-button" onClick={hNextTheme}>{t('next')}</button></div></>)}

        {phase === 'onboarding-auth' && renderCard(<><p className="onb-label">{t('authTitle')}</p><p className="onb-desc">{t('authDesc')}</p>
          <div className="token-input-wrap">
            <label className="token-label">{t('tokenLabel')}</label>
            <div className="token-field">
              <input type="text" className="token-input" value={token} onChange={e => { const raw = e.target.value.replace(/[^A-Za-z0-9-]/g, ''); const clean = raw.replace(/-/g, ''); let f = ''; for (let i = 0; i < clean.length && i < 32; i++) { if (i > 0 && i % 8 === 0) f += '-'; f += clean[i] } setToken(f); setTokenError(''); setAuthError('') }} placeholder={t('authPlaceholder')} maxLength={39} />
            </div>
            {(tokenError || authError) && <p className="token-error">{tokenError || authError}</p>}
          </div>
          <button className="start-button" onClick={hNextAuth} disabled={authLoading} style={{ marginTop: 8 }}>
            {authLoading ? <><span className="spinner" style={{ width: 16, height: 16, borderWidth: 2, position: 'relative', display: 'inline-block' }}><span className="spinner-ring" style={{ position: 'absolute', inset: 0 }} /></span> Проверка...</> : t('authBtn')}
          </button>
          <button className="skip-button" onClick={hRequestAccess} disabled={authLoading}>{t('authAlt')}</button></>)}

        {phase === 'requesting-access' && renderCard(<>
          {(!requestStatus || requestStatus === 'pending') && (<><div className="spinner"><div className="spinner-ring" /></div><p className="onb-label">{t('requestSent')}</p><p className="status-text" style={{ animation: 'textPulse 1.5s ease-in-out infinite', margin: '4px 0' }}>{t('requestPending')}</p><div className="request-id-badge">{t('requestId')}: #{requestId || '...'}</div><div className="progress-bar indeterminate" style={{ marginTop: 8 }}><div className="progress-fill" /></div>          <button className="skip-button" onClick={() => { cancelRequest(); setPhase('onboarding-auth') }}>{t('cancel')}</button></>)}
          {requestStatus === 'approved' && (<><div className="ready-icon"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" /><path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg></div><p className="ready-text">{t('requestApproved')}</p><p className="status-text" style={{ animation: 'none' }}>Перенаправление...</p></>)}
          {requestStatus === 'rejected' && (<><div className="error-icon-dl"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#EF4444" strokeWidth="2" /><line x1="16" y1="16" x2="32" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" /><line x1="32" y1="16" x2="16" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" /></svg></div><p className="status-text" style={{ color: '#EF4444', animation: 'none' }}>{t('requestRejected')}</p><button className="start-button" onClick={() => setPhase('onboarding-auth')}>{t('authBtn')}</button></>)}
        </>)}

        {phase === 'main' && renderCard(<><div className="ready-icon"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" /><path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg></div><p className="ready-text">{t('ready')}</p>
          <div className="main-cards">
            <button className="main-card" onClick={hStartChecker}><div className="main-card-icon" style={{ background: 'rgba(255,255,255,0.06)' }}><IconShield size={24} color="#fff" /></div><div className="main-card-body"><span className="main-card-title">{t('startCheck')}</span><span className="main-card-desc">Deep scan for files, processes, registry, network, and memory anomalies.</span></div><span className="main-card-arrow">→</span></button>
            <button className="main-card" onClick={hStartDashboard}><div className="main-card-icon" style={{ background: 'rgba(255,255,255,0.06)' }}><IconDashboard size={24} color="#fff" /></div><div className="main-card-body"><span className="main-card-title">{t('dashboard')}</span><span className="main-card-desc">Live system overview with streaming snapshots and runtime telemetry.</span></div><span className="main-card-arrow">→</span></button>
          </div></>)}

        {phase === 'checker' && <Checker lang={lang} tokenId={tokenId} onBack={hBackToMain} />}
        {phase === 'dashboard' && <Dashboard lang={lang} onBack={hBackToMain} />}

        <UpdateModal state={updateModal} theme={theme} lang={lang} onClose={hCloseModal} onDownload={hInstallUpdate} onRestart={hRestart} />
        <Footer version={version} updateAvailable={updateAvailable} />
      </div>
    </div>
  )
}

export default App
