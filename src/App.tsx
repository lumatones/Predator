import React, { useEffect, useState, useCallback } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import Checker from './pages/Checker'
import Dashboard from './pages/Dashboard'
import { IconShield, IconDashboard } from './icons'
import UpdateModal from './components/ui/UpdateModal'
import ParticleBackground from './components/ui/ParticleBackground'
import PredatorLogo3D from './components/ui/PredatorLogo3D'
import ThemeBurnTransition from './components/ui/ThemeBurnTransition'
import { ToastProvider } from './components/ui/ToastProvider'
import { Skeleton } from './components/ui/Skeleton'
import { Magnetic } from './components/ui/Magnetic'
import { Button } from './components/ui/Button'
import { useAuth } from './hooks/useAuth'
import type { AppPhase, ThemeId, Lang, UpdateModalState, ThemeColors } from './types'
import { THEMES, T } from './types'

// ── Stable components ──

const Logo = React.memo(function Logo({ accent, light, dark, subtitle }: {
  accent: string; light: string; dark: string; subtitle: string
}) {
  return (
    <div className="logo-section">
      <div className="logo-icon">
        <PredatorLogo3D accent={accent} light={light} dark={dark} size={72} />
      </div>
      <h1 className="title" data-text="Predator">Predator</h1>
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

const phaseVariants = {
  initial: { opacity: 0, filter: 'blur(10px)', scale: 0.95 },
  animate: { opacity: 1, filter: 'blur(0px)', scale: 1 },
  exit: { opacity: 0, filter: 'blur(10px)', scale: 0.95 },
}

const entryTransition = { duration: 0.55, ease: [0.16, 1, 0.3, 1] as const }

const PageWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const reducedMotion = useReducedMotion()
  // Treat the initial `null` value as reduced motion to avoid a flash of
  // animation for users who have requested reduced motion at the OS level.
  const isReduced = reducedMotion !== false
  return (
    <motion.div
      className="phase-motion"
      variants={phaseVariants}
      initial="initial"
      animate="animate"
      exit="exit"
      transition={{ duration: isReduced ? 0 : entryTransition.duration, ease: entryTransition.ease }}
    >
      {children}
    </motion.div>
  )
}

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
    // Сразу переходим к онбордингу — проверка апдейтов идёт в фоне
    const api = window.electronAPI
    if (!api) {
      // Без Electron (браузер) — показываем загрузку недолго
      const t = setTimeout(() => setPhase('onboarding-lang'), 1200)
      return () => clearTimeout(t)
    }

    // Запрос версии (быстрый)
    try { api.getAppVersion().then(setVersion).catch(() => setVersion('unknown')) } catch { setVersion('unknown') }

    // Показываем загрузку ~1.5с для плавного старта, потом выбор языка
    const enterTimer = setTimeout(() => setPhase('onboarding-lang'), 1500)

    // Фоновые слушатели апдейтов
    try {
      api.onUpdateAvailable(info => { setUpdateAvailable(true); setUpdateModal(p => ({ ...p, show: true, version: info.version, state: 'available' })) })
    } catch { /* skip */ }
    try { api.onUpdateNotAvailable(() => { /* апдейтов нет, ничего не делаем */ }) } catch { /* skip */ }
    try { api.onDownloadProgress(data => { setUpdateModal(p => ({ ...p, show: true, state: 'downloading', percent: data.percent, speed: data.bytesPerSecond > 0 ? `${(data.bytesPerSecond / 1024 / 1024).toFixed(1)} MB/s` : '', size: `${(data.transferred / 1024 / 1024).toFixed(1)} / ${(data.total / 1024 / 1024).toFixed(1)} MB` })) }) } catch { /* skip */ }
    try { api.onUpdateDownloaded(() => { setUpdateModal(p => ({ ...p, show: true, state: 'done' })) }) } catch { /* skip */ }
    try { api.onUpdateError(msg => { setUpdateModal(p => ({ ...p, state: 'error', errorMsg: msg })) }) } catch { /* skip */ }

    return () => clearTimeout(enterTimer)
  }, [])

  const hInstallUpdate = useCallback(() => { setUpdateModal(p => ({ ...p, state: 'downloading', percent: 0 })); window.electronAPI?.startDownload() }, [])
  const hRestart = useCallback(() => window.electronAPI?.restartApp(), [])
  const hCloseModal = useCallback(() => setUpdateModal(p => ({ ...p, show: false })), [])
  const hStartChecker = useCallback(() => setPhase('checker'), [])
  const hStartDashboard = useCallback(() => setPhase('dashboard'), [])
  const hNextLang = useCallback(() => {
    // Небольшая задержка для плавного перехода
    setTimeout(() => setPhase('onboarding-theme'), 150)
  }, [])

  const hNextTheme = useCallback(() => {
    setTimeout(() => setPhase('onboarding-auth'), 150)
  }, [])

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

  // ── Burn transition state ──
  const [burnState, setBurnState] = useState<{ old: ThemeColors; new: ThemeColors; newId: ThemeId } | null>(null)
  const [isBurning, setIsBurning] = useState(false)

  const handleThemeSelect = useCallback((id: ThemeId) => {
    if (id === theme) return

    // Во время онбординга — просто меняем тему без анимации сгорания,
    // чтобы оверлей не перекрывал карточки выбора темы
    if (phase === 'onboarding-theme') {
      setTheme(id)
      return
    }

    const old = THEMES[theme]
    const next = THEMES[id]
    setBurnState({ old, new: next, newId: id })
    setIsBurning(true)
  }, [theme, phase])

  const handleBurnComplete = useCallback(() => {
    if (burnState) {
      setTheme(burnState.newId)
    }
    // Small delay before removing overlay to avoid flicker
    setTimeout(() => {
      setIsBurning(false)
      setBurnState(null)
    }, 50)
  }, [burnState])

  const c = THEMES[theme]
  const subtitle = t('title')

  return (
    <ToastProvider>
    <div className="app">
      <div className="background-gradient">
        <div className="gradient-orb orb-1" /><div className="gradient-orb orb-2" /><div className="gradient-orb orb-3" />
        <ParticleBackground accentColor={c.accent} lightColor={c.light} />
      </div>
      <div className="scan-line" />
      <div className="container">
        <Logo accent={c.accent} light={c.light} dark={c.dark} subtitle={subtitle} />
        {(phase.startsWith('onboarding-') || phase === 'requesting-access') && (
          <div className="onb-steps">
            <div className={`onb-step${phase === 'onboarding-lang' ? ' active' : ' done'}`}><span className="onb-step-dot" /><span className="onb-step-label">{t('langTitle')}</span></div>
            <div className="onb-step-line" />
            <div className={`onb-step${phase === 'onboarding-theme' ? ' active' : phase === 'onboarding-auth' || phase === 'requesting-access' ? ' done' : ''}`}><span className="onb-step-dot" /><span className="onb-step-label">{t('themeTitle')}</span></div>
            <div className="onb-step-line" />
            <div className={`onb-step${phase === 'onboarding-auth' || phase === 'requesting-access' ? ' active' : ''}`}><span className="onb-step-dot" /><span className="onb-step-label">{t('authTitle')}</span></div>
          </div>
        )}

        <AnimatePresence mode="wait">
          {/* Loading */}
          {phase === 'loading' && <PageWrapper key="loading">{renderCard(<div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, width: '100%' }}><Skeleton width="64px" height="64px" radius="50%" /><Skeleton width="70%" height="16px" /><Skeleton width="50%" height="12px" /><Skeleton width="100%" height="6px" radius="3px" /></div>)}</PageWrapper>}

          {phase === 'onboarding-lang' && <PageWrapper key="onboarding-lang">{renderCard(<><p className="onb-label">{t('langTitle')}</p><p className="onb-desc">{t('langDesc')}</p>
          <div className="lang-grid">
            <button className={`lang-btn${lang === 'ru' ? ' active' : ''}`} onClick={() => setLang('ru')}><span className="lang-flag">🇷🇺</span><span className="lang-name">{t('langRu')}</span></button>
            <button className={`lang-btn${lang === 'en' ? ' active' : ''}`} onClick={() => setLang('en')}><span className="lang-flag">🇬🇧</span><span className="lang-name">{t('langEn')}</span></button>
          </div>
          <div className="onb-step-actions"><Button className="start-button" onClick={hNextLang}>{t('next')}</Button></div></>)}</PageWrapper>}

          {phase === 'onboarding-theme' && <PageWrapper key="onboarding-theme">{renderCard(<><p className="onb-label">{t('themeTitle')}</p><p className="onb-desc">{t('themeDesc')}</p>
          <div className="theme-grid-new">
            {(Object.entries(THEMES) as [ThemeId, ThemeColors][]).map(([id, th], i) => (
              <motion.button
                key={id}
                className={`theme-card-new${theme === id ? ' active' : ''}`}
                style={{
                  '--th-accent': th.accent,
                  '--th-light': th.light,
                  '--th-dark': th.dark,
                } as React.CSSProperties}
                onClick={() => handleThemeSelect(id)}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.08, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
                whileHover={{ y: -4, scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
              >
                <div className="theme-card-preview">
                  <div className="theme-card-swatch-main" style={{ background: th.accent }} />
                  <div className="theme-card-swatch-row">
                    <span className="theme-card-swatch-sm" style={{ background: th.light }} />
                    <span className="theme-card-swatch-sm" style={{ background: th.dark }} />
                  </div>
                  <div className="theme-card-preview-bg" style={{
                    background: `linear-gradient(135deg, ${th.accent}20, ${th.dark}30)`,
                  }} />
                </div>
                <span className="theme-card-name">{th.name}</span>
                {theme === id && (
                  <motion.div
                    className="theme-card-check"
                    layoutId="theme-check"
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ type: 'spring', stiffness: 400, damping: 25 }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  </motion.div>
                )}
              </motion.button>
            ))}
          </div>
          <div className="onb-step-actions"><Button className="start-button" onClick={hNextTheme}>{t('next')}</Button></div></>)}</PageWrapper>}

          {phase === 'onboarding-auth' && <PageWrapper key="onboarding-auth">{renderCard(<><p className="onb-label">{t('authTitle')}</p><p className="onb-desc">{t('authDesc')}</p>
          <div className="token-input-wrap">
            <label className="token-label">{t('tokenLabel')}</label>
            <div className="token-field">
              <input type="text" className="token-input" value={token} onChange={e => { const raw = e.target.value.replace(/[^A-Za-z0-9-]/g, ''); const clean = raw.replace(/-/g, ''); let f = ''; for (let i = 0; i < clean.length && i < 32; i++) { if (i > 0 && i % 8 === 0) f += '-'; f += clean[i] } setToken(f); setTokenError(''); setAuthError('') }} placeholder={t('authPlaceholder')} maxLength={39} />
            </div>
            {(tokenError || authError) && <p className="token-error">{tokenError || authError}</p>}
          </div>
          <Button className="start-button" onClick={hNextAuth} disabled={authLoading} style={{ marginTop: 8 }}>
            {authLoading ? <><span className="spinner" style={{ width: 16, height: 16, borderWidth: 2, position: 'relative', display: 'inline-block' }}><span className="spinner-ring" style={{ position: 'absolute', inset: 0 }} /></span> Проверка...</> : t('authBtn')}
          </Button>
          <Button className="skip-button" variant="ghost" onClick={hRequestAccess} disabled={authLoading}>{t('authAlt')}</Button></>)}</PageWrapper>}

          {phase === 'requesting-access' && <PageWrapper key="requesting-access">{renderCard(<>
          {(!requestStatus || requestStatus === 'pending') && (<><p className="onb-label">{t('requestSent')}</p><div className="request-id-badge">{t('requestId')}: #{requestId || '...'}</div><div style={{ display: 'flex', flexDirection: 'column', gap: 12, width: '100%', margin: '8px 0' }}><Skeleton width="100%" height="12px" /><Skeleton width="80%" height="12px" /><Skeleton width="60%" height="12px" /></div><Button className="skip-button" variant="ghost" onClick={() => { cancelRequest(); setPhase('onboarding-auth') }}>{t('cancel')}</Button></>)}
          {requestStatus === 'approved' && (<><div className="ready-icon"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" /><path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg></div><p className="ready-text">{t('requestApproved')}</p><p className="status-text" style={{ animation: 'none' }}>Перенаправление...</p></>)}
          {requestStatus === 'rejected' && (<><div className="error-icon-dl"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#EF4444" strokeWidth="2" /><line x1="16" y1="16" x2="32" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" /><line x1="32" y1="16" x2="16" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" /></svg></div><p className="status-text" style={{ color: '#EF4444', animation: 'none' }}>{t('requestRejected')}</p><Button className="start-button" onClick={() => setPhase('onboarding-auth')}>{t('authBtn')}</Button></>)}
        </>)}</PageWrapper>}

          {phase === 'main' && <PageWrapper key="main">{renderCard(<><div className="ready-icon"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" /><path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg></div><p className="ready-text">{t('ready')}</p>
          <div className="main-cards">
            <Magnetic><button className="main-card" onClick={hStartChecker}><div className="main-card-icon" style={{ background: 'rgba(255,255,255,0.06)' }}><IconShield size={24} color="#fff" /></div><div className="main-card-body"><span className="main-card-title">{t('startCheck')}</span><span className="main-card-desc">Deep scan for files, processes, registry, network, and memory anomalies.</span></div><span className="main-card-arrow">→</span></button></Magnetic>
            <Magnetic><button className="main-card" onClick={hStartDashboard}><div className="main-card-icon" style={{ background: 'rgba(255,255,255,0.06)' }}><IconDashboard size={24} color="#fff" /></div><div className="main-card-body"><span className="main-card-title">{t('dashboard')}</span><span className="main-card-desc">Live system overview with streaming snapshots and runtime telemetry.</span></div><span className="main-card-arrow">→</span></button></Magnetic>
          </div></>)}</PageWrapper>}

          {phase === 'checker' && <PageWrapper key="checker"><Checker lang={lang} tokenId={tokenId} onBack={hBackToMain} /></PageWrapper>}
          {phase === 'dashboard' && <PageWrapper key="dashboard"><Dashboard lang={lang} onBack={hBackToMain} /></PageWrapper>}
        </AnimatePresence>

        {burnState && (
          <ThemeBurnTransition
            isActive={isBurning}
            oldColors={burnState.old}
            newColors={burnState.new}
            onComplete={handleBurnComplete}
          />
        )}
        <UpdateModal state={updateModal} theme={theme} lang={lang} onClose={hCloseModal} onDownload={hInstallUpdate} onRestart={hRestart} />
        <Footer version={version} updateAvailable={updateAvailable} />
      </div>
    </div>
    </ToastProvider>
  )
}

export default App
