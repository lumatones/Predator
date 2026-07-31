import React, { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import Checker from './pages/Checker'
import Dashboard from './pages/Dashboard'
import { IconShield, IconDashboard } from './icons'
import ErrorBoundary from './components/ErrorBoundary'
import UpdateModal from './components/ui/UpdateModal'
import ParticleBackground from './components/ui/ParticleBackground'
import GlassEye from './components/ui/GlassEye'
import { playPixelVoice } from './utils/pixel-voice'
import ThemeBurnTransition from './components/ui/ThemeBurnTransition'
import { ToastProvider } from './components/ui/ToastProvider'
import { Skeleton } from './components/ui/Skeleton'
import { Magnetic } from './components/ui/Magnetic'
import { Button } from './components/ui/Button'
import { OnboardingFlow } from './components/onboarding/OnboardingFlow'
import { SettingsPanel } from './components/ui/SettingsPanel'
import { MusicPlayer } from './components/ui/MusicPlayer'
import { MiniPlayer } from './components/ui/MiniPlayer'
import { MusicPlayerContext, useMusicPlayer } from './hooks/useMusicPlayer'
import { useAuth } from './hooks/useAuth'
import { useThemeEngine } from './hooks/useThemeEngine'
import { useUpdateManager } from './hooks/useUpdateManager'
import { useOnboarding } from './hooks/useOnboarding'
import type { ThemeId, Lang } from './types'
import { THEMES, T } from './types'

// ── Eye Easter egg phrases ──
const EYE_PHRASES = [
  { text: 'Не тыкай на меня!', syllables: 5, pitch: 'mid'  as const },
  { text: 'Я же сказал!!!',     syllables: 5, pitch: 'high' as const },
  { text: 'ХВАТИТ!',           syllables: 3, pitch: 'high' as const },
  { text: 'Я предупреждал...',  syllables: 6, pitch: 'low'  as const },
]

const Logo: React.FC<{ subtitle: string }> = ({ subtitle }) => {
  const hoverCount = useRef(0)
  const [phraseIdx, setPhraseIdx] = useState(0)
  const [scaryMode, setScaryMode] = useState(false)
  const [redScreen, setRedScreen] = useState(false)
  const [jokeScreen, setJokeScreen] = useState(false)
  const scaryTriggered = useRef(false)
  const firstHoverDone = useRef(false)

  const advancePhrase = useCallback(() => {
    if (scaryTriggered.current) return
    firstHoverDone.current = true
    const c = hoverCount.current
    const nextIdx = Math.min(c, EYE_PHRASES.length - 1)
    setPhraseIdx(nextIdx)

    const p = EYE_PHRASES[nextIdx]
    setTimeout(() => playPixelVoice(p.syllables, p.pitch), 700)

    if (c >= EYE_PHRASES.length - 1) {
      scaryTriggered.current = true
      setScaryMode(true)
    }

    hoverCount.current = c + 1
  }, [])

  const handleFirstHover = useCallback(() => {
    if (firstHoverDone.current || scaryTriggered.current) return
    advancePhrase()
  }, [advancePhrase])

  const handleEyeClick = useCallback(() => {
    if (!firstHoverDone.current || scaryTriggered.current) return
    advancePhrase()
  }, [advancePhrase])

  // Red screen of death — triggers 2.5s after scary mode
  useEffect(() => {
    if (!scaryMode) return
    const t = setTimeout(() => setRedScreen(true), 2500)
    return () => clearTimeout(t)
  }, [scaryMode])

  // Red screen → joke screen (5s red, then joke)
  useEffect(() => {
    if (!redScreen) return
    const t = setTimeout(() => {
      setRedScreen(false)
      setJokeScreen(true)
    }, 5000)
    return () => clearTimeout(t)
  }, [redScreen])

  // Joke screen → dismiss after 3s
  useEffect(() => {
    if (!jokeScreen) return
    const t = setTimeout(() => {
      setJokeScreen(false)
      setScaryMode(false)
      setPhraseIdx(0)
      hoverCount.current = 0
      scaryTriggered.current = false
      firstHoverDone.current = false
    }, 3000)
    return () => clearTimeout(t)
  }, [jokeScreen])

  // Escape dismisses screens
  useEffect(() => {
    if (!redScreen && !jokeScreen) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setRedScreen(false)
        setJokeScreen(false)
        setScaryMode(false)
        setPhraseIdx(0)
        hoverCount.current = 0
        scaryTriggered.current = false
        firstHoverDone.current = false
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [redScreen, jokeScreen])

  const phrase = EYE_PHRASES[phraseIdx]

  return (
    <div className={`logo-section${scaryMode ? ' eye-scary' : ''}`}>
      <div className="logo-icon" onMouseEnter={handleFirstHover} onClick={handleEyeClick}>
        <GlassEye
          position="center"
          size={140}
          scanLine={false}
          creepiness={0.4}
          inline
        />
        {/* RPG speech bubble */}
        <div className="eye-speech">
          <div className="eye-speech-inner">
            <span className="eye-speech-text" key={phraseIdx}>{phrase.text}</span>
          </div>
        </div>
        {/* Creepy smile — Cheshire-style, appears in scary mode */}
        {scaryMode && (
          <div className="eye-smile">
            <svg width="180" height="70" viewBox="0 0 180 70" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="bloodDrip" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#cc0000" />
                  <stop offset="100%" stopColor="#660000" />
                </linearGradient>
              </defs>

              {/* ━━━ UPPER TEETH ━━━ */}
              <path d="M22 31 L24 38 L26 38 L28 31 L25 29Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.6" />
              <line x1="25" y1="31" x2="25" y2="36" stroke="#887766" strokeWidth="0.4" opacity="0.5" />
              <path d="M30 28 L32 38 L34 38 L36 28 L33 26Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.6" />
              <path d="M38 27 L40 37 L42 37 L44 27 L41 25Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.6" />
              <line x1="40" y1="28" x2="41" y2="35" stroke="#665544" strokeWidth="0.7" opacity="0.7" />
              <line x1="41" y1="28" x2="40.5" y2="32" stroke="#665544" strokeWidth="0.4" opacity="0.5" />
              <path d="M46 26 L48 31 L50 31 L52 26 L49 24Z" fill="#d4c8b0" stroke="#554433" strokeWidth="0.6" />
              <path d="M54 25 L56 37 L58 37 L60 25 L57 23Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.6" />
              <path d="M62 24 L64 38 L66 38 L68 24 L65 22Z" fill="#f5ede0" stroke="#554433" strokeWidth="0.6" />
              <path d="M70 23 L72 39 L74 39 L76 23 L73 21Z" fill="#e8d8c0" stroke="#554433" strokeWidth="0.6" />
              <line x1="73" y1="24" x2="73" y2="37" stroke="#998877" strokeWidth="0.5" opacity="0.6" />
              <path d="M78 23 L80 38 L82 38 L84 23 L81 21Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.6" />
              <path d="M86 24 L88 37 L90 37 L92 24 L89 22Z" fill="#f2eadc" stroke="#554433" strokeWidth="0.6" />
              <path d="M94 25 L96 38 L98 38 L100 25 L97 23Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.6" />
              <path d="M102 26 L104 37 L106 37 L108 26 L105 24Z" fill="#ddd0b8" stroke="#554433" strokeWidth="0.6" />
              <path d="M102.5 27 L103.5 35" stroke="#998866" strokeWidth="0.6" opacity="0.5" />
              <path d="M110 27 L112 35 L113 36 L114 27 L112 25Z" fill="#d0c4a8" stroke="#554433" strokeWidth="0.6" />
              <path d="M118 28 L120 38 L122 38 L124 28 L121 26Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.6" />
              <path d="M126 29 L128 36 L130 36 L132 29 L129 27Z" fill="#e0d4bc" stroke="#554433" strokeWidth="0.6" />
              <path d="M134 30 L136 37 L138 37 L139 30 L136 28Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.6" />
              <path d="M138 30 L136 36" stroke="#887766" strokeWidth="0.5" opacity="0.5" />
              <path d="M142 31 L143 38 L145 38 L147 31 L144 29Z" fill="#e4d8c0" stroke="#554433" strokeWidth="0.6" />
              <path d="M148 33 L149 37 L151 37 L152 33 L150 31Z" fill="#d8ccb0" stroke="#554433" strokeWidth="0.6" />

              {/* ━━━ LOWER TEETH ━━━ */}
              <path d="M24 40 L25 34 L27 34 L28 40Z" fill="#ddd0b8" stroke="#554433" strokeWidth="0.5" />
              <path d="M32 40 L33 33 L35 33 L36 40Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.5" />
              <path d="M40 40 L42 32 L44 32 L45 40Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.5" />
              <path d="M48 41 L50 31 L52 31 L53 41Z" fill="#e4d8c0" stroke="#554433" strokeWidth="0.5" />
              <path d="M62 41 L64 32 L66 32 L67 41Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.5" />
              <path d="M70 41 L72 31 L74 31 L75 41Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.5" />
              <path d="M78 42 L80 32 L82 32 L83 42Z" fill="#f2eadc" stroke="#554433" strokeWidth="0.5" />
              <path d="M86 42 L88 32 L90 32 L91 42Z" fill="#e4d8c0" stroke="#554433" strokeWidth="0.5" />
              <path d="M94 41 L96 31 L98 31 L99 41Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.5" />
              <path d="M102 41 L104 32 L106 32 L107 41Z" fill="#ddd0b8" stroke="#554433" strokeWidth="0.5" />
              <path d="M110 40 L112 33 L114 33 L115 40Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.5" />
              <path d="M118 40 L120 34 L121 34 L122 40Z" fill="#d0c0a0" stroke="#554433" strokeWidth="0.5" />
              <path d="M120 34 L119 38" stroke="#887766" strokeWidth="0.5" />
              <path d="M126 40 L128 34 L130 34 L131 40Z" fill="#e4d8c0" stroke="#554433" strokeWidth="0.5" />
              <path d="M134 39 L136 34 L138 34 L139 39Z" fill="#ddd0b8" stroke="#554433" strokeWidth="0.5" />
              <path d="M142 39 L144 35 L146 35 L147 39Z" fill="#e0d4bc" stroke="#554433" strokeWidth="0.5" />

              {/* ━━━ BLOOD ━━━ */}
              <path d="M34 35 Q36 40 34 42" stroke="#cc0000" strokeWidth="1.5" fill="none" opacity="0.6" />
              <path d="M62 36 Q64 41 62 43" stroke="#bb0000" strokeWidth="1.8" fill="none" opacity="0.7" />
              <path d="M94 36 Q96 41 94 43" stroke="#cc0000" strokeWidth="1.2" fill="none" opacity="0.5" />
              <path d="M34 42 Q33 49 34 53 Q35 49 34 42Z" fill="url(#bloodDrip)" opacity="0.8">
                <animate attributeName="opacity" values="0.8;1;0.8" dur="1.5s" repeatCount="indefinite" />
              </path>
              <path d="M64 43 Q63 51 64 56 Q65 51 64 43Z" fill="url(#bloodDrip)" opacity="0.75">
                <animate attributeName="opacity" values="0.75;0.95;0.75" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M94 43 Q93 48 94 52 Q95 48 94 43Z" fill="url(#bloodDrip)" opacity="0.7">
                <animate attributeName="opacity" values="0.7;0.9;0.7" dur="1.8s" repeatCount="indefinite" />
              </path>
              <circle cx="34" cy="55" r="2.5" fill="#cc0000" opacity="0.5">
                <animate attributeName="opacity" values="0.5;0.8;0.5" dur="3s" repeatCount="indefinite" />
                <animate attributeName="r" values="2.5;3;2.5" dur="4s" repeatCount="indefinite" />
              </circle>
              <circle cx="64" cy="58" r="2" fill="#cc0000" opacity="0.4">
                <animate attributeName="opacity" values="0.4;0.7;0.4" dur="2.8s" repeatCount="indefinite" />
              </circle>

              {/* ━━━ CORNER STRETCH MARKS ━━━ */}
              <path d="M14 34 Q6 32 4 28" stroke="#cc0000" strokeWidth="1.2" fill="none" opacity="0.5" />
              <path d="M16 36 Q8 36 5 34" stroke="#990000" strokeWidth="0.8" fill="none" opacity="0.4" />
              <path d="M164 34 Q172 32 174 28" stroke="#cc0000" strokeWidth="1.2" fill="none" opacity="0.5" />
              <path d="M162 36 Q170 36 173 34" stroke="#990000" strokeWidth="0.8" fill="none" opacity="0.4" />
            </svg>
          </div>
        )}
      </div>
      <h1 className="title" data-text="Predator">Predator</h1>
      <p className="subtitle">{subtitle}</p>

      {/* RED SCREEN OF DEATH */}
      {redScreen && (
        <div className="red-screen">
          <div className="red-screen-text">PREDATOR</div>
          <div className="red-screen-sub">HAS TAKEN CONTROL</div>
        </div>
      )}

      {/* JOKE SCREEN */}
      {jokeScreen && (
        <div className="red-screen red-screen--joke">
          <div className="red-screen-text red-screen-text--joke">ЭТО БЫЛА ШУТКА</div>
          <div className="red-screen-sub red-screen-sub--joke">JUST KIDDING... RELAX 😅</div>
        </div>
      )}
    </div>
  )
}

const Footer = React.memo(function Footer({ version, updateAvailable }: {
  version: string; updateAvailable: boolean
}) {
  return (
    <div className="footer">
      <span className="version">v{version || '0.0.3'}{updateAvailable && <span className="update-indicator" title="Update Available" />}</span>
      <span className="dot">•</span>
      <span className="secure"><span className="status-dot status-dot--green" /> Secure Connection</span>
    </div>
  )
})

const renderCard = (children: React.ReactNode) => (
  <div className="status-section"><div className="status-card">{children}</div></div>
)

const phaseVariants = {
  initial: (dir: number) => ({ opacity: 0, filter: 'blur(10px)', scale: 0.95, x: dir > 0 ? 30 : -30 }),
  animate: { opacity: 1, filter: 'blur(0px)', scale: 1, x: 0 },
  exit: (dir: number) => ({ opacity: 0, filter: 'blur(10px)', scale: 0.95, x: dir > 0 ? -30 : 30 }),
}

const entryTransition = { duration: 0.5, ease: [0.16, 1, 0.3, 1] as const }

const phaseOrder: Record<string, number> = {
  'onboarding-welcome': 0, 'onboarding-lang': 1, 'onboarding-theme': 2,
  'onboarding-auth': 3, 'onboarding-demo': 4,
  'loading': 5, 'requesting-access': 6, 'main': 7, 'checker': 8, 'dashboard': 9,
}

const PageWrapper: React.FC<{ children: React.ReactNode; phase: string }> = ({ children, phase }) => {
  const reducedMotion = useReducedMotion()
  const isReduced = reducedMotion !== false
  const prevRef = useRef(phase)
  const dir = (phaseOrder[phase] ?? 0) >= (phaseOrder[prevRef.current] ?? 0) ? 1 : -1
  useEffect(() => { prevRef.current = phase }, [phase])
  return (
    <motion.div
      className="phase-motion"
      custom={dir}
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
  const [lang, setLang] = useState<Lang>('ru')
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [musicOpen, setMusicOpen] = useState(false)

  const musicPlayer = useMusicPlayer()

  const {
    token, setToken,
    tokenId,
    tokenError, setTokenError,
    authLoading,
    authError, setAuthError,
    requestId, requestStatus,
    handleAuth,
    handleRequestAccess,
    cancelRequest,
  } = useAuth(lang)

  const {
    theme,
    setTheme,
    burnState,
    isBurning,
    handleThemeSelect,
    handleBurnComplete,
  } = useThemeEngine('predator')

  const {
    version,
    updateAvailable,
    updateModal,
    hInstallUpdate,
    hRestart,
    hCloseModal,
  } = useUpdateManager()

  const {
    phase,
    setPhase,
    hNextWelcome,
    hNextLang,
    hNextTheme,
    hNextAuth,
    hDemoComplete,
    hStartChecker,
    hStartDashboard,
    hBackToMain,
    hRequestAccess,
  } = useOnboarding({
    handleAuth,
    handleRequestAccess,
    cancelRequest,
    requestStatus,
    lang,
  })

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
      if (e.key === 'Escape') setSettingsOpen(false)
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  const t = useMemo(() => (key: string) => T[lang][key] || key, [lang])

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
        <Logo subtitle={subtitle} />
        {phase.startsWith('onboarding-') && (
          <PageWrapper key="onboarding" phase={phase}>
            <ErrorBoundary name="Onboarding">
            <OnboardingFlow
              phase={phase}
              lang={lang}
              theme={theme}
              themes={THEMES}
              token={token}
              tokenError={tokenError}
              authError={authError}
              authLoading={authLoading}
              requestStatus={requestStatus}
              requestId={requestId}
              accent={c.accent}
              light={c.light}
              dark={c.dark}
              t={t}
            onSetLang={setLang}
            onSetTheme={setTheme}
              onSetToken={setToken}
              onSetTokenError={setTokenError}
              onSetAuthError={setAuthError}
              onNextWelcome={hNextWelcome}
              onNextLang={hNextLang}
              onNextTheme={hNextTheme}
              onNextAuth={hNextAuth}
              onRequestAccess={hRequestAccess}
              onDemoComplete={hDemoComplete}
            />
            </ErrorBoundary>
          </PageWrapper>
        )}

        <AnimatePresence mode="wait">
          {phase === 'loading' && <PageWrapper key="loading" phase={phase}>{renderCard(<div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, width: '100%' }}><Skeleton width="64px" height="64px" radius="50%" /><Skeleton width="70%" height="16px" /><Skeleton width="50%" height="12px" /><Skeleton width="100%" height="6px" radius="3px" /></div>)}</PageWrapper>}

          {phase === 'requesting-access' && <PageWrapper key="requesting-access" phase={phase}>{renderCard(<>
          {(!requestStatus || requestStatus === 'pending') && (<><p className="onb-label">{t('requestSent')}</p><div className="request-id-badge">{t('requestId')}: #{requestId || '...'}</div><div style={{ display: 'flex', flexDirection: 'column', gap: 12, width: '100%', margin: '8px 0' }}><Skeleton width="100%" height="12px" /><Skeleton width="80%" height="12px" /><Skeleton width="60%" height="12px" /></div><Button className="skip-button" variant="ghost" onClick={() => { cancelRequest(); setPhase('onboarding-auth') }}>{t('cancel')}</Button></>)}
          {requestStatus === 'approved' && (<><div className="ready-icon"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" /><path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg></div><p className="ready-text">{t('requestApproved')}</p><p className="status-text" style={{ animation: 'none' }}>Перенаправление...</p></>)}
          {requestStatus === 'rejected' && (<><div className="error-icon-dl"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#EF4444" strokeWidth="2" /><line x1="16" y1="16" x2="32" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" /><line x1="32" y1="16" x2="16" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" /></svg></div><p className="status-text" style={{ color: '#EF4444', animation: 'none' }}>{t('requestRejected')}</p><Button className="start-button" onClick={() => setPhase('onboarding-auth')}>{t('authBtn')}</Button></>)}
        </>)}</PageWrapper>}

          {phase === 'main' && <PageWrapper key="main" phase={phase}><ErrorBoundary name="MainMenu">{renderCard(<><div className="ready-icon"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" /><path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg></div><p className="ready-text">{t('ready')}</p>
          <div className="main-cards">
            <Magnetic><motion.button className="main-card" onClick={hStartChecker} whileHover={{ scale: 1.02, y: -2 }} whileTap={{ scale: 0.96 }} transition={{ type: 'spring', stiffness: 400, damping: 25 }}><div className="main-card-icon"><IconShield size={24} color="#fff" /></div><div className="main-card-body"><span className="main-card-title">{t('startCheck')}</span><span className="main-card-desc">Deep scan for files, processes, registry, network, and memory anomalies.</span></div><span className="main-card-arrow">→</span></motion.button></Magnetic>
            <Magnetic><motion.button className="main-card" onClick={hStartDashboard} whileHover={{ scale: 1.02, y: -2 }} whileTap={{ scale: 0.96 }} transition={{ type: 'spring', stiffness: 400, damping: 25 }}><div className="main-card-icon"><IconDashboard size={24} color="#fff" /></div><div className="main-card-body"><span className="main-card-title">{t('dashboard')}</span><span className="main-card-desc">Live system overview with streaming snapshots and runtime telemetry.</span></div><span className="main-card-arrow">→</span></motion.button></Magnetic>
          </div></>)}</ErrorBoundary></PageWrapper>}

          {phase === 'checker' && <PageWrapper key="checker" phase={phase}><ErrorBoundary name="Checker"><Checker lang={lang} tokenId={tokenId} onBack={hBackToMain} accent={c.accent} light={c.light} dark={c.dark} /></ErrorBoundary></PageWrapper>}
          {phase === 'dashboard' && <PageWrapper key="dashboard" phase={phase}><ErrorBoundary name="Dashboard"><Dashboard lang={lang} onBack={hBackToMain} /></ErrorBoundary></PageWrapper>}
        </AnimatePresence>

        {burnState && (
          <ThemeBurnTransition
            isActive={isBurning}
            oldColors={burnState.old}
            newColors={burnState.new}
            onComplete={handleBurnComplete}
          />
        )}
      {(phase === 'main' || phase === 'checker' || phase === 'dashboard') && (
        <div className="floating-buttons">
          <motion.button className="settings-trigger" onClick={() => setMusicOpen(true)} title="Music" whileHover={{ scale: 1.08, y: -1 }} whileTap={{ scale: 0.93 }} transition={{ type: 'spring', stiffness: 400, damping: 25 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>
            </svg>
            <span className="settings-trigger-label">{lang === 'ru' ? 'Музыка' : 'Music'}</span>
          </motion.button>
          <motion.button className="settings-trigger" onClick={() => setSettingsOpen(true)} title="Settings" whileHover={{ scale: 1.08, y: -1 }} whileTap={{ scale: 0.93 }} transition={{ type: 'spring', stiffness: 400, damping: 25 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            <span className="settings-trigger-label">{lang === 'ru' ? 'Настройки' : 'Settings'}</span>
          </motion.button>
        </div>
      )}        <SettingsPanel
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        currentTheme={theme}
        currentLang={lang}
        onThemeChange={(id: ThemeId) => handleThemeSelect(id, phase)}
        lang={lang}
      />
      <MusicPlayerContext.Provider value={musicPlayer}>
        <MusicPlayer
          open={musicOpen}
          onClose={() => setMusicOpen(false)}
          accent={c.accent}
          light={c.light}
          dark={c.dark}
          lang={lang}
        />
        <MiniPlayer
          onOpenFull={() => setMusicOpen(true)}
          accent={c.accent}
        />
      </MusicPlayerContext.Provider>

      <UpdateModal state={updateModal} theme={theme} lang={lang} onClose={hCloseModal} onDownload={hInstallUpdate} onRestart={hRestart} />
        <Footer version={version} updateAvailable={updateAvailable} />
      </div>

    </div>
    </ToastProvider>
  )
}

export default App
