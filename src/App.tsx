import React, { useEffect, useState, useCallback, useRef } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import Checker from './pages/Checker'
import Dashboard from './pages/Dashboard'
import { IconShield, IconDashboard } from './icons'
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
import { useAuth } from './hooks/useAuth'
import type { AppPhase, ThemeId, Lang, UpdateModalState, ThemeColors } from './types'
import { THEMES, T } from './types'

// ── Eye Easter egg phrases ──
const EYE_PHRASES = [
  { text: 'Не тыкай на меня!', syllables: 5, pitch: 'mid' as const },
  { text: 'Я же сказал!!!', syllables: 5, pitch: 'high' as const },
  { text: 'ХВАТИТ!', syllables: 3, pitch: 'high' as const },
  { text: 'Я предупреждал...', syllables: 6, pitch: 'low' as const },
]

const Logo: React.FC<{ accent: string; light: string; dark: string; subtitle: string }> = ({ accent, light, dark, subtitle }) => {
  const hoverCount = useRef(0)
  const [phraseIdx, setPhraseIdx] = useState(0)
  const [scaryMode, setScaryMode] = useState(false)
  const [cmdVisible, setCmdVisible] = useState(false)
  const [countdown, setCountdown] = useState(100)
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
    // Voice plays AFTER typewriter starts (700ms delay matches CSS animation delay)
    setTimeout(() => playPixelVoice(p.syllables, p.pitch), 700)

    if (c >= EYE_PHRASES.length - 1) {
      scaryTriggered.current = true
      setScaryMode(true)
      setTimeout(() => setCmdVisible(true), 1500)
    }

    hoverCount.current = c + 1
  }, [])

  // First interaction: hover to discover the eye
  const handleFirstHover = useCallback(() => {
    if (firstHoverDone.current || scaryTriggered.current) return
    advancePhrase()
  }, [advancePhrase])

  // Subsequent: CLICK to poke the eye (logical: you're poking it)
  const handleEyeClick = useCallback(() => {
    if (!firstHoverDone.current || scaryTriggered.current) return
    advancePhrase()
  }, [advancePhrase])

  // Fake rapid countdown: 100 → 0 in ~6 seconds
  useEffect(() => {
    if (!cmdVisible) return
    const timer = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 5) { clearInterval(timer); return 0 }
        return prev - 5
      })
    }, 300)
    return () => clearInterval(timer)
  }, [cmdVisible])

  // Red screen of death when countdown hits 0
  useEffect(() => {
    if (countdown === 0 && cmdVisible) {
      const t = setTimeout(() => setRedScreen(true), 400)
      return () => clearTimeout(t)
    }
  }, [countdown, cmdVisible])

  // Red screen → joke screen transition (5s red, then joke)
  useEffect(() => {
    if (!redScreen) return
    const t = setTimeout(() => {
      setRedScreen(false)
      setJokeScreen(true)
    }, 5000)
    return () => clearTimeout(t)
  }, [redScreen])

  const dismissCmd = useCallback((e?: React.MouseEvent | KeyboardEvent) => {
    if (e && 'stopPropagation' in e) e.stopPropagation()
    setCmdVisible(false)
    setRedScreen(false)
    setJokeScreen(false)
    setScaryMode(false)
    setCountdown(100)
    setPhraseIdx(0)
    hoverCount.current = 0
    scaryTriggered.current = false
    firstHoverDone.current = false
  }, [])

  // Auto-dismiss everything if user closes during joke screen
  useEffect(() => {
    if (!redScreen && !jokeScreen) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') dismissCmd(e)
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [redScreen, jokeScreen, dismissCmd])

  // Joke screen auto-dismiss after 3s
  useEffect(() => {
    if (!jokeScreen) return
    const t = setTimeout(() => {
      setJokeScreen(false)
      dismissCmd()
    }, 3000)
    return () => clearTimeout(t)
  }, [jokeScreen, dismissCmd])

  // Escape key to dismiss CMD
  useEffect(() => {
    if (!cmdVisible) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') dismissCmd(e)
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [cmdVisible, dismissCmd])

  const phrase = EYE_PHRASES[phraseIdx]

  return (
    <div className={`logo-section${scaryMode ? ' eye-scary' : ''}`}>
      <div className="logo-icon" onMouseEnter={handleFirstHover} onClick={handleEyeClick}>
        <GlassEye position="center" size={140} scanLine={false} creepiness={0.4} inline />
        {/* RPG speech bubble */}
        <div className="eye-speech">
          <div className="eye-speech-inner">
            <span className="eye-speech-text" key={phraseIdx}>{phrase.text}</span>
          </div>
        </div>
        {/* Creepy smile — appears in scary mode (no background, Cheshire-style) */}
        {scaryMode && (
          <div className="eye-smile">
            <svg width="180" height="70" viewBox="0 0 180 70" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                {/* Blood gradient for drips */}
                <linearGradient id="bloodDrip" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#cc0000" />
                  <stop offset="100%" stopColor="#660000" />
                </linearGradient>
              </defs>

              {/* ━━━ UPPER TEETH — floating, individual, some cracked ━━━ */}
              {/* Tooth 1 — leftmost, chipped */}
              <path d="M22 31 L24 38 L26 38 L28 31 L25 29Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.6" />
              <line x1="25" y1="31" x2="25" y2="36" stroke="#887766" strokeWidth="0.4" opacity="0.5" />

              {/* Tooth 2 — long, sharp */}
              <path d="M30 28 L32 38 L34 38 L36 28 L33 26Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 3 — cracked */}
              <path d="M38 27 L40 37 L42 37 L44 27 L41 25Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.6" />
              <line x1="40" y1="28" x2="41" y2="35" stroke="#665544" strokeWidth="0.7" opacity="0.7" />
              <line x1="41" y1="28" x2="40.5" y2="32" stroke="#665544" strokeWidth="0.4" opacity="0.5" />

              {/* Tooth 4 — broken off halfway */}
              <path d="M46 26 L48 31 L50 31 L52 26 L49 24Z" fill="#d4c8b0" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 5 — normal */}
              <path d="M54 25 L56 37 L58 37 L60 25 L57 23Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 6 — center-left, long */}
              <path d="M62 24 L64 38 L66 38 L68 24 L65 22Z" fill="#f5ede0" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 7 — center, longest, slightly yellowed */}
              <path d="M70 23 L72 39 L74 39 L76 23 L73 21Z" fill="#e8d8c0" stroke="#554433" strokeWidth="0.6" />
              <line x1="73" y1="24" x2="73" y2="37" stroke="#998877" strokeWidth="0.5" opacity="0.6" />

              {/* Tooth 8 — center-right */}
              <path d="M78 23 L80 38 L82 38 L84 23 L81 21Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 9 — normal */}
              <path d="M86 24 L88 37 L90 37 L92 24 L89 22Z" fill="#f2eadc" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 10 — sharp */}
              <path d="M94 25 L96 38 L98 38 L100 25 L97 23Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 11 — stained brown edge */}
              <path d="M102 26 L104 37 L106 37 L108 26 L105 24Z" fill="#ddd0b8" stroke="#554433" strokeWidth="0.6" />
              <path d="M102.5 27 L103.5 35" stroke="#998866" strokeWidth="0.6" opacity="0.5" />

              {/* Tooth 12 — broken, sharp edge */}
              <path d="M110 27 L112 35 L113 36 L114 27 L112 25Z" fill="#d0c4a8" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 13 — normal */}
              <path d="M118 28 L120 38 L122 38 L124 28 L121 26Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 14 — small, receding */}
              <path d="M126 29 L128 36 L130 36 L132 29 L129 27Z" fill="#e0d4bc" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 15 — chipped corner */}
              <path d="M134 30 L136 37 L138 37 L139 30 L136 28Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.6" />
              <path d="M138 30 L136 36" stroke="#887766" strokeWidth="0.5" opacity="0.5" />

              {/* Tooth 16 — rightmost, crooked */}
              <path d="M142 31 L143 38 L145 38 L147 31 L144 29Z" fill="#e4d8c0" stroke="#554433" strokeWidth="0.6" />

              {/* Tooth 17 — tiny, barely there */}
              <path d="M148 33 L149 37 L151 37 L152 33 L150 31Z" fill="#d8ccb0" stroke="#554433" strokeWidth="0.6" />

              {/* ━━━ LOWER TEETH — smaller, sharper, floating ━━━ */}
              <path d="M24 40 L25 34 L27 34 L28 40Z" fill="#ddd0b8" stroke="#554433" strokeWidth="0.5" />
              <path d="M32 40 L33 33 L35 33 L36 40Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.5" />
              <path d="M40 40 L42 32 L44 32 L45 40Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.5" />
              <path d="M48 41 L50 31 L52 31 L53 41Z" fill="#e4d8c0" stroke="#554433" strokeWidth="0.5" />
              {/* Missing tooth — just empty space */}
              <path d="M62 41 L64 32 L66 32 L67 41Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.5" />
              <path d="M70 41 L72 31 L74 31 L75 41Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.5" />
              <path d="M78 42 L80 32 L82 32 L83 42Z" fill="#f2eadc" stroke="#554433" strokeWidth="0.5" />
              <path d="M86 42 L88 32 L90 32 L91 42Z" fill="#e4d8c0" stroke="#554433" strokeWidth="0.5" />
              <path d="M94 41 L96 31 L98 31 L99 41Z" fill="#f0e8d8" stroke="#554433" strokeWidth="0.5" />
              <path d="M102 41 L104 32 L106 32 L107 41Z" fill="#ddd0b8" stroke="#554433" strokeWidth="0.5" />
              <path d="M110 40 L112 33 L114 33 L115 40Z" fill="#e8dcc8" stroke="#554433" strokeWidth="0.5" />
              {/* Broken lower tooth */}
              <path d="M118 40 L120 34 L121 34 L122 40Z" fill="#d0c0a0" stroke="#554433" strokeWidth="0.5" />
              <path d="M120 34 L119 38" stroke="#887766" strokeWidth="0.5" />
              <path d="M126 40 L128 34 L130 34 L131 40Z" fill="#e4d8c0" stroke="#554433" strokeWidth="0.5" />
              <path d="M134 39 L136 34 L138 34 L139 39Z" fill="#ddd0b8" stroke="#554433" strokeWidth="0.5" />
              <path d="M142 39 L144 35 L146 35 L147 39Z" fill="#e0d4bc" stroke="#554433" strokeWidth="0.5" />

              {/* ━━━ BLOOD — dripping from between teeth ━━━ */}
              {/* Blood between teeth */}
              <path d="M34 35 Q36 40 34 42" stroke="#cc0000" strokeWidth="1.5" fill="none" opacity="0.6" />
              <path d="M62 36 Q64 41 62 43" stroke="#bb0000" strokeWidth="1.8" fill="none" opacity="0.7" />
              <path d="M94 36 Q96 41 94 43" stroke="#cc0000" strokeWidth="1.2" fill="none" opacity="0.5" />

              {/* Blood drips falling from teeth */}
              <path d="M34 42 Q33 49 34 53 Q35 49 34 42Z" fill="url(#bloodDrip)" opacity="0.8">
                <animate attributeName="opacity" values="0.8;1;0.8" dur="1.5s" repeatCount="indefinite" />
              </path>
              <path d="M64 43 Q63 51 64 56 Q65 51 64 43Z" fill="url(#bloodDrip)" opacity="0.75">
                <animate attributeName="opacity" values="0.75;0.95;0.75" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M94 43 Q93 48 94 52 Q95 48 94 43Z" fill="url(#bloodDrip)" opacity="0.7">
                <animate attributeName="opacity" values="0.7;0.9;0.7" dur="1.8s" repeatCount="indefinite" />
              </path>

              {/* Blood droplets */}
              <circle cx="34" cy="55" r="2.5" fill="#cc0000" opacity="0.5">
                <animate attributeName="opacity" values="0.5;0.8;0.5" dur="3s" repeatCount="indefinite" />
                <animate attributeName="r" values="2.5;3;2.5" dur="4s" repeatCount="indefinite" />
              </circle>
              <circle cx="64" cy="58" r="2" fill="#cc0000" opacity="0.4">
                <animate attributeName="opacity" values="0.4;0.7;0.4" dur="2.8s" repeatCount="indefinite" />
              </circle>

              {/* ━━━ CORNER STRETCH MARKS — skin tearing at smile edges ━━━ */}
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

      {/* JOKE SCREEN — same blood-red style, reveals it was a prank */}
      {jokeScreen && (
        <div className="red-screen red-screen--joke">
          <div className="red-screen-text red-screen-text--joke">ЭТО БЫЛА ШУТКА</div>
          <div className="red-screen-sub red-screen-sub--joke">JUST KIDDING... RELAX</div>
        </div>
      )}

      {/* Fake CMD terminal overlay */}
      {cmdVisible && !redScreen && !jokeScreen && (
        <div className="fake-cmd" onClick={dismissCmd}>
          <div className="fake-cmd-titlebar">
            <span className="fake-cmd-dot fake-cmd-close" onClick={dismissCmd} title="Закрыть" />
            <span className="fake-cmd-dot" />
            <span className="fake-cmd-dot" />
            <span className="fake-cmd-title">C:\Windows\System32\cmd.exe</span>
          </div>
          <div className="fake-cmd-body">
            <span className="fake-cmd-prompt">C:\Windows\System32&gt;</span>
            <span className="fake-cmd-cmd"> shutdown /s /t 100</span>
            {/* Countdown */}
            <div className="fake-cmd-countdown">
              {countdown > 0 ? (
                <>
                  Система завершит работу через: <span className="fake-cmd-timer">{countdown}</span> сек.
                </>
              ) : (
                <span className="fake-cmd-done" />
              )}
            </div>
          </div>
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
  const [settingsOpen, setSettingsOpen] = useState(false)

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
      const t = setTimeout(() => setPhase('onboarding-welcome'), 1200)
      return () => clearTimeout(t)
    }

    // Запрос версии (быстрый)
    try { api.getAppVersion().then(setVersion).catch(() => setVersion('unknown')) } catch { setVersion('unknown') }

    // Показываем загрузку ~1.5с для плавного старта, потом приветствие
    const enterTimer = setTimeout(() => setPhase('onboarding-welcome'), 1500)

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
  const hNextWelcome = useCallback(() => {
    setTimeout(() => setPhase('onboarding-lang'), 150)
  }, [])

  const hNextLang = useCallback(() => {
    setTimeout(() => setPhase('onboarding-theme'), 150)
  }, [])

  const hNextTheme = useCallback(() => {
    setTimeout(() => setPhase('onboarding-auth'), 150)
  }, [])

  const hDemoComplete = useCallback(() => {
    setTimeout(() => setPhase('main'), 150)
  }, [])

  const hNextAuth = useCallback(async () => {
    const success = await handleAuth()
    if (success) setPhase('onboarding-demo')
  }, [handleAuth])

  // ── Keyboard shortcuts ──
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
      const ctrl = e.ctrlKey || e.metaKey
      if (ctrl && e.shiftKey && e.key === 'S') { e.preventDefault(); if (phase === 'main') setPhase('checker'); return }
      if (e.key === 'Escape') { setSettingsOpen(false); return }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [phase])

  // Auto-transition to demo when access request is approved
  useEffect(() => {
    if (requestStatus === 'approved') {
      const timer = setTimeout(() => setPhase('onboarding-demo'), 1500)
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

  const hSetLang = useCallback((l: Lang) => setLang(l), [])
  const hSetThemeOnboarding = useCallback((id: ThemeId) => setTheme(id), [])

  const hBackToMain = useCallback(() => setPhase('main'), [])

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
        {/* ── Onboarding v2 (5-step flow) ── */}
        {phase.startsWith('onboarding-') && (
          <PageWrapper key="onboarding">
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
              onSetLang={hSetLang}
              onSetTheme={hSetThemeOnboarding}
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
          </PageWrapper>
        )}

        <AnimatePresence mode="wait">
          {/* Loading */}
          {phase === 'loading' && <PageWrapper key="loading">{renderCard(<div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, width: '100%' }}><Skeleton width="64px" height="64px" radius="50%" /><Skeleton width="70%" height="16px" /><Skeleton width="50%" height="12px" /><Skeleton width="100%" height="6px" radius="3px" /></div>)}</PageWrapper>}

          {/* Requesting access (overlay during onboarding-auth) */}
          {phase === 'requesting-access' && <PageWrapper key="requesting-access">{renderCard(<>
          {(!requestStatus || requestStatus === 'pending') && (<><p className="onb-label">{t('requestSent')}</p><div className="request-id-badge">{t('requestId')}: #{requestId || '...'}</div><div style={{ display: 'flex', flexDirection: 'column', gap: 12, width: '100%', margin: '8px 0' }}><Skeleton width="100%" height="12px" /><Skeleton width="80%" height="12px" /><Skeleton width="60%" height="12px" /></div><Button className="skip-button" variant="ghost" onClick={() => { cancelRequest(); setPhase('onboarding-auth') }}>{t('cancel')}</Button></>)}
          {requestStatus === 'approved' && (<><div className="ready-icon"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" /><path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg></div><p className="ready-text">{t('requestApproved')}</p><p className="status-text" style={{ animation: 'none' }}>Перенаправление...</p></>)}
          {requestStatus === 'rejected' && (<><div className="error-icon-dl"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#EF4444" strokeWidth="2" /><line x1="16" y1="16" x2="32" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" /><line x1="32" y1="16" x2="16" y2="32" stroke="#EF4444" strokeWidth="3" strokeLinecap="round" /></svg></div><p className="status-text" style={{ color: '#EF4444', animation: 'none' }}>{t('requestRejected')}</p><Button className="start-button" onClick={() => setPhase('onboarding-auth')}>{t('authBtn')}</Button></>)}
        </>)}</PageWrapper>}

          {phase === 'main' && <PageWrapper key="main">{renderCard(<><div className="ready-icon"><svg width="48" height="48" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="22" stroke="#22c55e" strokeWidth="2" /><path d="M16 24L22 30L32 18" stroke="#22c55e" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg></div><p className="ready-text">{t('ready')}</p>
          <div className="main-cards">
            <Magnetic><button className="main-card" onClick={hStartChecker}><div className="main-card-icon"><IconShield size={24} color="#fff" /></div><div className="main-card-body"><span className="main-card-title">{t('startCheck')}</span><span className="main-card-desc">Deep scan for files, processes, registry, network, and memory anomalies.</span></div><span className="main-card-arrow">→</span></button></Magnetic>
            <Magnetic><button className="main-card" onClick={hStartDashboard}><div className="main-card-icon"><IconDashboard size={24} color="#fff" /></div><div className="main-card-body"><span className="main-card-title">{t('dashboard')}</span><span className="main-card-desc">Live system overview with streaming snapshots and runtime telemetry.</span></div><span className="main-card-arrow">→</span></button></Magnetic>
          </div></>)}</PageWrapper>}

          {phase === 'checker' && <PageWrapper key="checker"><Checker lang={lang} tokenId={tokenId} onBack={hBackToMain} accent={c.accent} light={c.light} dark={c.dark} /></PageWrapper>}
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
        {/* Settings trigger (visible on main/checker/dashboard) */}
      {(phase === 'main' || phase === 'checker' || phase === 'dashboard') && (
        <button className="settings-trigger" onClick={() => setSettingsOpen(true)} title="Settings">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
          </svg>
        </button>
      )}

      <SettingsPanel
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        currentTheme={theme}
        currentLang={lang}
        onThemeChange={handleThemeSelect}
        lang={lang}
      />

      <UpdateModal state={updateModal} theme={theme} lang={lang} onClose={hCloseModal} onDownload={hInstallUpdate} onRestart={hRestart} />
        <Footer version={version} updateAvailable={updateAvailable} />
      </div>

    </div>
    </ToastProvider>
  )
}

export default App
