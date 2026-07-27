import React, { useMemo, useRef, useEffect } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import type { AppPhase, ThemeId, Lang, ThemeColors } from '../../types'
import { DEMO_FINDINGS } from '../../types'
import { WelcomeStep } from './WelcomeStep'
import { DemoScanStep } from './DemoScanStep'

// ── Step definitions ──
const STEPS: AppPhase[] = [
  'onboarding-welcome',
  'onboarding-lang',
  'onboarding-theme',
  'onboarding-auth',
  'onboarding-demo',
]

const STEP_LABELS_RU = ['Приветствие', 'Язык', 'Тема', 'Токен', 'Демо']
const STEP_LABELS_EN = ['Welcome', 'Language', 'Theme', 'Token', 'Demo']

// ── Step content transition variants ──
const stepVariants = {
  initial: (direction: number) => ({ opacity: 0, x: direction > 0 ? 24 : -24 }),
  animate: { opacity: 1, x: 0 },
  exit: (direction: number) => ({ opacity: 0, x: direction > 0 ? -24 : 24 }),
}

const transition = { duration: 0.25, ease: [0.16, 1, 0.3, 1] as const }

// ═══════════════════════════════════════════════════

interface OnboardingFlowProps {
  phase: AppPhase
  lang: Lang
  theme: ThemeId
  themes: Record<ThemeId, ThemeColors>
  token: string
  tokenError: string
  authError: string
  authLoading: boolean
  requestStatus: 'pending' | 'approved' | 'rejected' | null
  requestId: number | null
  accent: string
  light: string
  dark: string
  // Translators
  t: (key: string) => string
  // Callbacks
  onSetLang: (l: Lang) => void
  onSetTheme: (id: ThemeId) => void
  onSetToken: (t: string) => void
  onSetTokenError: (e: string) => void
  onSetAuthError: (e: string) => void
  onNextWelcome: () => void
  onNextLang: () => void
  onNextTheme: () => void
  onNextAuth: () => Promise<void>
  onRequestAccess: () => Promise<void>
  onDemoComplete: () => void
}

export const OnboardingFlow: React.FC<OnboardingFlowProps> = ({
  phase, lang, theme, themes, token, tokenError, authError, authLoading,
  accent, light, t,
  onSetLang, onSetTheme, onSetToken, onSetTokenError, onSetAuthError,
  onNextWelcome, onNextLang, onNextTheme, onNextAuth, onRequestAccess, onDemoComplete,
}) => {
  const currentStepIndex = STEPS.indexOf(phase)
  const stepLabels = useMemo(() => lang === 'ru' ? STEP_LABELS_RU : STEP_LABELS_EN, [lang])
  // Track direction for slide animation
  const prevIndexRef = useRef(currentStepIndex)
  useEffect(() => { prevIndexRef.current = currentStepIndex }, [currentStepIndex])
  const direction = currentStepIndex >= prevIndexRef.current ? 1 : -1

  return (
    <>
      {/* ── Step Indicator (5 steps) ── */}
      <div className="onb-steps onb-steps-v2">
        {STEPS.map((stepPhase, i) => {
          const isActive = stepPhase === phase
          const isDone = currentStepIndex > i
          return (
            <React.Fragment key={stepPhase}>
              {i > 0 && (
                <div className={`onb-step-line${isDone ? ' done' : ''}${isActive ? ' active' : ''}`} />
              )}
              <div className={`onb-step${isActive ? ' active' : ''}${isDone ? ' done' : ''}`}>
                <span className="onb-step-dot" />
                <span className="onb-step-label">{stepLabels[i]}</span>
              </div>
            </React.Fragment>
          )
        })}
      </div>

      {/* ── Step Content with transitions ── */}
      <div className="status-section">
        <div className="status-card">
          <AnimatePresence mode="wait">
            <motion.div
              key={phase}
              custom={direction}
              variants={stepVariants}
              initial="initial"
              animate="animate"
              exit="exit"
              transition={transition}
              style={{ width: '100%' }}
            >
          {/* Step 0: Welcome */}
          {phase === 'onboarding-welcome' && (
            <WelcomeStep
              welcomeTitle={t('welcomeTitle')}
              welcomeDesc={t('welcomeDesc')}
              welcomeStart={t('welcomeStart')}
              accent={accent}
              light={light}
              lang={lang}
              onNext={onNextWelcome}
            />
          )}

          {/* Step 1: Language */}
          {phase === 'onboarding-lang' && (
            <>
              <p className="onb-label">{t('langTitle')}</p>
              <p className="onb-desc">{t('langDesc')}</p>
              <div className="lang-grid">
                <button
                  className={`lang-btn${lang === 'ru' ? ' active' : ''}`}
                  onClick={() => onSetLang('ru')}
                >
                  <span className="lang-flag">🇷🇺</span>
                  <span className="lang-name">{t('langRu')}</span>
                </button>
                <button
                  className={`lang-btn${lang === 'en' ? ' active' : ''}`}
                  onClick={() => onSetLang('en')}
                >
                  <span className="lang-flag">🇬🇧</span>
                  <span className="lang-name">{t('langEn')}</span>
                </button>
              </div>
              <div className="onb-step-actions">
                <button className="start-button btn btn-primary" onClick={onNextLang}>
                  {t('next')}
                </button>
              </div>
            </>
          )}

          {/* Step 2: Theme */}
          {phase === 'onboarding-theme' && (
            <>
              <p className="onb-label">{t('themeTitle')}</p>
              <p className="onb-desc">{t('themeDesc')}</p>
              <div className="theme-grid-new">
                {(Object.entries(themes) as [ThemeId, ThemeColors][]).map(([id, th], i) => (
                  <motion.button
                    key={id}
                    className={`theme-card-new${theme === id ? ' active' : ''}`}
                    style={{
                      '--th-accent': th.accent,
                      '--th-light': th.light,
                      '--th-dark': th.dark,
                    } as React.CSSProperties}
                    onClick={() => onSetTheme(id)}
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
              <div className="onb-step-actions">
                <button
                  className="start-button adaptive-accent"
                  style={{ '--btn-accent': themes[theme].accent } as React.CSSProperties}
                  onClick={onNextTheme}
                >
                  {t('next')}
                </button>
              </div>
            </>
          )}

          {/* Step 3: Auth */}
          {phase === 'onboarding-auth' && (
            <>
              <p className="onb-label">{t('authTitle')}</p>
              <p className="onb-desc">{t('authDesc')}</p>
              <div className="token-input-wrap">
                <label className="token-label">{t('tokenLabel')}</label>
                <div className="token-field">
                  <input
                    type="text"
                    className="token-input"
                    value={token}
                    onChange={e => {
                      const raw = e.target.value.replace(/[^A-Za-z0-9-]/g, '')
                      const clean = raw.replace(/-/g, '')
                      let f = ''
                      for (let i = 0; i < clean.length && i < 32; i++) {
                        if (i > 0 && i % 8 === 0) f += '-'
                        f += clean[i]
                      }
                      onSetToken(f)
                      onSetTokenError('')
                      onSetAuthError('')
                    }}
                    placeholder={t('authPlaceholder')}
                    maxLength={39}
                  />
                </div>
                {(tokenError || authError) && <p className="token-error">{tokenError || authError}</p>}
              </div>
              <button className="start-button btn btn-primary" onClick={onNextAuth} disabled={authLoading} style={{ marginTop: 8 }}>
                {authLoading ? (
                  <><span className="spinner" style={{ width: 16, height: 16, borderWidth: 2, position: 'relative', display: 'inline-block' }}>
                    <span className="spinner-ring" style={{ position: 'absolute', inset: 0 }} />
                  </span> Проверка...</>
                ) : t('authBtn')}
              </button>
              <button className="skip-button btn btn-ghost" onClick={onRequestAccess} disabled={authLoading}>
                {t('authAlt')}
              </button>
            </>
          )}

          {/* Step 4: Demo Scan */}
          {phase === 'onboarding-demo' && (
            <DemoScanStep
              demoTitle={t('demoTitle')}
              demoDesc={t('demoDesc')}
              demoStart={t('demoStart')}
              demoScanning={t('demoScanning')}
              demoDone={t('demoDone')}
              demoDoneDesc={t('demoDoneDesc')}
              demoEnterApp={t('demoEnterApp')}
              demoFindings={DEMO_FINDINGS[lang]}
              accent={accent}
              light={light}
              onComplete={onDemoComplete}
            />
          )}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </>
  )
}
