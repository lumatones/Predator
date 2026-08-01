import { useState, useCallback, useEffect } from 'react'
import type { AppPhase, Lang } from '../types'

/**
 * Dependencies injected from useAuth + parent component.
 * The hook doesn't call useAuth itself — it receives the auth API
 * via props to stay pure and testable.
 */
export interface UseOnboardingDeps {
  handleAuth: () => Promise<boolean>
  handleRequestAccess: () => Promise<boolean>
  cancelRequest: () => void
  requestStatus: string | null
  lang: Lang
  /**
   * True when onboarding was completed in a previous session — skip straight to main.
   * `null` while the persisted config is still loading (keep showing the loading screen).
   */
  onboardingComplete: boolean | null
  /** Persist the completed flag once the user passes the auth step. */
  onCompleteOnboarding: () => void
}

/**
 * Onboarding phase state machine — manages the 4-step onboarding flow
 * (welcome → lang → theme → auth) plus main navigation callbacks.
 *
 * Extracted from App.tsx (~70 lines) to keep the App component lean.
 */
export function useOnboarding(deps: UseOnboardingDeps) {
  const {
    handleAuth,
    handleRequestAccess,
    cancelRequest,
    requestStatus,
    onboardingComplete,
    onCompleteOnboarding,
  } = deps

  const [phase, setPhase] = useState<AppPhase>('loading')
  const smokeTarget = import.meta.env.DEV ? new URLSearchParams(window.location.search).get('smoke') : null
  const smokePhase: AppPhase | null = smokeTarget === 'checker'
    ? 'checker'
    : smokeTarget === 'main'
      ? 'main'
      : smokeTarget === 'dashboard'
        ? 'dashboard'
        : null

  // ── Enter onboarding on mount ──
  // Wait for persisted config so a completed onboarding never flashes the welcome screen.
  useEffect(() => {
    if (smokePhase) {
      setPhase(smokePhase)
      return
    }
    if (onboardingComplete === null) return
    const api = window.electronAPI
    const delay = api ? 1500 : 1200
    const t = setTimeout(() => setPhase(onboardingComplete ? 'main' : 'onboarding-welcome'), delay)
    return () => clearTimeout(t)
  }, [smokePhase, onboardingComplete])

  // ── Phase transitions (150ms delay for smooth Framer Motion exit→enter) ──
  const goToPhase = useCallback(
    (p: AppPhase) => {
      setTimeout(() => setPhase(p), 150)
    },
    [],
  )

  const hNextWelcome = useCallback(() => goToPhase('onboarding-lang'), [goToPhase])
  const hNextLang = useCallback(() => goToPhase('onboarding-theme'), [goToPhase])
  const hNextTheme = useCallback(() => goToPhase('onboarding-auth'), [goToPhase])
  const hBackToMain = useCallback(() => setPhase('main'), [])

  // ── Navigation to main sections (instant, no delay) ──
  const hStartChecker = useCallback(() => setPhase('checker'), [])
  const hStartDashboard = useCallback(() => setPhase('dashboard'), [])

  // ── Auth flow ──
  const hNextAuth = useCallback(async () => {
    const success = await handleAuth()
    if (success) {
      onCompleteOnboarding()
      setPhase('main')
    }
  }, [handleAuth, onCompleteOnboarding])

  const hRequestAccess = useCallback(async () => {
    const ok = await handleRequestAccess()
    if (ok) setPhase('requesting-access')
  }, [handleRequestAccess])

  // ── Keyboard shortcuts (global) ──
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      )
        return
      const ctrl = e.ctrlKey || e.metaKey
      // Ctrl+Shift+S → jump to Checker from main
      if (ctrl && e.shiftKey && e.key === 'S') {
        e.preventDefault()
        if (phase === 'main') setPhase('checker')
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [phase])

  // ── Auto-transition to main when access request is approved ──
  useEffect(() => {
    if (requestStatus === 'approved') {
      onCompleteOnboarding()
      const timer = setTimeout(() => setPhase('main'), 1500)
      return () => clearTimeout(timer)
    }
  }, [requestStatus, onCompleteOnboarding])

  return {
    phase,
    setPhase,
    hNextWelcome,
    hNextLang,
    hNextTheme,
    hNextAuth,
    hStartChecker,
    hStartDashboard,
    hBackToMain,
    hRequestAccess,
    cancelRequest,
  } as const
}
