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
}

/**
 * Onboarding phase state machine — manages the full 5-step onboarding flow
 * (welcome → lang → theme → auth → demo) plus main navigation callbacks.
 *
 * Extracted from App.tsx (~70 lines) to keep the App component lean.
 */
export function useOnboarding(deps: UseOnboardingDeps) {
  const {
    handleAuth,
    handleRequestAccess,
    cancelRequest,
    requestStatus,
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
  // Browser fallback (no Electron API)
  useEffect(() => {
    if (smokePhase) {
      setPhase(smokePhase)
      return
    }
    const api = window.electronAPI
    if (api) return
    const t = setTimeout(() => setPhase('onboarding-welcome'), 1200)
    return () => clearTimeout(t)
  }, [smokePhase])

  // Electron: brief loading screen then welcome
  useEffect(() => {
    if (smokePhase) return
    const api = window.electronAPI
    if (!api) return
    const enterTimer = setTimeout(() => setPhase('onboarding-welcome'), 1500)
    return () => clearTimeout(enterTimer)
  }, [smokePhase])

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
  const hDemoComplete = useCallback(() => goToPhase('main'), [goToPhase])
  const hBackToMain = useCallback(() => setPhase('main'), [])

  // ── Navigation to main sections (instant, no delay) ──
  const hStartChecker = useCallback(() => setPhase('checker'), [])
  const hStartDashboard = useCallback(() => setPhase('dashboard'), [])

  // ── Auth flow ──
  const hNextAuth = useCallback(async () => {
    const success = await handleAuth()
    if (success) setPhase('onboarding-demo')
  }, [handleAuth])

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

  // ── Auto-transition to demo when access request is approved ──
  useEffect(() => {
    if (requestStatus === 'approved') {
      const timer = setTimeout(() => setPhase('onboarding-demo'), 1500)
      return () => clearTimeout(timer)
    }
  }, [requestStatus])

  return {
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
    cancelRequest,
  } as const
}
