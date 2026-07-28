import { useState, useEffect, useCallback } from 'react'
import type { ThemeId, ThemeColors } from '../types'
import { THEMES } from '../types'

/**
 * Theme engine — manages the selected theme, applies CSS custom properties,
 * and handles the animated burn transition between themes.
 *
 * Extracted from App.tsx (~50 lines) to keep the App component lean.
 */
export function useThemeEngine(initialTheme: ThemeId = 'predator') {
  const [theme, setTheme] = useState<ThemeId>(initialTheme)
  const [burnState, setBurnState] = useState<{
    old: ThemeColors
    new: ThemeColors
    newId: ThemeId
  } | null>(null)
  const [isBurning, setIsBurning] = useState(false)

  // ── Apply CSS custom properties whenever theme changes ──
  useEffect(() => {
    const c = THEMES[theme]
    const r = document.documentElement
    r.style.setProperty('--accent-red', c.accent)
    r.style.setProperty('--accent-orange', c.light)
    r.style.setProperty(
      '--accent-gradient',
      `linear-gradient(135deg, ${c.accent}, ${c.light}, ${c.dark})`,
    )
    r.style.setProperty('--bg-primary', c.bg)
    r.style.setProperty('--bg-secondary', c.card)
  }, [theme])

  /**
   * Simple theme setter — used during onboarding or when burn animation
   * is not needed (e.g. onboarding-theme phase where overlay blocks cards).
   */
  const setThemeSimple = useCallback((id: ThemeId) => setTheme(id), [])

  /**
   * Theme selector with optional burn animation.
   * During onboarding-theme, skip animation to avoid overlay blocking cards.
   * In all other phases, play the burn transition.
   */
  const handleThemeSelect = useCallback(
    (id: ThemeId, currentPhase?: string) => {
      if (id === theme) return

      if (currentPhase === 'onboarding-theme') {
        setTheme(id)
        return
      }

      const old = THEMES[theme]
      const next = THEMES[id]
      setBurnState({ old, new: next, newId: id })
      setIsBurning(true)
    },
    [theme],
  )

  /** Called when burn animation completes — applies the new theme. */
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

  return {
    theme,
    setTheme: setThemeSimple,
    burnState,
    isBurning,
    handleThemeSelect,
    handleBurnComplete,
  } as const
}
