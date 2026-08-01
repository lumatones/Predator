import { useState, useRef, useCallback, useEffect } from 'react'
import type { ScanResult, ScanResponse, ScanMode } from '../types/electron'
import { tabCache } from '../pages/checker-config'

interface UseCheckerTabsOpts {
  phase: 'idle' | 'scanning' | 'done'
  results: ScanResult[]
  summary: ScanResponse['summary'] | null
  scanRef: React.MutableRefObject<boolean>
  onInitFromCache: (mode: ScanMode) => void
}

export function useCheckerTabs({ phase, results, summary, scanRef, onInitFromCache }: UseCheckerTabsOpts) {
  const [activeTab, setActiveTab] = useState<ScanMode>('full')
  const [tabTransition, setTabTransition] = useState<'enter' | 'idle' | 'exit'>('idle')
  const transitionTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Initialize from cache + cleanup timeout on unmount
  useEffect(() => {
    onInitFromCache('full')
    return () => {
      if (transitionTimer.current) clearTimeout(transitionTimer.current)
    }
  }, [])

  const handleTabChange = useCallback((tab: ScanMode) => {
    if (tab === activeTab) return
    scanRef.current = false

    if (phase === 'done' && summary) {
      tabCache.set(activeTab, { results, summary })
    }

    setTabTransition('exit')
    if (transitionTimer.current) clearTimeout(transitionTimer.current)

    transitionTimer.current = setTimeout(() => {
      setActiveTab(tab)
      onInitFromCache(tab)
      setTabTransition('enter')
      setTimeout(() => setTabTransition('idle'), 200)
    }, 150)
  }, [activeTab, phase, results, summary, scanRef, onInitFromCache])

  return { activeTab, tabTransition, handleTabChange }
}
