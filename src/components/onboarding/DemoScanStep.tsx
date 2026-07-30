import React, { useState, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Button } from '../ui/Button'

interface DemoScanStepProps {
  demoTitle: string
  demoDesc: string
  demoStart: string
  demoScanning: string
  demoDone: string
  demoDoneDesc: string
  demoEnterApp: string
  demoFindings: string[]
  accent: string
  light: string
  onComplete: () => void
}

type DemoPhase = 'idle' | 'scanning' | 'done'

const FAKE_PHASES = [
  'Scanning processes...',
  'Heuristic file analysis...',
  'Registry deep scan...',
  'Network connections...',
  'DMA device detection...',
  'Browser history check...',
]

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ff4444',
  HIGH: '#ff8a5b',
  MEDIUM: '#fbbf24',
}

function getRisk(findings: string): keyof typeof RISK_COLORS {
  if (findings.includes('CRITICAL')) return 'CRITICAL'
  if (findings.includes('HIGH')) return 'HIGH'
  return 'MEDIUM'
}

export const DemoScanStep: React.FC<DemoScanStepProps> = ({
  demoTitle, demoDesc, demoStart, demoScanning,
  demoDone, demoDoneDesc, demoEnterApp,
  demoFindings, accent, light, onComplete,
}) => {
  const [phase, setPhase] = useState<DemoPhase>('idle')
  const [currentPhase, setCurrentPhase] = useState(0)
  const [progress, setProgress] = useState(0)
  const [foundFindings, setFoundFindings] = useState<number[]>([])
  const [terminalLines, setTerminalLines] = useState<string[]>([])
  const scanRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const foundRef = useRef<number[]>([])

  const startDemoScan = useCallback(() => {
    setPhase('scanning')
    setProgress(0)
    setCurrentPhase(0)
    setFoundFindings([])
    setTerminalLines([])
  }, [])

  useEffect(() => {
    if (phase !== 'scanning') return

    let p = 0
    let phaseIdx = 0
    const lines: string[] = []

    const addLine = (text: string) => {
      lines.push(text)
      setTerminalLines([...lines])
    }

    scanRef.current = setInterval(() => {
      p += 2 + Math.random() * 3
      if (p >= 100) {
        p = 100
        setProgress(100)
        if (scanRef.current) clearInterval(scanRef.current)
        setPhase('done')
        setFoundFindings([0, 1, 2, 3, 4])
        addLine(`  ✓ Scan complete — ${demoFindings.length} threats detected`)
        return
      }

      setProgress(Math.min(p, 99))

      // Advance through phases
      const newPhaseIdx = Math.min(Math.floor(p / (100 / FAKE_PHASES.length)), FAKE_PHASES.length - 1)
      if (newPhaseIdx !== phaseIdx) {
        phaseIdx = newPhaseIdx
        setCurrentPhase(phaseIdx)
        addLine(`  ⏳ ${FAKE_PHASES[phaseIdx]}`)
      }

      // Occasionally add a finding
      const currentFound = foundRef.current
      if (p > 20 && Math.random() < 0.15 && currentFound.length + 1 <= demoFindings.length) {
        const nextIdx = currentFound.length
        setFoundFindings(prev => {
          foundRef.current = [...prev, nextIdx]
          return foundRef.current
        })
        addLine(`  ⚠ ${demoFindings[nextIdx]}`)
      }

      // Occasionally add an OK line
      if (Math.random() < 0.3) {
        const oks = ['  ✓ Clean', '  ✓ Safe', '  ✓ Verified signature', '  ✓ No threats']
        addLine(oks[Math.floor(Math.random() * oks.length)])
      }
    }, 250 + Math.random() * 150)

    foundRef.current = foundFindings
    return () => {
      if (scanRef.current) clearInterval(scanRef.current)
    }
  }, [phase, demoFindings])

  // Reset demo when unmounted
  useEffect(() => {
    return () => {
      if (scanRef.current) clearInterval(scanRef.current)
    }
  }, [])

  const visibleLines = terminalLines.slice(-8)

  return (
    <div className="ob-demo">
      {phase === 'idle' && (
        <motion.div
          className="ob-demo-idle"
          key="idle"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
        >
          <h2 className="onb-label">{demoTitle}</h2>
          <p className="onb-desc">{demoDesc}</p>
          <div className="ob-demo-icon-wrap">
            <motion.div
              className="ob-demo-shield"
              animate={{ rotate: [0, -5, 5, 0] }}
              transition={{ duration: 4, repeat: Infinity, ease: 'easeInOut' }}
            >
              <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
                <path d="M32 4L56 16V36C56 48 38 58 32 60C26 58 8 48 8 36V16L32 4Z"
                  stroke={accent} strokeWidth="2" strokeLinejoin="round" />
                <path d="M24 32L30 38L40 26" stroke={light} strokeWidth="2.5"
                  strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </motion.div>
          </div>
          <Button className="start-button ob-welcome-btn" onClick={startDemoScan}>
            {demoStart}
          </Button>
        </motion.div>
      )}

      {phase === 'scanning' && (
        <motion.div
          className="ob-demo-scanning"
          key="scanning"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <h2 className="onb-label">{demoScanning}</h2>

          {/* Progress bar */}
          <div className="ob-demo-progress-wrap">
            <motion.div
              className="ob-demo-progress-fill"
              style={{ background: `linear-gradient(90deg, ${accent}, ${light})` }}
              animate={{ width: `${progress}%` }}
              transition={{ duration: 0.3, ease: 'linear' }}
            />
            <span className="ob-demo-progress-text">{Math.round(progress)}%</span>
          </div>

          {/* Phase indicator */}
          <div className="ob-demo-phase">
            {FAKE_PHASES[currentPhase]}
          </div>

          {/* Findings counter */}
          <div className="ob-demo-findings-count">
            <motion.span
              style={{ color: foundFindings.length > 0 ? accent : 'var(--text-secondary)' }}
              animate={foundFindings.length > 0 ? { scale: [1, 1.1, 1] } : {}}
              transition={{ duration: 0.3 }}
            >
              ⚠ {foundFindings.length}
            </motion.span>
            <span className="ob-demo-count-label">threats found</span>
          </div>

          {/* Terminal log */}
          <div className="ob-demo-terminal">
            <AnimatePresence mode="popLayout">
              {visibleLines.map((line, i) => (
                <motion.div
                  key={`${line}-${i}`}
                  className={`ob-demo-terminal-line${line.includes('⚠') ? ' warn' : line.includes('✓') ? ' ok' : ''}`}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  {line}
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </motion.div>
      )}

      {phase === 'done' && (
        <motion.div
          className="ob-demo-done"
          key="done"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4 }}
        >
          <motion.div
            className="ob-demo-done-icon"
            initial={{ scale: 0, rotate: -90 }}
            animate={{ scale: 1, rotate: 0 }}
            transition={{ type: 'spring', stiffness: 200, damping: 15, delay: 0.1 }}
          >
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
              <circle cx="24" cy="24" r="22" stroke={accent} strokeWidth="2" />
              <path d="M16 24L22 30L32 18" stroke={light} strokeWidth="3"
                strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </motion.div>
          <h2 className="onb-label">{demoDone}</h2>
          <p className="onb-desc" style={{ maxWidth: 380, textAlign: 'center' }}>{demoDoneDesc}</p>

          {/* Found threats summary */}
          <div className="ob-demo-summary">
            {demoFindings.map((f, i) => {
              const risk = getRisk(f)
              return (
                <motion.div
                  key={f}
                  className="ob-demo-finding"
                  initial={{ opacity: 0, x: -16 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.3 + i * 0.12, duration: 0.35 }}
                >
                  <span className="ob-demo-finding-dot" style={{ background: RISK_COLORS[risk] }} />
                  <span className="ob-demo-finding-text">{f}</span>
                  <span className="ob-demo-finding-badge" style={{ color: RISK_COLORS[risk], borderColor: RISK_COLORS[risk] + '40' }}>
                    {risk}
                  </span>
                </motion.div>
              )
            })}
          </div>

          <Button className="start-button ob-welcome-btn" onClick={onComplete}>
            {demoEnterApp}
          </Button>
        </motion.div>
      )}
    </div>
  )
}
