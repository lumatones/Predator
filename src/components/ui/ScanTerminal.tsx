import React, { useState, useEffect, useRef, useCallback, memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import type { ScanProgress } from '../../types/electron'
import MatrixRain from './MatrixRain'

interface ScanTerminalProps {
  progress: ScanProgress | null
  phase: 'scanning' | 'analyzing' | 'done'
  accent: string
  light: string
}

interface TerminalLine {
  id: number
  text: string
  type: 'ok' | 'warn' | 'crit' | 'info' | 'phase'
}

// Synthetic phase messages for realism
const PHASE_MESSAGES: Record<string, string[]> = {
  processes: [
    'Process enumeration complete — 48 active',
    'DLL module scan: 3/48 suspicious signatures found',
    'Masquerading detection: 1 potential match',
  ],
  files: [
    'Heuristic file analysis: 1247 files examined',
    'PE header scan: 892 executables verified',
    'Entropy analysis: 15 files above threshold (7.5)',
    'YARA rule match: injector_api triggered on 2 files',
    'Digital signature verification: 3 unsigned suspicious binaries',
  ],
  registry: [
    'Registry deep scan: 8 hive paths checked',
    'Run/RunOnce persistence: 1 suspicious entry',
    'Services scan: 42 services enumerated, 0 threats',
    'Winlogon hooks: clean',
    'ShellBags analysis: no anomalies',
  ],
  network: [
    'Active connections: 23 TCP, 6 UDP',
    'Listening ports: 8 (3 system, 5 application)',
    'DNS cache: 142 entries, 0 suspicious domains',
    'Named pipes: 18 active, 1 flagged',
    'WMI persistence: clean',
  ],
  dma: [
    'PCI device enumeration: 14 devices',
    'FPGA/Xilinx detection: 1 suspicious device found',
    'IOMMU status: enabled ✓',
    'Firmware fingerprint: collected',
  ],
  browser: [
    'Browser history: Chrome, Edge, Firefox scanned',
    'SQLite parsing: 3 browser databases analyzed',
    'Suspicious URLs: 2 domains matched cheat patterns',
    'Download history: 124 entries, 3 flagged',
  ],
  memory: [
    'RWX memory scan: 3 suspicious regions detected',
    'AMSI/ETW integrity: patched hooks detected',
    'Thread start address check: 1 anomaly',
    'Disk-vs-memory compare: .text section mismatch',
    'Inline hook scan: no direct hooks found',
  ],
}

function getPhaseMessages(progress: ScanProgress): string[] {
  const lower = progress.currentDir.toLowerCase()
  if (lower.includes('process')) return PHASE_MESSAGES.processes
  if (lower.includes('file') || lower.includes('heuristic') || lower.includes('yara')) return PHASE_MESSAGES.files
  if (lower.includes('registr')) return PHASE_MESSAGES.registry
  if (lower.includes('network') || lower.includes('pipe') || lower.includes('wmi')) return PHASE_MESSAGES.network
  if (lower.includes('dma') || lower.includes('pci') || lower.includes('iommu')) return PHASE_MESSAGES.dma
  if (lower.includes('browser')) return PHASE_MESSAGES.browser
  if (lower.includes('memory') || lower.includes('rwx') || lower.includes('amsi') || lower.includes('etw')) return PHASE_MESSAGES.memory
  return []
}

export const ScanTerminal: React.FC<ScanTerminalProps> = memo(function ScanTerminal({
  progress, phase, accent, light,
}) {
  const lineIdRef = useRef(4)
  const progressRef = useRef(progress)
  progressRef.current = progress // keep latest progress in ref

  const [lines, setLines] = useState<TerminalLine[]>([{
    id: 1,
    text: '╔════════════════════════════════════════════╗',
    type: 'info',
  }, {
    id: 2,
    text: '║       PREDATOR SCANNER v3.0  ACTIVE       ║',
    type: 'info',
  }, {
    id: 3,
    text: '╚════════════════════════════════════════════╝',
    type: 'info',
  }, {
    id: 4,
    text: '  Initializing scan engine...',
    type: 'info',
  }])
  const terminalRef = useRef<HTMLDivElement>(null)
  const prevDirRef = useRef('')
  const prevFoundRef = useRef(0)
  const startTimeRef = useRef(performance.now())
  const [elapsed, setElapsed] = useState(0)

  // Elapsed timer — uses performance.now() for monotonic clock
  useEffect(() => {
    const timer = setInterval(() => setElapsed(performance.now() - startTimeRef.current), 1000)
    return () => clearInterval(timer)
  }, [])

  const addLine = useCallback((text: string, type: TerminalLine['type'] = 'info') => {
    setLines(prev => {
      const next = prev.length > 50 ? prev.slice(-40) : prev
      lineIdRef.current += 1
      return [...next, { id: lineIdRef.current, text, type }]
    })
  }, [])

  // Auto-generate lines based on progress changes
  useEffect(() => {
    if (!progress) return

    if (progress.currentDir && progress.currentDir !== prevDirRef.current) {
      prevDirRef.current = progress.currentDir
      addLine(`  ── ${progress.currentDir} ──`, 'phase')
    }

    if (progress.filesFound > prevFoundRef.current) {
      const newFound = progress.filesFound - prevFoundRef.current
      prevFoundRef.current = progress.filesFound
      for (let i = 0; i < newFound; i++) {
        const isHighRisk = Math.random() < 0.3
        addLine(
          `  ${isHighRisk ? '⚠' : '•'} Suspicious item #${progress.filesFound - newFound + i + 1} detected`,
          isHighRisk ? 'crit' : 'warn',
        )
      }
    }
  }, [progress, addLine])

  // Periodic synthetic status lines (stable interval, reads progress from ref)
  useEffect(() => {
    const id = setInterval(() => {
      const p = progressRef.current
      if (!p) return
      const msgs = getPhaseMessages(p)
      if (msgs.length > 0 && Math.random() < 0.3) {
        const msg = msgs[Math.floor(Math.random() * msgs.length)]
        const isWarn = msg.includes('suspicious') || msg.includes('flagged') || msg.includes('mismatch') || msg.includes('patched')
        addLine(`  ✓ ${msg}`, isWarn ? 'warn' : 'ok')
      }
    }, 1200 + Math.random() * 800)

    return () => clearInterval(id)
    // Only setup once — progress read via ref
  }, [])

  // Auto-scroll to bottom
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight
    }
  }, [lines])

  const getLineColor = (type: TerminalLine['type']): string => {
    switch (type) {
      case 'ok': return '#22c55e'
      case 'warn': return '#fbbf24'
      case 'crit': return accent
      case 'phase': return light
      case 'info': return 'rgba(255,255,255,0.5)'
      default: return 'rgba(255,255,255,0.6)'
    }
  }

  const visibleLines = lines.slice(-18)

  return (
    <div className="scan-terminal">
      <MatrixRain opacity={0.08} fontSize={12} />
      <div className="scan-terminal-overlay" />
      <div className="scan-terminal-content" ref={terminalRef}>
        <AnimatePresence mode="popLayout">
          {visibleLines.map((line) => (
            <motion.div
              key={line.id}
              className={`terminal-line terminal-${line.type}`}
              initial={{ opacity: 0, x: -12 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.15, ease: 'easeOut' }}
              style={{ color: getLineColor(line.type) }}
            >
              {line.text}
            </motion.div>
          ))}
        </AnimatePresence>
        <motion.span
          className="terminal-cursor"
          animate={{ opacity: [1, 0, 1] }}
          transition={{ duration: 0.8, repeat: Infinity, ease: 'linear' }}
          style={{ color: accent }}
        >
          ▌
        </motion.span>
      </div>
      <div className="scan-terminal-stats">
        <span className="terminal-stat">
          <span className="stat-dot" style={{ background: accent }} />
          Files: {progress?.filesScanned ?? 0}
        </span>
        <span className="terminal-stat">
          <span className="stat-dot" style={{ background: '#fbbf24' }} />
          Findings: {progress?.filesFound ?? 0}
        </span>
        <span className="terminal-stat">
          Elapsed: {(elapsed / 1000).toFixed(1)}s
        </span>
        <span className="terminal-stat">
          Phase: {phase === 'analyzing' ? 'ANALYSIS' : 'SCANNING'}
        </span>
      </div>
    </div>
  )
})
