import { useState, useMemo, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import type { ScanResult } from '../../types/electron'

// ── Tier definitions ──
interface TierDef {
  id: string
  name: string
  icon: string
  description: string
  signalPrefixes: string[]   // matches in results that start with these prefixes
}

const TIERS: TierDef[] = [
  {
    id: 't1',
    name: 'Thread States',
    icon: '🧬',
    description: 'APC wait states + thread bloat in game processes',
    signalPrefixes: ['APC:thread-bloat', 'APC:user-request-wait'],
  },
  {
    id: 't2',
    name: 'Atom Tables',
    icon: '⚛️',
    description: 'Shellcode patterns in Windows global atom tables',
    signalPrefixes: ['atom-bomb'],
  },
  {
    id: 't3',
    name: 'ETW Monitor',
    icon: '📡',
    description: '5-min background trace — sustained thread creation bursts',
    signalPrefixes: ['EBAPC:sustained', 'EBAPC:thread-burst'],
  },
  {
    id: 't4',
    name: 'Thread Pool',
    icon: '🏊',
    description: 'Pool Party / WTH — WrQueue saturation analysis',
    signalPrefixes: ['TPABUSE:'],
  },
  {
    id: 't5',
    name: 'Process Hollowing',
    icon: '🎭',
    description: 'RunPE — module count, PEB path, disk-vs-memory hash',
    signalPrefixes: ['HOLLOW:'],
  },
]

// ── Tier status type ──
type TierStatus = 'clean' | 'suspicious' | 'detected'

interface TierResult {
  tier: TierDef
  status: TierStatus
  risk: 'high' | 'medium' | 'low' | 'none'
  findings: ScanResult[]
  highCount: number
  mediumCount: number
  lowCount: number
}

// ── Helpers ──

function matchTier(result: ScanResult, tier: TierDef): boolean {
  // Check fileName for signal prefix (e.g. "⚠ APC Injection: GTA5.exe — ...")
  if (tier.signalPrefixes.some(p =>
    result.fileName.toLowerCase().includes(p.toLowerCase())
  )) return true

  // Check matches array for signal strings
  return result.matches.some(m =>
    tier.signalPrefixes.some(p => m.toLowerCase().includes(p.toLowerCase()))
  )
}

function tierStatus(findings: ScanResult[]): { status: TierStatus; risk: 'high' | 'medium' | 'low' | 'none' } {
  if (findings.length === 0) return { status: 'clean', risk: 'none' }
  const hasHigh = findings.some(r => r.risk === 'critical' || r.risk === 'high')
  const hasMedium = findings.some(r => r.risk === 'medium')
  if (hasHigh) return { status: 'detected', risk: 'high' }
  if (hasMedium) return { status: 'suspicious', risk: 'medium' }
  return { status: 'suspicious', risk: 'low' }
}

// ── Status colors ──
const STATUS_COLORS: Record<TierStatus, { bg: string; border: string; dot: string; text: string; pulse: boolean }> = {
  clean:      { bg: 'rgba(34,197,94,0.06)',  border: 'rgba(34,197,94,0.2)',  dot: 'var(--color-success)', text: 'var(--color-success)', pulse: false },
  suspicious: { bg: 'rgba(245,158,11,0.06)',  border: 'rgba(245,158,11,0.2)',  dot: 'var(--color-warning)', text: 'var(--color-warning)', pulse: true },
  detected:   { bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.25)',  dot: 'var(--color-error)',  text: 'var(--color-error)',  pulse: true },
}

const STATUS_LABELS_RU: Record<TierStatus, string> = {
  clean: 'Чисто',
  suspicious: 'Подозрительно',
  detected: 'Обнаружено',
}
const STATUS_LABELS_EN: Record<TierStatus, string> = {
  clean: 'Clean',
  suspicious: 'Suspicious',
  detected: 'Detected',
}

// ── Component ──

interface ApcDashboardProps {
  results: ScanResult[]
  lang: 'ru' | 'en'
}

export function ApcDashboard({ results, lang }: ApcDashboardProps) {
  const [expandedTiers, setExpandedTiers] = useState<Set<string>>(new Set())
  const [isCollapsed, setIsCollapsed] = useState(false)

  // Analyze results per tier
  const tierResults = useMemo((): TierResult[] => {
    return TIERS.map(tier => {
      const findings = results.filter(r => matchTier(r, tier))
      const { status, risk } = tierStatus(findings)
      return {
        tier,
        status,
        risk,
        findings,
        highCount: findings.filter(r => r.risk === 'critical' || r.risk === 'high').length,
        mediumCount: findings.filter(r => r.risk === 'medium').length,
        lowCount: findings.filter(r => r.risk === 'low').length,
      }
    })
  }, [results])

  // Overall stats
  const totalFindings = tierResults.reduce((sum, t) => sum + t.findings.length, 0)
  const detectedTiers = tierResults.filter(t => t.status === 'detected').length
  const suspiciousTiers = tierResults.filter(t => t.status === 'suspicious').length
  const cleanTiers = tierResults.filter(t => t.status === 'clean').length

  // Don't render if no APC-related findings and nothing suspicious
  if (totalFindings === 0) return null

  const overallStatus: TierStatus =
    detectedTiers > 0 ? 'detected' :
    suspiciousTiers > 0 ? 'suspicious' : 'clean'

  const statusLabels = lang === 'ru' ? STATUS_LABELS_RU : STATUS_LABELS_EN

  const toggleTier = (id: string) => {
    setExpandedTiers(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // Auto-expand detected tiers once on first load
  useEffect(() => {
    const toExpand = tierResults.filter(t => t.status === 'detected').map(t => t.tier.id)
    if (toExpand.length > 0) {
      setExpandedTiers(prev => {
        const next = new Set(prev)
        toExpand.forEach(id => next.add(id))
        return next
      })
    }
  }, []) // run once on mount

  return (
    <div className="apc-dashboard">
      {/* ── Header ── */}
      <div className="apc-dashboard-header" onClick={() => setIsCollapsed(c => !c)}>
        <div className="apc-dashboard-header-left">
          <div className={`apc-dashboard-status-dot ${overallStatus}`} />
          <span className="apc-dashboard-title">
            🛡️ APC Injection Dashboard
          </span>
          <span className={`apc-dashboard-badge ${overallStatus}`}>
            {statusLabels[overallStatus]}
          </span>
        </div>
        <div className="apc-dashboard-header-right">
          <span className="apc-dashboard-summary">
            {detectedTiers > 0 && <span className="apc-stat detected">{detectedTiers} 🔴</span>}
            {suspiciousTiers > 0 && <span className="apc-stat suspicious">{suspiciousTiers} 🟡</span>}
            {cleanTiers > 0 && <span className="apc-stat clean">{cleanTiers} 🟢</span>}
          </span>
          <span className={`apc-dashboard-chevron ${isCollapsed ? '' : 'open'}`}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </span>
        </div>
      </div>

      {/* ── Tier Cards ── */}
      <AnimatePresence>
        {!isCollapsed && (
          <motion.div
            className="apc-dashboard-tiers"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
          >
            {tierResults.map((tr, i) => {
              const colors = STATUS_COLORS[tr.status]
              const isExpanded = expandedTiers.has(tr.tier.id)

              return (
                <motion.div
                  key={tr.tier.id}
                  className={`apc-tier-card ${tr.status}`}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.06, duration: 0.3, ease: 'easeOut' }}
                  style={{
                    '--card-bg': colors.bg,
                    '--card-border': colors.border,
                    '--card-dot': colors.dot,
                  } as React.CSSProperties}
                >
                  {/* Tier Header */}
                  <button className="apc-tier-header" onClick={() => toggleTier(tr.tier.id)}>
                    <div className="apc-tier-header-left">
                      {/* Pulse dot for active tiers */}
                      <span className={`apc-tier-dot ${colors.pulse ? 'pulse' : ''}`} />
                      <span className="apc-tier-icon">{tr.tier.icon}</span>
                      <div className="apc-tier-info">
                        <span className="apc-tier-name">{tr.tier.name}</span>
                        <span className="apc-tier-desc">{tr.tier.description}</span>
                      </div>
                    </div>
                    <div className="apc-tier-header-right">
                      {/* Finding counts by risk */}
                      {tr.findings.length > 0 ? (
                        <div className="apc-tier-counts">
                          {tr.highCount > 0 && <span className="apc-count high">{tr.highCount}</span>}
                          {tr.mediumCount > 0 && <span className="apc-count medium">{tr.mediumCount}</span>}
                          {tr.lowCount > 0 && <span className="apc-count low">{tr.lowCount}</span>}
                        </div>
                      ) : (
                        <span className="apc-tier-clean">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2.5">
                            <polyline points="20 6 9 17 4 12" />
                          </svg>
                        </span>
                      )}
                      <span className={`apc-tier-chevron ${isExpanded ? 'open' : ''}`}>
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </span>
                    </div>
                  </button>

                  {/* Expanded findings */}
                  <AnimatePresence>
                    {isExpanded && tr.findings.length > 0 && (
                      <motion.div
                        className="apc-tier-body"
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                      >
                        {tr.findings.map((finding, j) => (
                          <div
                            key={`${tr.tier.id}-${j}`}
                            className={`apc-finding-row ${finding.risk}`}
                          >
                            <span className={`apc-finding-risk-dot ${finding.risk}`} />
                            <div className="apc-finding-info">
                              <span className="apc-finding-name">{finding.fileName}</span>
                              <div className="apc-finding-matches">
                                {finding.matches.slice(0, 3).map((m, k) => (
                                  <span key={k} className="apc-finding-tag">{m}</span>
                                ))}
                              </div>
                            </div>
                          </div>
                        ))}
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Expanded: clean tier message */}
                  <AnimatePresence>
                    {isExpanded && tr.findings.length === 0 && (
                      <motion.div
                        className="apc-tier-body clean"
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                      >
                        <div className="apc-clean-msg">
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2">
                            <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
                            <polyline points="22 4 12 14.01 9 11.01" />
                          </svg>
                          <span>No injection indicators detected in this tier.</span>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              )
            })}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default ApcDashboard
