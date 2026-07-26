/**
 * Predator — Persistent Profile
 *
 * Tracks cumulative risk scores across multiple scan sessions.
 * Detects "smart" cheaters who trigger minor alerts consistently over time
 * by escalating their profile when consistency exceeds threshold.
 *
 * Storage: JSON file at %APPDATA%/Predator/scan-history.json
 */

import fs from 'fs'
import path from 'path'
import os from 'os'

// ── Types ──

export interface SessionRecord {
  id: string
  timestamp: string
  mode: string
  scanTimeMs: number
  filesScanned: number
  highRiskCount: number
  mediumRiskCount: number
  lowRiskCount: number
  totalRiskScore: number
  topFindings: string[]
}

export interface PersistentProfile {
  sessions: SessionRecord[]
  cumulativeScore: number
  consistencyRatio: number
  trend: 'escalating' | 'stable' | 'declining'
  lastEscalation: string | null
  totalScans: number
}

// ── Config ──

const PROFILE_PATH = path.join(os.homedir(), 'AppData', 'Roaming', 'Predator', 'scan-history.json')
const MAX_SESSIONS = 20
const CONSISTENCY_WINDOW = 7 // days
const ESCALATION_CONSISTENCY_THRESHOLD = 0.7 // 70% of sessions flagged = escalate
const ESCALATION_SCORE_BOOST = 25 // bonus risk score when profile is escalated

function ensureDir(): void {
  const dir = path.dirname(PROFILE_PATH)
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true })
}

function loadProfile(): PersistentProfile {
  ensureDir()
  try {
    const data = JSON.parse(fs.readFileSync(PROFILE_PATH, 'utf-8'))
    return {
      sessions: data.sessions || [],
      cumulativeScore: data.cumulativeScore || 0,
      consistencyRatio: data.consistencyRatio || 0,
      trend: data.trend || 'stable',
      lastEscalation: data.lastEscalation || null,
      totalScans: data.totalScans || 0,
    }
  } catch {
    return {
      sessions: [],
      cumulativeScore: 0,
      consistencyRatio: 0,
      trend: 'stable',
      lastEscalation: null,
      totalScans: 0,
    }
  }
}

function saveProfile(profile: PersistentProfile): void {
  ensureDir()
  // Trim old sessions beyond MAX_SESSIONS
  if (profile.sessions.length > MAX_SESSIONS) {
    profile.sessions = profile.sessions.slice(-MAX_SESSIONS)
  }
  fs.writeFileSync(PROFILE_PATH, JSON.stringify(profile, null, 2))
}

// ── Core: record session ──

export interface ScanSummary {
  mode: string
  scanTimeMs: number
  filesScanned: number
  highRiskCount: number
  mediumRiskCount: number
  lowRiskCount: number
  topFindings: string[]
}

/**
 * Record a completed scan session and return the escalation bonus (if any).
 * Call this AFTER a scan completes.
 */
export function recordSession(summary: ScanSummary): number {
  const profile = loadProfile()

  const totalRiskScore = summary.highRiskCount * 80 + summary.mediumRiskCount * 50 + summary.lowRiskCount * 20

  const session: SessionRecord = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    timestamp: new Date().toISOString(),
    mode: summary.mode,
    scanTimeMs: summary.scanTimeMs,
    filesScanned: summary.filesScanned,
    highRiskCount: summary.highRiskCount,
    mediumRiskCount: summary.mediumRiskCount,
    lowRiskCount: summary.lowRiskCount,
    totalRiskScore,
    topFindings: summary.topFindings.slice(0, 5),
  }

  profile.sessions.push(session)
  profile.totalScans++

  // Trim
  if (profile.sessions.length > MAX_SESSIONS) {
    profile.sessions = profile.sessions.slice(-MAX_SESSIONS)
  }

  // Calculate consistency
  const now = Date.now()
  const recentSessions = profile.sessions.filter(s => {
    const age = (now - new Date(s.timestamp).getTime()) / 86400000
    return age <= CONSISTENCY_WINDOW
  })

  const flaggedCount = recentSessions.filter(s => s.totalRiskScore > 0).length
  profile.consistencyRatio = recentSessions.length > 0 ? flaggedCount / recentSessions.length : 0

  // Cumulative score (weighted: recent scans count more)
  profile.cumulativeScore = profile.sessions
    .slice(-10)
    .reduce((sum, s, i) => sum + s.totalRiskScore * (0.5 + (i / 20)), 0)

  // Trend detection
  const last3 = profile.sessions.slice(-3)
  if (last3.length >= 3) {
    const scores = last3.map(s => s.totalRiskScore)
    if (scores[2] > scores[1] && scores[1] > scores[0]) {
      profile.trend = 'escalating'
    } else if (scores[2] < scores[1] && scores[1] < scores[0]) {
      profile.trend = 'declining'
    } else {
      profile.trend = 'stable'
    }
  }

  let escalationBonus = 0

  // Escalation: high consistency + high cumulative
  if (profile.consistencyRatio >= ESCALATION_CONSISTENCY_THRESHOLD && profile.cumulativeScore > 100) {
    escalationBonus = ESCALATION_SCORE_BOOST
    profile.lastEscalation = new Date().toISOString()
  }

  saveProfile(profile)
  return escalationBonus
}

/**
 * Get the current persistent profile for the user.
 */
export function getProfile(): PersistentProfile {
  return loadProfile()
}

/**
 * Check if the user's profile should escalate findings.
 * Returns the bonus risk score to add to all findings.
 */
export function getEscalationBonus(): number {
  const profile = loadProfile()
  if (profile.consistencyRatio >= ESCALATION_CONSISTENCY_THRESHOLD && profile.cumulativeScore > 100) {
    return ESCALATION_SCORE_BOOST
  }
  return 0
}

/**
 * Get profile summary for UI display.
 */
export function getProfileSummary(): {
  totalScans: number
  consistencyPercent: number
  trend: string
  escalated: boolean
  recentFindings: number
} {
  const profile = loadProfile()
  const recentFindings = profile.sessions.slice(-5).reduce((sum, s) => sum + s.highRiskCount + s.mediumRiskCount, 0)

  return {
    totalScans: profile.totalScans,
    consistencyPercent: Math.round(profile.consistencyRatio * 100),
    trend: profile.trend,
    escalated: profile.consistencyRatio >= ESCALATION_CONSISTENCY_THRESHOLD && profile.cumulativeScore > 100,
    recentFindings,
  }
}
