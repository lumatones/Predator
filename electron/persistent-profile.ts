/**
 * Predator — Persistent Profile
 *
 * Tracks cumulative risk scores across multiple scan sessions.
 * Detects "smart" cheaters who trigger minor alerts consistently over time
 * by escalating their profile when consistency exceeds threshold.
 *
 * E19 enhancements:
 *   - Device fingerprinting (HWID-based) for cross-account tracking
 *   - Threat actor profiling (pattern-based grouping across scans)
 *   - Cross-scan pattern correlation
 *
 * Storage: JSON file at %APPDATA%/Predator/scan-history.json
 */

import fs from 'fs'
import path from 'path'
import os from 'os'
import { execWithTimeout } from './utils/exec'
import crypto from 'crypto'

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
  /** E19: Device fingerprint for cross-account tracking */
  deviceFingerprint: string | null
  /** E19: Threat actor profiles grouped by attack pattern */
  threatActors: ThreatActorProfile[]
}

// ── E19: Threat actor profile ──

export interface ThreatActorProfile {
  /** Pattern signature (hashed behavior fingerprint) */
  patternHash: string
  /** Human-readable pattern description */
  description: string
  /** Number of scans where this pattern appeared */
  occurrences: number
  /** First and last seen timestamps */
  firstSeen: string
  lastSeen: string
  /** Cheat tools associated with this pattern */
  associatedCheats: string[]
  /** Pattern confidence (0-100) — how consistently this pattern appears) */
  confidence: number
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
      deviceFingerprint: data.deviceFingerprint || null,
      threatActors: data.threatActors || [],
    }
  } catch {
    return {
      sessions: [],
      cumulativeScore: 0,
      consistencyRatio: 0,
      trend: 'stable',
      lastEscalation: null,
      totalScans: 0,
      deviceFingerprint: null,
      threatActors: [],
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

// ═══════════════════════════════════════════════════
// E19: DEVICE FINGERPRINTING
// ═══════════════════════════════════════════════════

/**
 * Generate a device fingerprint (HWID) based on system identifiers.
 * Used for cross-account tracking — cheaters who use multiple
 * Windows accounts are still linked by hardware fingerprint.
 *
 * Components:
 *   - Motherboard serial (wmic baseboard)
 *   - System UUID (wmic csproduct)
 *   - OS install date
 *   - Primary disk serial
 *
 * All components are hashed with SHA256 — no raw hardware IDs stored.
 */
export function generateDeviceFingerprint(): string {
  const components: string[] = []

  try {
    const out = execWithTimeout('wmic baseboard get serialnumber /format:csv 2>nul', { timeout: 5000 }) || ''
    const lines = out.trim().split('\n')
    if (lines.length >= 2) {
      const serial = lines[1].split(',').pop()?.trim()
      if (serial) components.push('mb:' + serial)
    }
  } catch { /* optional */ }

  try {
    const out = execWithTimeout('wmic csproduct get uuid /format:csv 2>nul', { timeout: 5000 }) || ''
    const lines = out.trim().split('\n')
    if (lines.length >= 2) {
      const uuid = lines[1].split(',').pop()?.trim()
      if (uuid) components.push('uuid:' + uuid)
    }
  } catch { /* optional */ }

  try {
    const out = execWithTimeout('wmic os get installdate /format:csv 2>nul', { timeout: 5000 }) || ''
    const lines = out.trim().split('\n')
    if (lines.length >= 2) {
      const date = lines[1].split(',').pop()?.trim()
      if (date) components.push('os:' + date)
    }
  } catch { /* optional */ }

  try {
    const out = execWithTimeout('wmic diskdrive where "Index=0" get serialnumber /format:csv 2>nul', { timeout: 5000 }) || ''
    const lines = out.trim().split('\n')
    if (lines.length >= 2) {
      const serial = lines[1].split(',').pop()?.trim()
      if (serial) components.push('disk:' + serial)
    }
  } catch { /* optional */ }

  // Fallback: use hostname + username if no HWID available
  if (components.length === 0) {
    components.push('host:' + os.hostname())
    components.push('user:' + os.userInfo().username)
  }

  const raw = components.sort().join('|')
  return crypto.createHash('sha256').update(raw).digest('hex').slice(0, 16)
}

/**
 * Get or create the device fingerprint for the current profile.
 */
export function getDeviceFingerprint(): string {
  const profile = loadProfile()
  if (profile.deviceFingerprint) return profile.deviceFingerprint

  const fp = generateDeviceFingerprint()
  profile.deviceFingerprint = fp
  saveProfile(profile)
  return fp
}

// ═══════════════════════════════════════════════════
// E19: THREAT ACTOR PROFILING
// ═══════════════════════════════════════════════════

/**
 * Hash a set of cheat findings into a behavioral pattern signature.
 * Same cheat tool used across multiple scans will generate the same hash.
 */
function hashPattern(findings: string[]): string {
  const normalized = [...new Set(findings)]
    .map(f => f.toLowerCase().replace(/[^a-z0-9]/g, ''))
    .sort()
    .join(',')
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 12)
}

/**
 * Record detected cheat tools and update threat actor profiles.
 * Call this after each scan with the list of detected cheat names/groups.
 *
 * @param detectedCheats Array of cheat names found in this scan
 * @param topFindings Top finding descriptions from the scan
 */
export function updateThreatActors(
  detectedCheats: string[],
  topFindings: string[],
): ThreatActorProfile[] {
  if (detectedCheats.length === 0) return []

  const profile = loadProfile()
  const now = new Date().toISOString()
  const patternHash = hashPattern(detectedCheats)

  // Find existing profile or create new one
  const existing = profile.threatActors.find(t => t.patternHash === patternHash)

  if (existing) {
    existing.occurrences++
    existing.lastSeen = now
    // Merge cheat names
    for (const cheat of detectedCheats) {
      if (!existing.associatedCheats.includes(cheat)) {
        existing.associatedCheats.push(cheat)
      }
    }
    existing.confidence = Math.min(
      Math.round((existing.occurrences / profile.totalScans) * 100),
      100,
    )
  } else {
    profile.threatActors.push({
      patternHash,
      description: topFindings.slice(0, 3).join('; ') || 'Unknown pattern',
      occurrences: 1,
      firstSeen: now,
      lastSeen: now,
      associatedCheats: detectedCheats,
      confidence: Math.round((1 / Math.max(profile.totalScans, 1)) * 100),
    })
  }

  // Cap threat actors at 10 (keep highest confidence)
  if (profile.threatActors.length > 10) {
    profile.threatActors.sort((a, b) => b.confidence - a.confidence)
    profile.threatActors = profile.threatActors.slice(0, 10)
  }

  saveProfile(profile)
  return profile.threatActors
}

/**
 * Get the most confident threat actor pattern (if any).
 * This is the "signature move" of the cheater — the tool they use most consistently.
 */
export function getTopThreatActor(): ThreatActorProfile | null {
  const profile = loadProfile()
  if (profile.threatActors.length === 0) return null

  const top = profile.threatActors.reduce((best, t) =>
    t.confidence > best.confidence ? t : best,
  )
  return top.confidence >= 30 ? top : null // At least 30% confidence
}

/**
 * Check if the current scan's findings correlate with known threat actors.
 * Returns the matching threat actor if a pattern match is found.
 */
export function correlateWithThreatActors(detectedCheats: string[]): ThreatActorProfile | null {
  if (detectedCheats.length === 0) return null

  const profile = loadProfile()
  const patternHash = hashPattern(detectedCheats)
  return profile.threatActors.find(t => t.patternHash === patternHash) || null
}
