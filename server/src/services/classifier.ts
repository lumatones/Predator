/**
 * Predator — Smart Classifier v2
 *
 * Multi-layer classification engine that combines:
 *   - Exact hash matching (SHA256 / partial hash)
 *   - File name analysis (cheat names, masquerading)
 *   - Folder path analysis (known cheat directories)
 *   - Match content analysis (cheat keywords, patterns)
 *   - Finding kind weighting (e.g. DMA findings > browser findings)
 *   - Correlation engine (multiple weak signals → confident verdict)
 *   - Crowdsourcing (community-voted safe/malicious)
 *
 * Architecture:
 *   ┌─────────────┐     ┌──────────────────┐     ┌──────────┐
 *   │ Classifier   │────▶│ Signal Analyzers │────▶│ Scorer   │
 *   │ Input        │     │  - hashMatch     │     │ Engine   │
 *   │  {sha256,    │     │  - fileMatch     │     │          │
 *   │   fileName,  │     │  - pathMatch     │     │ score >= │
 *   │   matches,   │     │  - keywordMatch  │     │ 70 → mal │
 *   │   ...}       │     │  - kindWeight    │     │ score <= │
 *   └─────────────┘     │  - correlation    │     │ 20 → safe │
 *                       └──────────────────┘     │ else pen │
 *                                                └──────────┘
 */

import { query } from '../config/database'
import {
  matchCheatFileName,
  matchCheatFolder,
  matchCheatKeywords,
  isHardwareDma,
  isCleanerActivity,
  FINDING_KIND_WEIGHTS,
} from './cheat-knowledge'
import { matchTlsh } from './tlsh-matcher'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export type Classification = 'safe' | 'malicious' | 'pending'

export interface ClassifierInput {
  sha256?: string
  partialHash?: string
  tlsh?: string
  filePath?: string
  fileName: string
  fileType: string
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  pcUsername: string
  /** Source mode or finding kind: 'process', 'dma', 'cleaner', 'file', 'registry', 'browser', etc. */
  findingKind?: string
  /** File size in bytes */
  size?: number
  /** Whether the file is digitally signed */
  hasValidSignature?: boolean
}

export interface ClassifierResult {
  classification: Classification
  reason: string
  autoConfirmed: boolean
  /** Underlying score [0..100] */
  score: number
  /** Breakdown of signals for debugging */
  breakdown?: SignalBreakdown
}

export interface SignalBreakdown {
  totalScore: number
  threshold: {
    malicious: number
    safe: number
  }
  signals: SignalEntry[]
}

export interface SignalEntry {
  name: string
  score: number
  details: string
}

export interface ClassifierStats {
  totalClassified: number
  autoSafe: number
  autoMalicious: number
  pending: number
}

// ═══════════════════════════════════════════════════
// THRESHOLDS
// ═══════════════════════════════════════════════════

const THRESHOLDS = {
  /** Score >= MALICIOUS → auto-classify as malicious */
  MALICIOUS: 70,
  /** Score <= SAFE → auto-classify as safe */
  SAFE: 20,
  /** Minimum confirm_count for safe-files DB to auto-trust */
  SAFE_FILE_MIN_CONFIRMATIONS: 5,
  /** Minimum unique PCs for crowdsource safe */
  CROWDSOURCE_SAFE_MIN_PCS: 10,
  /** Minimum unique PCs for crowdsource malicious */
  CROWDSOURCE_MALICIOUS_MIN_PCS: 5,
  /** Correlation bonus threshold — if n distinct weak signals, add bonus */
  CORRELATION_MIN_SIGNALS: 3,
  /** Correlation bonus points */
  CORRELATION_BONUS: 25,
  /** DMA auto-malicious threshold (lower because DMA is inherently suspicious) */
  DMA_MALICIOUS_THRESHOLD: 50,
  /** Cleaner auto-malicious threshold */
  CLEANER_MALICIOUS_THRESHOLD: 55,
}

// ═══════════════════════════════════════════════════
// TRUSTED SYSTEM ROOTS
// ═══════════════════════════════════════════════════

const TRUSTED_SYSTEM_ROOTS = [
  'c:\\windows\\system32\\',
  'c:\\windows\\syswow64\\',
  'c:\\windows\\winsxs\\',
  'c:\\windows\\microsoft.net\\',
  'c:\\program files\\',
  'c:\\program files (x86)\\',
  'c:\\programdata\\microsoft\\',
]

// ═══════════════════════════════════════════════════
// SIGNAL ANALYZERS
// ═══════════════════════════════════════════════════

/**
 * RULE 1: Exact SHA256 hash match in confirmed cheat DB.
 * Score: +100 (immediate malicious regardless of other signals).
 */
async function signalHashMatch(sha256: string | undefined): Promise<SignalEntry | null> {
  if (!sha256) return null
  try {
    const rows = await query<{ cnt: number }[]>(
      'SELECT COUNT(*) AS cnt FROM suspicious_hashes WHERE sha256 = ? AND status = ?',
      [sha256.toLowerCase(), 'confirmed']
    )
    if ((rows[0]?.cnt || 0) > 0) {
      return { name: 'hash_match', score: 100, details: 'SHA256 confirmed as cheat by admin' }
    }
  } catch { /* ignore */ }
  return null
}

/**
 * RULE 2: Safe file database check (partial hash or SHA256).
 * Score: -80 (overrides almost everything).
 */
async function signalSafeFile(
  partialHash: string | undefined,
  sha256: string | undefined,
  filePath: string | undefined,
  fileName: string,
): Promise<SignalEntry | null> {
  try {
    const hashesToCheck = [partialHash, sha256].filter(Boolean) as string[]
    for (const hash of hashesToCheck) {
      if (!hash || hash.length !== 64) continue
      const rows = await query<{ confirm_count: number }[]>(
        'SELECT confirm_count FROM safe_files WHERE partial_hash = ? AND confirm_count >= ?',
        [hash.toLowerCase(), THRESHOLDS.SAFE_FILE_MIN_CONFIRMATIONS]
      )
      if (rows.length > 0) {
        return {
          name: 'safe_file_db',
          score: -80,
          details: `Safe file confirmed by ${rows[0].confirm_count} devices`,
        }
      }
    }

    // System path heuristic
    if (filePath) {
      const lower = filePath.toLowerCase()
      if (
        (lower.includes('\\system32\\') || lower.includes('\\syswow64\\')) &&
        (lower.endsWith('.dll') || lower.endsWith('.exe'))
      ) {
        return {
          name: 'system_path',
          score: -40,
          details: `System directory file (${fileName})`,
        }
      }
    }
  } catch { /* ignore */ }
  return null
}

/**
 * RULE 3: File name analysis.
 * Scores: cheat name +40, masquerading +30, cheat DLL +35.
 */
function signalFileName(name: string): SignalEntry | null {
  const result = matchCheatFileName(name)
  if (!result.matched) return null

  const first = result.names[0]
  let score = 0
  let label = ''

  if (first.startsWith('known_cheat_exe:')) {
    score = 40
    label = `Known cheat executable: ${first.replace('known_cheat_exe:', '')}`
  } else if (first.startsWith('known_cheat_dll:')) {
    score = 35
    label = `Known cheat library: ${first.replace('known_cheat_dll:', '')}`
  } else if (first.startsWith('masquerading:')) {
    score = 30
    label = `Masquerading as legitimate file: ${first.replace('masquerading:', '')}`
  }

  return score > 0 ? { name: 'file_name', score, details: label } : null
}

/**
 * RULE 4: Folder path analysis.
 * Score per match: +15 each (max +45).
 */
function signalFolderPath(path: string | undefined): SignalEntry | null {
  if (!path) return null
  const result = matchCheatFolder(path)
  if (!result.matched) return null

  const score = Math.min(result.folders.length * 15, 45)
  return {
    name: 'folder_path',
    score,
    details: `Cheat-related folder(s): ${result.folders.join(', ')}`,
  }
}

/**
 * RULE 5: Match content analysis.
 * High keywords: +20 each (max +60)
 * Medium keywords: +8 each (max +32)
 * Behavioral indicators: +5 each (max +20)
 */
function signalMatchKeywords(matches: string[]): SignalEntry | null {
  if (!matches || matches.length === 0) return null
  const result = matchCheatKeywords(matches)

  if (result.high.length === 0 && result.medium.length === 0 && result.behavioral.length === 0) {
    return null
  }

  // Cap individual contributions
  const highScore = Math.min(result.high.length * 20, 60)
  const mediumScore = Math.min(result.medium.length * 8, 32)
  const behavioralScore = Math.min(result.behavioral.length * 5, 20)
  const totalScore = highScore + mediumScore + behavioralScore

  const parts: string[] = []
  if (result.high.length > 0) parts.push(`${result.high.length} high-signal keyword(s)`)
  if (result.medium.length > 0) parts.push(`${result.medium.length} medium-signal keyword(s)`)
  if (result.behavioral.length > 0) parts.push(`${result.behavioral.length} behavioral indicator(s)`)

  return {
    name: 'match_keywords',
    score: totalScore,
    details: parts.join('; '),
  }
}

/**
 * RULE 6: Finding kind weight.
 * Different detection types get different relevance multipliers.
 * E.g. DMA findings are inherently more suspicious than browser history.
 */
function signalFindingKind(findingKind: string | undefined, risk: string): SignalEntry | null {
  if (!findingKind) return null
  const weight = FINDING_KIND_WEIGHTS[findingKind.toLowerCase()]
  if (!weight || weight <= 1.0) return null

  // Only add positive signal if finding kind has elevated weight
  const baseScore = risk === 'high' ? 15 : risk === 'medium' ? 8 : 0
  const weightedScore = Math.round(baseScore * (weight - 1.0) * 2)

  if (weightedScore <= 0) return null

  return {
    name: 'finding_kind',
    score: weightedScore,
    details: `${findingKind} finding type (weight: ${weight.toFixed(1)}x)`,
  }
}

/**
 * RULE 7: DMA hardware detection (separate because it's higher confidence).
 */
function signalDmaHardware(findingKind: string | undefined, matches: string[], risk: string): SignalEntry | null {
  if (!isHardwareDma(findingKind, matches)) return null

  let score = 25 // base score for DMA suspicion
  if (risk === 'high') score += 20
  if (findingKind === 'dma') score += 15

  return {
    name: 'dma_hardware',
    score,
    details: 'DMA/hardware detection indicators',
  }
}

/**
 * RULE 8: Cleaner / anti-forensic detection.
 */
function signalCleaner(findingKind: string | undefined, matches: string[], risk: string): SignalEntry | null {
  if (!isCleanerActivity(findingKind, matches)) return null

  let score = 15
  if (risk === 'high') score += 15
  if (findingKind === 'cleaner') score += 10

  return {
    name: 'cleaner_activity',
    score,
    details: 'Anti-forensic / cleaner activity detected',
  }
}

/**
 * RULE 9: Trusted system path (negative signal — reduces score).
 * If the file has a valid digital signature, give extra safe points.
 */
function signalTrustedPath(
  path: string | undefined,
  risk: string,
  hasValidSignature?: boolean,
): SignalEntry | null {
  if (!path) return null
  const lower = path.toLowerCase()
  for (const root of TRUSTED_SYSTEM_ROOTS) {
    if (lower.startsWith(root)) {
      let reduction = risk === 'low' ? -30 : risk === 'medium' ? -15 : 0
      // Signed binary in system path — even safer
      if (reduction < 0 && hasValidSignature) {
        reduction -= 15
      }
      if (reduction < 0) {
        return {
          name: 'trusted_path',
          score: reduction,
          details: `Trusted system path: ${root.slice(0, 40)}...${hasValidSignature ? ' (digitally signed)' : ''}`,
        }
      }
    }
  }
  return null
}

/**
 * RULE 10: TLSH fuzzy hash matching.
 * If the finding has a TLSH hash, compare against confirmed cheat TLSH hashes.
 * Score: +50 if distance <= threshold (size-aware).
 */
async function signalTlshMatch(
  tlsh: string | undefined,
  size: number | undefined,
): Promise<SignalEntry | null> {
  if (!tlsh || tlsh.length < 10) return null

  try {
    const result = await matchTlsh(tlsh, size)
    if (result) {
      return {
        name: 'tlsh_match',
        score: 50,
        details: `TLSH fuzzy match (distance: ${result.distance}/${result.threshold}, matched SHA256: ${result.matchedSha256.slice(0, 16)}...)`,
      }
    }
  } catch { /* ignore */ }
  return null
}

/**
 * RULE 11: Correlation engine.
 * If 3+ distinct signal categories are present (none dominant), add bonus.
 * This detects when multiple weak indicators together form a strong case.
 */
function signalCorrelation(signals: SignalEntry[]): SignalEntry | null {
  const positiveSignals = signals.filter(s => s.score > 0)

  // Remove auto-triggering signals from count (they already decide)
  const autoSignals = new Set(['hash_match', 'safe_file_db'])
  const normalSignals = positiveSignals.filter(s => !autoSignals.has(s.name))

  if (normalSignals.length >= THRESHOLDS.CORRELATION_MIN_SIGNALS) {
    const categories = new Set(normalSignals.map(s => s.name))
    if (categories.size >= 2) {
      return {
        name: 'correlation',
        score: THRESHOLDS.CORRELATION_BONUS,
        details: `${normalSignals.length} distinct signals from ${categories.size} categories → correlation bonus`,
      }
    }
  }
  return null
}

// ═══════════════════════════════════════════════════
// ORCHESTRATOR
// ═══════════════════════════════════════════════════

export async function classifyFinding(input: ClassifierInput): Promise<ClassifierResult> {
  const { sha256, partialHash, filePath, fileName, risk, matches, findingKind, pcUsername } = input

  // ── Step 1: Gather all signals ──
  const signals: SignalEntry[] = []

  // Run hash checks first (fastest)
  const hashSignal = await signalHashMatch(sha256)
  if (hashSignal) signals.push(hashSignal)

  // Run safe file check
  const safeSignal = await signalSafeFile(partialHash, sha256, filePath, fileName)
  if (safeSignal) signals.push(safeSignal)

  // If hash immediately confirms malicious, skip further analysis
  const hashMatch = signals.find(s => s.name === 'hash_match')
  if (hashMatch && hashMatch.score >= 100) {
    const breakdown: SignalBreakdown = { totalScore: 100, threshold: { malicious: THRESHOLDS.MALICIOUS, safe: THRESHOLDS.SAFE }, signals }
    return {
      classification: 'malicious',
      reason: hashMatch.details,
      autoConfirmed: true,
      score: 100,
      breakdown,
    }
  }

  // If immediately safe, skip further analysis
  const safeDbMatch = signals.find(s => s.name === 'safe_file_db')
  if (safeDbMatch && safeDbMatch.score <= -80) {
    const breakdown: SignalBreakdown = { totalScore: 0, threshold: { malicious: THRESHOLDS.MALICIOUS, safe: THRESHOLDS.SAFE }, signals }
    return {
      classification: 'safe',
      reason: safeDbMatch.details,
      autoConfirmed: true,
      score: 0,
      breakdown,
    }
  }

  // Run remaining signal analyzers in parallel
  const remainingSignals = await Promise.all([
    signalFileName(fileName),
    signalFolderPath(filePath),
    signalMatchKeywords(matches),
    signalFindingKind(findingKind, risk),
    signalDmaHardware(findingKind, matches, risk),
    signalCleaner(findingKind, matches, risk),
    signalTrustedPath(filePath, risk, input.hasValidSignature),
    signalTlshMatch(input.tlsh, input.size),
  ])

  for (const s of remainingSignals) {
    if (s) signals.push(s)
  }

  // ── Step 2: Correlation engine ──
  const correlationSignal = signalCorrelation(signals)
  if (correlationSignal) signals.push(correlationSignal)

  // ── Step 3: Calculate total score ──
  let totalScore = signals.reduce((sum, s) => sum + s.score, 0)
  totalScore = Math.max(0, Math.min(100, totalScore))

  // ── Step 4: Apply thresholds ──
  // DMA/cleaner findings have lower thresholds
  const isDma = signals.some(s => s.name === 'dma_hardware')
  const isCleaner = signals.some(s => s.name === 'cleaner_activity')
  const maliciousThreshold = isDma ? THRESHOLDS.DMA_MALICIOUS_THRESHOLD
    : isCleaner ? THRESHOLDS.CLEANER_MALICIOUS_THRESHOLD
    : THRESHOLDS.MALICIOUS

  const breakdown: SignalBreakdown = {
    totalScore,
    threshold: { malicious: maliciousThreshold, safe: THRESHOLDS.SAFE },
    signals,
  }

  if (totalScore >= maliciousThreshold) {
    const topSignals = signals
      .filter(s => s.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
    const reasons = topSignals.map(s => s.details)
    return {
      classification: 'malicious',
      reason: reasons.join('; '),
      autoConfirmed: true,
      score: totalScore,
      breakdown,
    }
  }

  if (totalScore <= THRESHOLDS.SAFE) {
    // Try to find an auto-safe reason
    const safeReasons = signals
      .filter(s => s.score < 0)
      .sort((a, b) => a.score - b.score)
    if (safeReasons.length > 0) {
      return {
        classification: 'safe',
        reason: safeReasons[0].details,
        autoConfirmed: true,
        score: totalScore,
        breakdown,
      }
    }
    // No negative signals — safe because nothing triggered
    return {
      classification: 'safe',
      reason: `Low risk score (${totalScore}) with no strong indicators`,
      autoConfirmed: true,
      score: totalScore,
      breakdown,
    }
  }

  // ── Step 5: Crowdsourcing (for pending range) ──
  if (sha256) {
    const crowdResult = await checkCrowdsource(sha256, risk, pcUsername, totalScore)
    if (crowdResult) return crowdResult
  }

  // ── Default: pending (needs admin review) ──
  return {
    classification: 'pending',
    reason: `Score ${totalScore}/${maliciousThreshold} — requires admin review`,
    autoConfirmed: false,
    score: totalScore,
    breakdown,
  }
}

// ═══════════════════════════════════════════════════
// CROWDSOURCING
// ═══════════════════════════════════════════════════

async function checkCrowdsource(
  sha256: string,
  risk: string,
  _pcUsername: string,
  _currentScore: number,
): Promise<ClassifierResult | null> {
  try {
    const rows = await query<{ unique_pcs: number; avg_risk_score: number }[]>(
      `SELECT
         COUNT(DISTINCT pc_username) AS unique_pcs,
         AVG(risk_score) AS avg_risk_score
       FROM suspicious_hashes
       WHERE sha256 = ? AND status = 'pending'`,
      [sha256.toLowerCase()]
    )

    const uniquePcs = rows[0]?.unique_pcs || 0
    const avgRisk = rows[0]?.avg_risk_score || 0

    // Many PCs report low risk → safe
    if (uniquePcs >= THRESHOLDS.CROWDSOURCE_SAFE_MIN_PCS && avgRisk < 30) {
      return {
        classification: 'safe',
        reason: `Crowdsourced: ${uniquePcs} PCs report low risk (avg score: ${avgRisk.toFixed(0)})`,
        autoConfirmed: true,
        score: 5,
      }
    }

    // Many PCs report high risk → malicious (overrides borderline score)
    if (uniquePcs >= THRESHOLDS.CROWDSOURCE_MALICIOUS_MIN_PCS && risk === 'high') {
      return {
        classification: 'malicious',
        reason: `Crowdsourced: ${uniquePcs} PCs report HIGH risk`,
        autoConfirmed: true,
        score: 85,
      }
    }

    return null
  } catch { return null }
}

// ═══════════════════════════════════════════════════
// BATCH CLASSIFICATION
// ═══════════════════════════════════════════════════

export async function classifyBatch(
  findings: ClassifierInput[],
): Promise<{
  stats: ClassifierStats
  pendingFindings: ClassifierInput[]
  autoClassified: Array<{ input: ClassifierInput; result: ClassifierResult }>
}> {
  const stats: ClassifierStats = { totalClassified: 0, autoSafe: 0, autoMalicious: 0, pending: 0 }
  const pendingFindings: ClassifierInput[] = []
  const autoClassified: Array<{ input: ClassifierInput; result: ClassifierResult }> = []

  for (const finding of findings) {
    const result = await classifyFinding(finding)
    stats.totalClassified++

    if (result.classification === 'safe') {
      stats.autoSafe++
      autoClassified.push({ input: finding, result })
      await autoAddToSafeFiles(finding)
    } else if (result.classification === 'malicious') {
      stats.autoMalicious++
      autoClassified.push({ input: finding, result })
      await autoConfirmHash(finding, result)
    } else {
      stats.pending++
      pendingFindings.push(finding)
    }
  }

  return { stats, pendingFindings, autoClassified }
}

// ═══════════════════════════════════════════════════
// AUTO-ACTIONS
// ═══════════════════════════════════════════════════

async function autoAddToSafeFiles(finding: ClassifierInput): Promise<void> {
  try {
    const hashForSafeDb = finding.partialHash || finding.sha256
    if (!hashForSafeDb) return
    await query(
      `INSERT INTO safe_files (partial_hash, file_name, file_size, confirm_count)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE confirm_count = confirm_count + 1, last_seen = NOW()`,
      [hashForSafeDb.toLowerCase(), finding.fileName, finding.size || 0, THRESHOLDS.SAFE_FILE_MIN_CONFIRMATIONS]
    )
  } catch { /* best effort */ }
}

async function autoConfirmHash(finding: ClassifierInput, result: ClassifierResult): Promise<void> {
  try {
    if (!finding.sha256) return
    const updated = await query<{ affectedRows: number }>(
      `UPDATE suspicious_hashes
       SET status = 'confirmed', auto_classified = TRUE, auto_reason = ?, risk_score = ?, reviewed_at = NOW()
       WHERE sha256 = ? AND status = 'pending'`,
      [result.reason, Math.round(result.score), finding.sha256.toLowerCase()]
    )
    if (!updated || (updated as any).affectedRows === 0) {
      await query(
        `INSERT IGNORE INTO suspicious_hashes (sha256, file_name, file_size, risk_score, status, auto_classified, auto_reason, pc_username)
         VALUES (?, ?, ?, ?, 'confirmed', TRUE, ?, 'auto-classifier')`,
        [finding.sha256.toLowerCase(), finding.fileName, finding.size || 0, Math.round(result.score), result.reason]
      )
    }
  } catch { /* best effort */ }
}

// ═══════════════════════════════════════════════════
// SHADOW RULE AUTO-PROMOTION
// ═══════════════════════════════════════════════════

export async function autoPromoteShadowRules(): Promise<string[]> {
  try {
    const promoted: string[] = []
    const SHADOW_PROMOTE_MIN_PCS = 20

    const rows = await query<{ rule_name: string; unique_pcs: number; total_occurrences: number }[]>(
      `SELECT
         rule_name,
         COUNT(DISTINCT pc_username) AS unique_pcs,
         SUM(occurrence_count) AS total_occurrences
       FROM shadow_findings
       WHERE status = 'shadow'
       GROUP BY rule_name
       HAVING unique_pcs >= ?
       ORDER BY unique_pcs DESC`,
      [SHADOW_PROMOTE_MIN_PCS]
    )

    for (const row of rows) {
      await query(
        `UPDATE shadow_findings SET status = 'promoted', promoted_at = NOW()
         WHERE rule_name = ? AND status = 'shadow'`,
        [row.rule_name]
      )

      const shas = await query<{ sha256: string; file_name: string | null; tlsh: string | null }[]>(
        `SELECT DISTINCT sha256, file_name, tlsh FROM shadow_findings
         WHERE rule_name = ? AND sha256 IS NOT NULL AND status = 'promoted'`,
        [row.rule_name]
      )

      let inserted = 0
      for (const s of shas) {
        try {
          await query(
            `INSERT IGNORE INTO suspicious_hashes (sha256, tlsh, file_name, risk_score, status)
             VALUES (?, ?, ?, 70, 'pending')`,
            [s.sha256, s.tlsh || null, s.file_name || 'unknown']
          )
          inserted++
        } catch { /* ignore */ }
      }

      promoted.push(row.rule_name)
      console.log(`  🤖 Auto-promoted shadow rule "${row.rule_name}" — ${row.unique_pcs} PCs, ${row.total_occurrences} occurrences, ${inserted} hashes`)
    }

    return promoted
  } catch (err) {
    console.error('Auto-promote shadow rules error:', err)
    return []
  }
}

// ═══════════════════════════════════════════════════
// PERIODIC CLEANUP
// ═══════════════════════════════════════════════════

let _cleanupTimer: ReturnType<typeof setInterval> | null = null

export function startAutoClassifier(intervalMs = 5 * 60 * 1000): void {
  if (_cleanupTimer) return
  console.log('  🤖 Smart Classifier v2 started (weighted scoring + correlation engine)')
  autoPromoteShadowRules().catch(() => {})
  _cleanupTimer = setInterval(() => {
    autoPromoteShadowRules().catch(() => {})
  }, intervalMs)
}

export function stopAutoClassifier(): void {
  if (_cleanupTimer) {
    clearInterval(_cleanupTimer)
    _cleanupTimer = null
  }
}
