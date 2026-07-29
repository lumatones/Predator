/**
 * Predator — Auto-Classifier
 *
 * Server-side intelligence that automatically classifies scan results
 * as safe, malicious, or pending — reducing admin review burden.
 *
 * Rules (evaluated in priority order):
 *   1. Hash matches confirmed cheat DB → malicious
 *   2. Hash + path matches safe-files DB (confirm_count >= 5) → safe
 *   3. Trusted system path + low risk + no strong signals → safe
 *   4. Crowdsourcing: 10+ unique PCs report same hash as low-risk → safe
 *   5. Shadow rule with 20+ unique PCs → auto-promote to active
 *   6. Multiple HIGH-risk detections across 5+ PCs → malicious
 *   7. Everything else → pending
 */

import { query } from '../config/database'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export type Classification = 'safe' | 'malicious' | 'pending'

export interface ClassifierInput {
  /** Full SHA256 hash of the file (if available) */
  sha256?: string
  /** Partial hash (first 64KB SHA256) for safe-files DB matching */
  partialHash?: string
  filePath?: string
  fileName: string
  fileType: string
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  pcUsername: string
}

export interface ClassifierResult {
  classification: Classification
  reason: string
  autoConfirmed: boolean
}

export interface ClassifierStats {
  totalClassified: number
  autoSafe: number
  autoMalicious: number
  pending: number
}

// ═══════════════════════════════════════════════════
// CONFIGURABLE THRESHOLDS
// ═══════════════════════════════════════════════════

const THRESHOLDS = {
  /** Minimum confirm_count for safe-files DB to auto-trust */
  SAFE_FILE_MIN_CONFIRMATIONS: 5,
  /** Minimum unique PCs reporting same hash as low-risk → safe */
  CROWDSOURCE_SAFE_MIN_PCS: 10,
  /** Minimum unique PCs for shadow rule → auto-promote */
  SHADOW_PROMOTE_MIN_PCS: 20,
  /** Minimum unique PCs reporting same hash as high-risk → malicious */
  CROWDSOURCE_MALICIOUS_MIN_PCS: 5,
  /** Maximum risk score to consider for auto-safe classification */
  AUTO_SAFE_MAX_SCORE: 30,
}

// ── Trusted system paths (files in these paths are almost never cheats) ──
const TRUSTED_SYSTEM_ROOTS = [
  'c:\\windows\\system32\\',
  'c:\\windows\\syswow64\\',
  'c:\\windows\\winsxs\\',
  'c:\\windows\\microsoft.net\\',
  'c:\\program files\\',
  'c:\\program files (x86)\\',
  'c:\\programdata\\microsoft\\',
]

// ── Strong cheat signals (if ANY match contains these, auto-classify as malicious) ──
const STRONG_CHEAT_SIGNALS = [
  'yara:', 'yara[', 'hash match:', 'known cheat',
  'sha256:', 'cheat:', 'dma:', 'fpga', 'pcileech',
  'injector:', 'aimbot', 'wallhack', 'esp',
  '🎭 masquerading', '🧬 combo:', '🔐 api hashing',
]

// ═══════════════════════════════════════════════════
// CORE CLASSIFICATION LOGIC
// ═══════════════════════════════════════════════════

export async function classifyFinding(input: ClassifierInput): Promise<ClassifierResult> {
  const { sha256, partialHash, filePath, fileName, risk, matches, pcUsername } = input

  // ── RULE 1: Hash in confirmed cheat DB → malicious ──
  if (sha256) {
    const confirmedHash = await checkConfirmedHash(sha256)
    if (confirmedHash) {
      return { classification: 'malicious', reason: 'Hash confirmed as cheat by admin', autoConfirmed: true }
    }
  }

  // ── RULE 2: Hash/path in safe-files DB (high confidence) → safe ──
  // NOTE: safe-files DB uses partial_hash (first 64KB SHA256), not full sha256.
  // We try matching by partialHash first (if available), then by full sha256 as fallback.
  if (partialHash || sha256 || filePath) {
    const safeFileResult = await checkSafeFile(partialHash, sha256, filePath, fileName)
    if (safeFileResult.isSafe) {
      return { classification: 'safe', reason: safeFileResult.reason, autoConfirmed: true }
    }
  }

  // ── RULE 3: Trusted system path + low risk + no strong signals → safe ──
  if (risk === 'low' && filePath) {
    const isTrusted = TRUSTED_SYSTEM_ROOTS.some(root =>
      filePath.toLowerCase().startsWith(root)
    )
    const hasStrongSignals = matches.some(m =>
      STRONG_CHEAT_SIGNALS.some(signal => m.toLowerCase().includes(signal))
    )
    if (isTrusted && !hasStrongSignals) {
      return {
        classification: 'safe',
        reason: `Trusted system path (${filePath.slice(0, 60)}...) + low risk + no strong signals`,
        autoConfirmed: true,
      }
    }
  }

  // ── RULE 4: Strong cheat signals → malicious ──
  const strongSignalCount = matches.filter(m =>
    STRONG_CHEAT_SIGNALS.some(signal => m.toLowerCase().includes(signal))
  ).length
  if (strongSignalCount >= 2 && risk === 'high') {
    return {
      classification: 'malicious',
      reason: `${strongSignalCount} strong cheat signals detected in matches`,
      autoConfirmed: true,
    }
  }

  // ── RULE 5: Crowdsourcing (full sha256 only, not partial hash) ──
  if (sha256) {
    const crowdResult = await checkCrowdsource(sha256, risk, pcUsername)
    if (crowdResult) return crowdResult
  }

  // ── RULE 6: Single strong signal + high risk → malicious ──
  if (strongSignalCount >= 1 && risk === 'high') {
    return {
      classification: 'malicious',
      reason: `High risk + strong cheat signal: ${matches.find(m => STRONG_CHEAT_SIGNALS.some(s => m.toLowerCase().includes(s))) || 'unknown'}`,
      autoConfirmed: true,
    }
  }

  // ── Default: pending (requires admin review) ──
  return { classification: 'pending', reason: 'Requires admin review', autoConfirmed: false }
}

// ═══════════════════════════════════════════════════
// HELPER QUERIES
// ═══════════════════════════════════════════════════

async function checkConfirmedHash(sha256: string): Promise<boolean> {
  try {
    const rows = await query<{ cnt: number }[]>(
      'SELECT COUNT(*) AS cnt FROM suspicious_hashes WHERE sha256 = ? AND status = ?',
      [sha256.toLowerCase(), 'confirmed']
    )
    return (rows[0]?.cnt || 0) > 0
  } catch { return false }
}

async function checkSafeFile(
  partialHash: string | undefined,
  fullSha256: string | undefined,
  filePath: string | undefined,
  _fileName: string,
): Promise<{ isSafe: boolean; reason: string }> {
  try {
    // Primary check: by partial_hash (first 64KB) — this is what safe_files stores
    if (partialHash) {
      const rows = await query<{ confirm_count: number }[]>(
        'SELECT confirm_count FROM safe_files WHERE partial_hash = ? AND confirm_count >= ?',
        [partialHash.toLowerCase(), THRESHOLDS.SAFE_FILE_MIN_CONFIRMATIONS]
      )
      if (rows.length > 0) {
        return {
          isSafe: true,
          reason: `Safe file confirmed by ${rows[0].confirm_count} devices (partial hash)`,
        }
      }
    }

    // Fallback: try full sha256 (some entries may have been stored with full hash)
    if (fullSha256 && fullSha256 !== partialHash) {
      const rows = await query<{ confirm_count: number }[]>(
        'SELECT confirm_count FROM safe_files WHERE partial_hash = ? AND confirm_count >= ?',
        [fullSha256.toLowerCase(), THRESHOLDS.SAFE_FILE_MIN_CONFIRMATIONS]
      )
      if (rows.length > 0) {
        return {
          isSafe: true,
          reason: `Safe file confirmed by ${rows[0].confirm_count} devices`,
        }
      }
    }

    // Check by path pattern (community-verified safe directories)
    if (filePath) {
      const lowerPath = filePath.toLowerCase()
      // System DLLs in System32/SysWOW64 are almost always safe
      if (
        (lowerPath.includes('\\system32\\') || lowerPath.includes('\\syswow64\\')) &&
        (lowerPath.endsWith('.dll') || lowerPath.endsWith('.exe'))
      ) {
        return { isSafe: true, reason: 'System directory file' }
      }
    }

    return { isSafe: false, reason: '' }
  } catch { return { isSafe: false, reason: '' } }
}

async function checkCrowdsource(
  sha256: string,
  risk: string,
  pcUsername: string,
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

    // Many PCs reporting low risk → safe
    if (uniquePcs >= THRESHOLDS.CROWDSOURCE_SAFE_MIN_PCS && avgRisk < THRESHOLDS.AUTO_SAFE_MAX_SCORE) {
      return {
        classification: 'safe',
        reason: `Crowdsourced: ${uniquePcs} PCs report low risk (avg score: ${avgRisk.toFixed(0)})`,
        autoConfirmed: true,
      }
    }

    // Many PCs reporting high risk → malicious
    if (uniquePcs >= THRESHOLDS.CROWDSOURCE_MALICIOUS_MIN_PCS && risk === 'high') {
      return {
        classification: 'malicious',
        reason: `Crowdsourced: ${uniquePcs} PCs report HIGH risk`,
        autoConfirmed: true,
      }
    }

    return null
  } catch { return null }
}

// ═══════════════════════════════════════════════════
// BATCH CLASSIFICATION
// ═══════════════════════════════════════════════════

/**
 * Classify a batch of findings from a single scan.
 * Returns stats and a list of findings that need admin attention.
 */
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
      // Auto-insert into safe_files for future reference
      await autoAddToSafeFiles(finding, result)
    } else if (result.classification === 'malicious') {
      stats.autoMalicious++
      autoClassified.push({ input: finding, result })
      // Auto-confirm in suspicious_hashes
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

async function autoAddToSafeFiles(finding: ClassifierInput, result: ClassifierResult): Promise<void> {
  try {
    // Use partialHash (first 64KB) for safe_files — that's what the table stores
    const hashForSafeDb = finding.partialHash || finding.sha256
    if (!hashForSafeDb) return
    await query(
      `INSERT INTO safe_files (partial_hash, file_name, file_size, confirm_count)
       VALUES (?, ?, 0, ?)
       ON DUPLICATE KEY UPDATE confirm_count = confirm_count + 1, last_seen = NOW()`,
      [hashForSafeDb.toLowerCase(), finding.fileName, THRESHOLDS.SAFE_FILE_MIN_CONFIRMATIONS]
    )
  } catch { /* best effort */ }
}

async function autoConfirmHash(finding: ClassifierInput, result: ClassifierResult): Promise<void> {
  try {
    if (!finding.sha256) return
    // Update existing pending hash to confirmed AND set auto_classified flags
    const updated = await query<{ affectedRows: number }>(
      `UPDATE suspicious_hashes
       SET status = 'confirmed', auto_classified = TRUE, auto_reason = ?, reviewed_at = NOW()
       WHERE sha256 = ? AND status = 'pending'`,
      [result.reason, finding.sha256.toLowerCase()]
    )
    // If no existing pending record, insert as confirmed with auto flags
    if (!updated || (updated as any).affectedRows === 0) {
      await query(
        `INSERT IGNORE INTO suspicious_hashes (sha256, file_name, file_size, risk_score, status, auto_classified, auto_reason, pc_username)
         VALUES (?, ?, 0, 85, 'confirmed', TRUE, ?, 'auto-classifier')`,
        [finding.sha256.toLowerCase(), finding.fileName, result.reason]
      )
    }
  } catch { /* best effort */ }
}

// ═══════════════════════════════════════════════════
// SHADOW RULE AUTO-PROMOTION
// ═══════════════════════════════════════════════════

/**
 * Check shadow findings for rules that have crossed the promotion threshold.
 * Auto-promotes rules that have been observed on enough unique PCs.
 * Called periodically or after each scan submission.
 */
export async function autoPromoteShadowRules(): Promise<string[]> {
  try {
    const promoted: string[] = []

    // Find shadow rules with enough unique PCs
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
      [THRESHOLDS.SHADOW_PROMOTE_MIN_PCS]
    )

    for (const row of rows) {
      // Promote the rule
      await query(
        `UPDATE shadow_findings SET status = 'promoted', promoted_at = NOW()
         WHERE rule_name = ? AND status = 'shadow'`,
        [row.rule_name]
      )

      // Insert any sha256 entries into suspicious_hashes for admin review
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
        } catch (err) { console.warn('[classifier] failed:', (err as Error).message) }
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

/**
 * Start periodic auto-classification tasks:
 * - Shadow rule promotion check every 5 minutes
 * - Crowdsource re-evaluation every 10 minutes
 */
export function startAutoClassifier(intervalMs = 5 * 60 * 1000): void {
  if (_cleanupTimer) return

  console.log('  🤖 Auto-classifier started (rules engine + crowdsourcing)')

  // Initial run
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
