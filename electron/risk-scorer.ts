/**
 * Predator — Weighted Risk Scorer (E18)
 *
 * ML-inspired risk scoring engine:
 *   - Signal category weights (memory > process > file > path)
 *   - Evidence accumulation with confidence decay
 *   - Adaptive thresholds based on system baseline
 *   - Score normalization to 0-100
 *
 * Philosophy: Not all signals are equal. A memory byte pattern match
 * should contribute much more to risk than a filename keyword match.
 */

import type { ScanResult } from './types'

// ═══════════════════════════════════════════════════
// SIGNAL WEIGHTS — higher = more reliable/dangerous
// ═══════════════════════════════════════════════════

/** Weight multiplier by signal source */
export const SIGNAL_WEIGHTS: Record<string, number> = {
  // Hardware-level detection (definitive)
  'memory_pattern': 1.0,       // Byte pattern in process memory
  'dma_fpga': 0.95,            // PCIe/USB FPGA device detected
  'driver_signature': 0.9,     // Unsigned kernel driver
  'pcie_scan': 0.9,            // PCIe config space scan

  // Process-level detection (strong)
  'injection_detected': 0.85,  // DLL/code injection
  'debug_port': 0.8,           // CEF remote debugging
  'apc_injection': 0.8,        // APC injection
  'process_hollowing': 0.8,    // Process hollowing

  // File-level detection (moderate)
  'yara_match': 0.7,           // YARA rule match
  'tlsh_match': 0.65,          // Fuzzy hash match
  'pe_anomaly': 0.6,           // PE header anomaly
  'entropy_high': 0.5,         // High entropy = packed
  'unsigned_binary': 0.4,      // Unsigned executable

  // Heuristic detection (weaker)
  'suspicious_extension': 0.2, // .dll/.asi in game dir
  'filename_keyword': 0.15,    // Name contains 'cheat'
  'path_keyword': 0.15,        // Path contains cheat keyword
  'registry_keyword': 0.2,     // Registry key match
  'network_port': 0.5,         // Suspicious network port
  'network_c2': 0.7,           // C2 server connection
  'network_proxy': 0.3,        // Proxy setting
  'network_vpn': 0.25,         // VPN adapter
  'firewall_rule': 0.35,       // Suspicious firewall rule
  'dns_cache': 0.4,            // C2 domain in DNS

  // Default
  'default': 0.3,
}

/**
 * Classify a match string into a signal category.
 */
export function classifySignal(match: string): string {
  const lower = match.toLowerCase()

  if (lower.includes('memory') || lower.includes('byte pattern') || lower.includes('aimbot') ||
    lower.includes('esp') || lower.includes('overlay')) return 'memory_pattern'

  if (lower.includes('dma') || lower.includes('fpga') || lower.includes('pcie') ||
    lower.includes('xilinx') || lower.includes('altera')) return 'dma_fpga'

  if (lower.includes('driver') && (lower.includes('unsigned') || lower.includes('sign')))
    return 'driver_signature'

  if (lower.includes('inject') || lower.includes('handle')) return 'injection_detected'
  if (lower.includes('debug') || lower.includes('cef') || lower.includes('devtools'))
    return 'debug_port'
  if (lower.includes('apc') || lower.includes('atom')) return 'apc_injection'
  if (lower.includes('hollow')) return 'process_hollowing'
  if (lower.includes('yara')) return 'yara_match'
  if (lower.includes('tlsh') || lower.includes('fuzzy')) return 'tlsh_match'
  if (lower.includes('entropy')) return 'entropy_high'
  if (lower.includes('unsigned') || lower.includes('signature')) return 'unsigned_binary'
  if (lower.includes('extension')) return 'suspicious_extension'
  if (lower.includes('port')) return 'network_port'
  if (lower.includes('c2') || lower.includes('bulletproof')) return 'network_c2'
  if (lower.includes('proxy')) return 'network_proxy'
  if (lower.includes('vpn') || lower.includes('tap-') || lower.includes('wireguard'))
    return 'network_vpn'
  if (lower.includes('firewall')) return 'firewall_rule'
  if (lower.includes('dns')) return 'dns_cache'

  return 'default'
}

// ═══════════════════════════════════════════════════
// EVIDENCE ACCUMULATOR
// ═══════════════════════════════════════════════════

interface EvidenceItem {
  category: string
  weight: number
  risk: 'high' | 'medium' | 'low'
  timestamp: number
  findingId: string
}

/**
 * Collect evidence from all scan results and accumulate weighted scores.
 */
function collectEvidence(results: ScanResult[]): EvidenceItem[] {
  const evidence: EvidenceItem[] = []
  const now = Date.now()

  for (const r of results) {
    for (const match of r.matches) {
      const category = classifySignal(match)
      evidence.push({
        category,
        weight: SIGNAL_WEIGHTS[category] ?? SIGNAL_WEIGHTS.default,
        risk: r.risk,
        timestamp: now,
        findingId: `${r.type}:${r.fileName}`,
      })
    }
  }

  return evidence
}

// ═══════════════════════════════════════════════════
// SCORE CALCULATION
// ═══════════════════════════════════════════════════

export interface RiskScore {
  /** Overall risk score 0-100 */
  overall: number
  /** Breakdown by category */
  categories: Record<string, { score: number; count: number }>
  /** Risk level */
  level: 'critical' | 'high' | 'medium' | 'low' | 'clean'
  /** Evidence count */
  totalEvidence: number
  /** Whether the score was escalated by persistent profile */
  escalated: boolean
  /** Adaptive threshold used */
  threshold: number
}

/**
 * Calculate weighted risk score from scan results.
 *
 * Uses:
 *   - Signal weights per category
 *   - Evidence accumulation (more evidence = higher confidence)
 *   - Adaptive threshold based on evidence count
 *   - Diminishing returns (log scale to prevent score inflation)
 */
export function calculateRisk(
  results: ScanResult[],
  escalationBonus = 0,
): RiskScore {
  const evidence = collectEvidence(results)

  if (evidence.length === 0) {
    return {
      overall: 0,
      categories: {},
      level: 'clean',
      totalEvidence: 0,
      escalated: false,
      threshold: 30,
    }
  }

  // Aggregate by category
  const categories: Record<string, { totalWeight: number; count: number; maxRisk: number }> = {}
  for (const e of evidence) {
    if (!categories[e.category]) {
      categories[e.category] = { totalWeight: 0, count: 0, maxRisk: 0 }
    }
    categories[e.category].totalWeight += e.weight
    categories[e.category].count++
    categories[e.category].maxRisk = Math.max(
      categories[e.category].maxRisk,
      e.risk === 'high' ? 3 : e.risk === 'medium' ? 2 : 1,
    )
  }

  // Calculate per-category scores with diminishing returns
  const categoryScores: Record<string, { score: number; count: number }> = {}
  let rawScore = 0

  for (const [cat, data] of Object.entries(categories)) {
    // Use log scale: score = weight_sum * max_risk * log2(1 + count) * 25
    const diversityBonus = Math.log2(1 + data.count)
    const catScore = Math.min(data.totalWeight * data.maxRisk * diversityBonus * 25, 100)
    categoryScores[cat] = { score: Math.round(catScore), count: data.count }
    rawScore += catScore * data.totalWeight
  }

  // Normalize: divide by total weight to prevent inflation
  const totalWeight = Object.values(categories).reduce((s, c) => s + c.totalWeight, 0)
  const normalizedScore = totalWeight > 0 ? Math.round(rawScore / totalWeight) : 0

  // Escalation bonus
  const escalated = escalationBonus > 0
  const finalScore = Math.min(normalizedScore + escalationBonus, 100)

  // Adaptive threshold: lower threshold when lots of evidence
  const adaptiveThreshold = evidence.length > 20 ? 20
    : evidence.length > 10 ? 25
    : evidence.length > 5 ? 30
    : 35

  // Level classification
  let level: RiskScore['level']
  if (finalScore >= 85) level = 'critical'
  else if (finalScore >= 65) level = 'high'
  else if (finalScore >= 35) level = 'medium'
  else if (finalScore >= adaptiveThreshold) level = 'low'
  else level = 'clean'

  return {
    overall: finalScore,
    categories: categoryScores,
    level,
    totalEvidence: evidence.length,
    escalated,
    threshold: adaptiveThreshold,
  }
}

// ═══════════════════════════════════════════════════
// TIME-DECAY FOR HISTORICAL FINDINGS
// ═══════════════════════════════════════════════════

/**
 * Apply time decay to historical risk scores.
 * Signals older than 7 days decay exponentially.
 *
 * @param score Original score (0-100)
 * @param ageMs Age of the finding in milliseconds
 * @returns Decayed score
 */
export function decayScore(score: number, ageMs: number): number {
  const ageDays = ageMs / (1000 * 60 * 60 * 24)
  const HALF_LIFE_DAYS = 7
  const decayFactor = Math.pow(0.5, ageDays / HALF_LIFE_DAYS)
  return Math.round(score * decayFactor)
}

// ═══════════════════════════════════════════════════
// SCORE TO RISK LEVEL (replaces heuristic.riskScoreToLevel)
// ═══════════════════════════════════════════════════

/**
 * Convert numerical risk score to risk level string.
 * More granular than the old 3-level system.
 */
export function scoreToLevel(score: number): 'critical' | 'high' | 'medium' | 'low' | 'clean' {
  if (score >= 85) return 'critical'
  if (score >= 65) return 'high'
  if (score >= 35) return 'medium'
  if (score >= 15) return 'low'
  return 'clean'
}

// ═══════════════════════════════════════════════════
// SCAN RESULT SCORING WRAPPER
// ═══════════════════════════════════════════════════

/**
 * Re-score existing scan results using weighted engine.
 * Adds a `weightedRisk` score to each result's matches for downstream use.
 */
export function rescoreResults(results: ScanResult[]): ScanResult[] {
  return results.map(r => {
    let maxWeight = 0
    let totalWeight = 0
    for (const match of r.matches) {
      const category = classifySignal(match)
      const weight = SIGNAL_WEIGHTS[category] ?? SIGNAL_WEIGHTS.default
      maxWeight = Math.max(maxWeight, weight)
      totalWeight += weight
    }

    // Adjust risk if weighted score contradicts original
    const avgWeight = r.matches.length > 0 ? totalWeight / r.matches.length : 0
    if (r.risk === 'medium' && maxWeight >= 0.8) {
      return { ...r, risk: 'high' as const, matches: [...r.matches, `↑ Escalated: weighted signal (${(avgWeight * 100).toFixed(0)}%)`] }
    }
    if (r.risk === 'low' && maxWeight >= 0.6) {
      return { ...r, risk: 'medium' as const, matches: [...r.matches, `↑ Escalated: weighted signal (${(avgWeight * 100).toFixed(0)}%)`] }
    }
    return r
  })
}
