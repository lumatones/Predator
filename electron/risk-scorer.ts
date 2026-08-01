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

import type { EvidenceRecord, ScanResult } from './types'

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

export interface EvidenceItem {
  category: string
  weight: number
  risk: 'critical' | 'high' | 'medium' | 'low'
  timestamp: number
  findingId: string
}

const SIGNAL_EXPLANATIONS: Record<string, string> = {
  memory_pattern: 'Память содержит признак, характерный для вмешательства в игровой процесс.',
  dma_fpga: 'Обнаружен признак DMA/FPGA-оборудования или ПО прямого доступа к памяти.',
  driver_signature: 'Найден драйвер с проблемной или отсутствующей цифровой подписью.',
  injection_detected: 'Найден признак инжекта, подозрительного дескриптора или удалённого потока.',
  debug_port: 'Обнаружен отладочный порт или DevTools-контекст, связанный с вмешательством.',
  apc_injection: 'Обнаружен признак APC/атомарной инъекции в другой процесс.',
  process_hollowing: 'Найден признак подмены содержимого легитимного процесса.',
  yara_match: 'Сработало YARA-правило по известному шаблону.',
  tlsh_match: 'Найдено fuzzy/TLSH-сходство с известным образцом.',
  entropy_high: 'Высокая энтропия может указывать на упаковку или сокрытие содержимого.',
  unsigned_binary: 'Бинарный файл не имеет подтверждённой цифровой подписи.',
  default: 'Сработал индикатор сканера, требующий ручной проверки.',
}

function baseConfidence(risk: ScanResult['risk']): number {
  return risk === 'critical' ? 90 : risk === 'high' ? 78 : risk === 'medium' ? 58 : 35
}

const GENERATED_DUPLICATE_SUFFIX = /#duplicate:\d+$/

function findingIdFor(result: ScanResult, duplicateIndex?: number): string {
  const base = (result.findingId || `${result.type}:${result.path}:${result.fileName}`)
    .replace(GENERATED_DUPLICATE_SUFFIX, '')
  return duplicateIndex === undefined || duplicateIndex === 0 ? base : `${base}#duplicate:${duplicateIndex + 1}`
}

function buildFindingEvidence(result: ScanResult): EvidenceRecord[] {
  const timestamp = result.modifiedAt || new Date().toISOString()
  return result.matches
    .filter(match => !match.startsWith('↑ Escalated:'))
    .map((raw, index) => {
      const category = classifySignal(raw)
      const weight = SIGNAL_WEIGHTS[category] ?? SIGNAL_WEIGHTS.default
      return {
        id: `${findingIdFor(result)}:e${index + 1}`,
        source: result.type,
        category,
        weight,
        confidence: Math.round(baseConfidence(result.risk) * (0.55 + weight * 0.45)),
        explanation: SIGNAL_EXPLANATIONS[category] || SIGNAL_EXPLANATIONS.default,
        raw,
        timestamp,
      }
    })
}

const CORRELATION_TYPE_PAIRS = new Set([
  'browser:file',
  'file:browser',
  'file:process',
  'process:file',
  'process:registry',
  'registry:process',
  'hardware:software',
  'software:hardware',
])

function canCorrelate(left: ScanResult, right: ScanResult): boolean {
  if (!CORRELATION_TYPE_PAIRS.has(`${left.type}:${right.type}`)) return false

  const ignored = new Set([
    'file', 'process', 'history', 'browser', 'system', 'detected', 'found',
    'injector', 'suspicious', 'remote', 'thread', 'match', 'signature',
    'device', 'software', 'driver', 'tool', 'chrome', 'windows', 'prefetch',
  ])
  const tokens = (result: ScanResult) => `${result.fileName} ${result.path} ${result.matches.join(' ')}`
    .toLowerCase()
    .split(/[^a-z0-9а-яё]+/i)
    .filter(token => token.length >= 4 && !ignored.has(token))
  const rightTokens = new Set(tokens(right))
  return tokens(left).some(token => rightTokens.has(token))
}

function addCorrelations(results: ScanResult[]): ScanResult[] {
  const seenIds = new Map<string, number>()
  const prepared = results.map(result => {
    const baseId = findingIdFor(result)
    const duplicateIndex = seenIds.get(baseId) ?? 0
    seenIds.set(baseId, duplicateIndex + 1)
    const findingId = findingIdFor(result, duplicateIndex)
    const normalizedResult = { ...result, findingId }
    const sourceEvidence = result.evidence ?? buildFindingEvidence(normalizedResult)
    const evidence = sourceEvidence.map((item, index) => ({
      ...item,
      id: `${findingId}:e${index + 1}`,
      relatedFindingIds: undefined,
    }))
    return {
      ...normalizedResult,
      evidence,
    }
  })

  return prepared.map(result => {
    const relatedFindingIds = prepared
      .filter(other => other.findingId !== result.findingId && canCorrelate(result, other))
      .filter(other => result.evidence?.some(e => e.weight >= 0.6) && other.evidence?.some(e => e.weight >= 0.6))
      .map(other => other.findingId!)
      .slice(0, 8)

    if (relatedFindingIds.length === 0) return result
    return {
      ...result,
      evidence: result.evidence?.map(item => ({ ...item, relatedFindingIds })),
    }
  })
}

/**
 * Collect evidence from structured results, falling back to legacy matches.
 */
function collectEvidence(results: ScanResult[]): EvidenceItem[] {
  const evidence: EvidenceItem[] = []
  for (const r of results) {
    const structured = r.evidence ?? buildFindingEvidence(r)
    for (const item of structured) {
      evidence.push({
        category: item.category,
        weight: item.weight,
        risk: r.risk,
        timestamp: Date.parse(item.timestamp) || Date.now(),
        findingId: findingIdFor(r),
      })
    }
  }
  return evidence
}

// ═══════════════════════════════════════════════════
// SCORE CALCULATION
// ═══════════════════════════════════════════════════

export interface RiskContribution {
  category: string
  score: number
  count: number
  weight: number
  confidence: number
  explanation: string
}

export interface RiskScore {
  /** Overall risk score 0-100 */
  overall: number
  /** Breakdown by category */
  categories: Record<string, { score: number; count: number }>
  /** Explainable contribution of each signal category. */
  contributions: RiskContribution[]
  /** Risk level */
  level: 'critical' | 'high' | 'medium' | 'low' | 'clean'
  /** Evidence count */
  totalEvidence: number
  /** Whether the score was escalated by persistent profile */
  escalated: boolean
  /** Adaptive threshold used */
  threshold: number
  /** Human-readable summary for moderators. */
  explanation: string
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
      contributions: [],
      level: 'clean',
      totalEvidence: 0,
      escalated: false,
      threshold: 30,
      explanation: 'Структурированные сигналы отсутствуют.',
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
      e.risk === 'critical' ? 4 : e.risk === 'high' ? 3 : e.risk === 'medium' ? 2 : 1,
    )
  }

  // Calculate per-category scores with diminishing returns
  const categoryScores: Record<string, { score: number; count: number }> = {}
  const contributions: RiskContribution[] = []
  let rawScore = 0

  for (const [cat, data] of Object.entries(categories)) {
    // Use log scale: score = weight_sum * max_risk * log2(1 + count) * 25
    const diversityBonus = Math.log2(1 + data.count)
    const catScore = Math.min(data.totalWeight * data.maxRisk * diversityBonus * 25, 100)
    const score = Math.round(catScore)
    categoryScores[cat] = { score, count: data.count }
    contributions.push({
      category: cat,
      score,
      count: data.count,
      weight: Number((data.totalWeight / data.count).toFixed(2)),
      confidence: Math.min(100, Math.round((data.maxRisk / 4) * 100)),
      explanation: SIGNAL_EXPLANATIONS[cat] || SIGNAL_EXPLANATIONS.default,
    })
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
    contributions: contributions.sort((a, b) => b.score - a.score),
    escalated,
    threshold: adaptiveThreshold,
    explanation: `${evidence.length} сигналов из ${contributions.length} категорий сформировали оценку ${finalScore}/100.`,
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
  const enriched = addCorrelations(results)
  return enriched.map(r => {
    const evidence = r.evidence ?? []
    const maxWeight = evidence.reduce((max, item) => Math.max(max, item.weight), 0)
    const totalWeight = evidence.reduce((sum, item) => sum + item.weight, 0)
    const avgWeight = evidence.length > 0 ? totalWeight / evidence.length : 0
    const riskScore = Math.round(Math.min(100, (maxWeight * 0.7 + avgWeight * 0.3) * 100))
    const escalationMatch = `↑ Escalated: weighted signal (${(avgWeight * 100).toFixed(0)}%)`
    const hasEscalation = r.matches.some(match => match === escalationMatch)
    const shouldEscalateHigh = r.risk === 'medium' && maxWeight >= 0.8
    const shouldEscalateMedium = r.risk === 'low' && maxWeight >= 0.6
    const nextRisk: ScanResult['risk'] = shouldEscalateHigh ? 'high' : shouldEscalateMedium ? 'medium' : r.risk
    const nextMatches = (shouldEscalateHigh || shouldEscalateMedium) && !hasEscalation
      ? [...r.matches, escalationMatch]
      : r.matches
    const adjustedEvidence = evidence.map(item => ({
      ...item,
      confidence: Math.round(baseConfidence(nextRisk) * (0.55 + item.weight * 0.45)),
    }))
    const leading = adjustedEvidence.slice().sort((a, b) => b.weight - a.weight)[0]

    return {
      ...r,
      risk: nextRisk,
      evidence: adjustedEvidence,
      matches: nextMatches,
      riskScore,
      riskExplanation: leading
        ? `${leading.category}: ${leading.explanation} Confidence ${leading.confidence}%.`
        : 'Нет структурированных сигналов для оценки.',
    }
  })
}
