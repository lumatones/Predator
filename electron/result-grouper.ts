/**
 * Predator — Result Grouper
 *
 * Groups raw scan results into logical "cheat groups" for cleaner UI display.
 * Instead of showing individual files, the user sees detected cheat software.
 *
 * Grouping logic:
 *   1. Extract cheat name from match strings (e.g. "process:eulen" → "Eulen")
 *   2. Group files/processes/registry by shared cheat name
 *   3. Ungrouped items go into "Other Suspicious Activity"
 *   4. Sort groups by severity (high risk first, then by file count)
 */

import type { ScanResult } from './types'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface CheatGroup {
  /** Display name of the detected cheat */
  cheatName: string
  /** Risk level of the group (highest among members) */
  risk: 'high' | 'medium' | 'low'
  /** All findings belonging to this cheat */
  findings: ScanResult[]
  /** Count breakdown */
  counts: {
    files: number
    processes: number
    registry: number
    browser: number
    hardware: number
    other: number
  }
  /** Representative match tags (unique across all findings) */
  tags: string[]
  /** Confidence score (0-100) */
  confidence: number
}

export interface GroupedResults {
  /** Detected cheat software groups */
  cheatGroups: CheatGroup[]
  /** Ungrouped high-risk findings */
  otherHigh: ScanResult[]
  /** Ungrouped medium-risk findings */
  otherMedium: ScanResult[]
  /** Ungrouped low-risk findings (filtered out by default) */
  otherLow: ScanResult[]
  /** Summary */
  summary: {
    totalCheatsDetected: number
    totalHighRisk: number
    totalMediumRisk: number
    totalLowRisk: number
  }
}

// ═══════════════════════════════════════════════════
// CHEAT NAME EXTRACTION
// ═══════════════════════════════════════════════════

/**
 * Known cheat names and their aliases for grouping.
 * Structure: canonicalName → [...aliases]
 */
const CHEAT_NAME_MAP: Record<string, string[]> = {
  'Eulen': ['eulen', 'eulenmenu', 'eulen menu'],
  'RedEngine': ['redengine', 'redenginev2', 'red engine'],
  'Skript.gg': ['skript', 'skript.gg', 'skriptgg', 'skriptmenu'],
  'Cherax': ['cherax', 'cheraxmenu'],
  'Stand': ['stand', 'stand.gg', 'standmenu'],
  '2Take1': ['2take1', '2take1menu', '2take1.menu'],
  'Impulse': ['impulse', 'impulseone', 'impulsemenu'],
  'Luna': ['luna', 'luna menu'],
  'Paragon': ['paragon', 'paragonmenu'],
  'Ozark': ['ozark', 'ozarkmenu'],
  'Kiddions': ['kiddions', 'kiddion', 'kiddionsmenu'],
  'Nightfall': ['nightfall', 'nightfall cheat'],
  'Aurora': ['aurora', 'auroramenu'],
  'Hydrogen': ['hydrogen'],
  'Oxide': ['oxide'],
  'Havoc': ['havoc'],
  'Revolution': ['revolution'],
  'Majestic RP': ['majesty', 'majestic'],
  '0xCheats': ['0xcheats', '0xcheat', 'oxcheat', '0x cheat'],
  'LeetCheats': ['leetcheats', 'leetcheat', 'noleet', '1337'],
  'Unicore': ['unicore', 'unicoremenu'],
  'Vanish': ['vanish', 'vanishmenu'],
  'Modest': ['modest', 'modestmenu'],
  'Susano': ['susano', 'susanomenu'],
  'Lambda': ['lambda', 'lambdamenu'],
  'vMenu': ['vmenu'],
  'Absolute': ['absolute'],
  'DMA Hardware': ['dma', 'fpga', 'pcileech', 'fuser', 'screamer', 'leechcore'],
  'Cheat Engine': ['cheat engine', 'cheatengine', 'ce.exe'],
  'Xenos Injector': ['xenos', 'xenos64'],
  'Process Hacker': ['process hacker', 'processhacker'],
  'Extreme Injector': ['extremeinjector'],
  'Spoofer': ['spoofer', 'hwid spoofer', 'hwidspoofer', 'mac spoofer'],
  'PC Cleaner': ['cleaner', 'tracecleaner', 'logcleaner', 'logkiller', 'pc clean'],
  'VMProtect': ['vmprotect'],
  'Themida': ['themida'],
  'Enigma Protector': ['enigma protector', 'enigma'],
  'Obsidium': ['obsidium'],
  'KDMapper': ['kdmapper', 'drvmap'],
}

/**
 * Extract cheat name from a single finding's matches and filename.
 */
function extractCheatName(finding: ScanResult): string | null {
  const searchText = [
    finding.fileName.toLowerCase(),
    finding.path.toLowerCase(),
    ...finding.matches.map(m => m.toLowerCase()),
  ].join(' ')

  // Try exact cheat name matches first
  for (const [canonicalName, aliases] of Object.entries(CHEAT_NAME_MAP)) {
    for (const alias of aliases) {
      if (searchText.includes(alias)) {
        return canonicalName
      }
    }
  }

  // Try extracting from match patterns like "process:cheatname" or "file:cheatname" or "folder:cheatname"
  for (const match of finding.matches) {
    const processMatch = match.match(/^process:(.+)/i)
    if (processMatch) {
      const name = processMatch[1].trim().toLowerCase()
      for (const [canonicalName, aliases] of Object.entries(CHEAT_NAME_MAP)) {
        if (aliases.some(a => name.includes(a))) return canonicalName
      }
    }
    const fileMatch = match.match(/^(?:file|folder|lua):(.+)/i)
    if (fileMatch) {
      const name = fileMatch[1].trim().toLowerCase()
      for (const [canonicalName, aliases] of Object.entries(CHEAT_NAME_MAP)) {
        if (aliases.some(a => name.includes(a))) return canonicalName
      }
    }
    // Check "content:" and "signatures" matches too
    const contentMatch = match.match(/^(?:content|signatures)\s*\[?([^\]:]+)/i)
    if (contentMatch) {
      const name = contentMatch[1].trim().toLowerCase()
      for (const [canonicalName, aliases] of Object.entries(CHEAT_NAME_MAP)) {
        if (aliases.some(a => name.includes(a))) return canonicalName
      }
    }
  }

  // Try extracting from YARA matches
  for (const match of finding.matches) {
    const yaraMatch = match.match(/YARA\s*\[([^\]]+)\]/i)
    if (yaraMatch) {
      const ruleName = yaraMatch[1].toLowerCase()
      for (const [canonicalName, aliases] of Object.entries(CHEAT_NAME_MAP)) {
        if (aliases.some(a => ruleName.includes(a))) return canonicalName
      }
    }
  }

  return null
}

/**
 * Calculate confidence score for a group (0-100).
 * Based on: number of findings, risk levels, match quality.
 */
function calculateConfidence(findings: ScanResult[]): number {
  if (findings.length === 0) return 0

  let score = 0
  const highCount = findings.filter(f => f.risk === 'high').length
  const mediumCount = findings.filter(f => f.risk === 'medium').length

  // Base score from findings count
  score += Math.min(findings.length * 15, 45)

  // Bonus for high-risk findings
  score += highCount * 20

  // Bonus for medium-risk findings
  score += mediumCount * 5

  // Bonus for diverse finding types (file + process + registry = more confident)
  const types = new Set(findings.map(f => f.type))
  score += (types.size - 1) * 10

  // Cap at 100
  return Math.min(score, 100)
}

/**
 * Group scan results by detected cheat software.
 * Only medium+ risk items are grouped; low-risk items go to otherLow.
 */
export function groupResults(results: ScanResult[]): GroupedResults {
  const cheatGroupMap = new Map<string, ScanResult[]>()
  const otherHigh: ScanResult[] = []
  const otherMedium: ScanResult[] = []
  const otherLow: ScanResult[] = []

  for (const finding of results) {
    const cheatName = extractCheatName(finding)

    if (cheatName) {
      const existing = cheatGroupMap.get(cheatName) || []
      existing.push(finding)
      cheatGroupMap.set(cheatName, existing)
    } else {
      // Ungrouped — sort by risk
      if (finding.risk === 'high') otherHigh.push(finding)
      else if (finding.risk === 'medium') otherMedium.push(finding)
      else otherLow.push(finding)
    }
  }

  // Build cheat groups
  const cheatGroups: CheatGroup[] = []
  for (const [cheatName, findings] of cheatGroupMap) {
    const risk: 'high' | 'medium' | 'low' = findings.some(f => f.risk === 'high')
      ? 'high'
      : findings.some(f => f.risk === 'medium')
        ? 'medium'
        : 'low'

    const counts = {
      files: findings.filter(f => f.type === 'file').length,
      processes: findings.filter(f => f.type === 'process').length,
      registry: findings.filter(f => f.type === 'registry').length,
      browser: findings.filter(f => f.type === 'browser').length,
      hardware: findings.filter(f => f.type === 'hardware').length,
      other: findings.filter(f => !['file', 'process', 'registry', 'browser', 'hardware'].includes(f.type)).length,
    }

    // Collect unique tags
    const tagSet = new Set<string>()
    for (const f of findings) {
      for (const m of f.matches) {
        // Clean up match strings for display
        const clean = m
          .replace(/^(process|file|folder|lua|content|signatures|archive|binary-sig):/i, '')
          .replace(/^YARA\s*\[/i, '')
          .replace(/\]$/, '')
          .trim()
        if (clean.length > 3 && clean.length < 60) {
          tagSet.add(clean)
        }
      }
    }

    cheatGroups.push({
      cheatName,
      risk,
      findings,
      counts,
      tags: Array.from(tagSet).slice(0, 8),
      confidence: calculateConfidence(findings),
    })
  }

  // Sort groups: high risk first, then by confidence
  cheatGroups.sort((a, b) => {
    const riskOrder = { high: 0, medium: 1, low: 2 }
    const riskDiff = riskOrder[a.risk] - riskOrder[b.risk]
    if (riskDiff !== 0) return riskDiff
    return b.confidence - a.confidence
  })

  return {
    cheatGroups,
    otherHigh,
    otherMedium,
    otherLow,
    summary: {
      totalCheatsDetected: cheatGroups.length,
      totalHighRisk: results.filter(r => r.risk === 'high').length,
      totalMediumRisk: results.filter(r => r.risk === 'medium').length,
      totalLowRisk: results.filter(r => r.risk === 'low').length,
    },
  }
}

/**
 * Filter results to only show real threats (removes noise).
 * Used BEFORE grouping to ensure clean input.
 */
export function filterNoiseFindings(results: ScanResult[]): ScanResult[] {
  return results.filter(r => {
    // Always keep high-risk
    if (r.risk === 'high') return true

    // Always keep medium-risk with strong signals
    if (r.risk === 'medium') {
      const strongSignals = r.matches.some(m =>
        /cheat|inject|hack|dma|fpga|spoof|bypass|🎭|🧬|🔐|YARA/i.test(m)
      )
      if (strongSignals) return true
    }

    // Filter out low-risk noise:
    // - Files without meaningful match data
    // - System path files with only "Extension" or "No digital signature" matches
    if (r.risk === 'low') {
      const meaningfulMatches = r.matches.filter(m =>
        !m.startsWith('Extension ') &&
        !m.includes('No digital signature') &&
        !m.includes('Recently created') &&
        m.length > 10
      )
      // Keep only if there's at least 1 meaningful match beyond basic flags
      if (meaningfulMatches.length === 0) return false
    }

    return true
  })
}
