/**
 * Result Grouper (Frontend)
 *
 * Groups raw scan results into logical "cheat groups" for cleaner UI display.
 * This is a pure-function frontend version — no Node.js dependencies.
 */

import type { ScanResult } from '../types/electron'

export interface CheatGroup {
  cheatName: string
  risk: 'high' | 'medium' | 'low'
  findings: ScanResult[]
  counts: {
    files: number
    processes: number
    registry: number
    browser: number
    hardware: number
    other: number
  }
  tags: string[]
  confidence: number
}

export interface DeviceSummary {
  connectedSafe: ScanResult[]
  connectedSuspicious: ScanResult[]
  dmaHistory: ScanResult[]
  hasSuspiciousDevices: boolean
  hasDmaHistory: boolean
}

export interface GroupedResults {
  cheatGroups: CheatGroup[]
  otherHigh: ScanResult[]
  otherMedium: ScanResult[]
  otherLow: ScanResult[]
  deviceSummary: DeviceSummary
  summary: {
    totalCheatsDetected: number
    totalHighRisk: number
    totalMediumRisk: number
    totalLowRisk: number
  }
}

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

function extractCheatName(finding: ScanResult): string | null {
  const searchText = [
    finding.fileName.toLowerCase(),
    finding.path.toLowerCase(),
    ...finding.matches.map(m => m.toLowerCase()),
  ].join(' ')

  for (const [canonicalName, aliases] of Object.entries(CHEAT_NAME_MAP)) {
    for (const alias of aliases) {
      if (searchText.includes(alias)) return canonicalName
    }
  }

  for (const match of finding.matches) {
    const procMatch = match.match(/^process:(.+)/i)
    if (procMatch) {
      const name = procMatch[1].trim().toLowerCase()
      for (const [cn, aliases] of Object.entries(CHEAT_NAME_MAP)) {
        if (aliases.some(a => name.includes(a))) return cn
      }
    }
    const fileMatch = match.match(/^(?:file|folder|lua):(.+)/i)
    if (fileMatch) {
      const name = fileMatch[1].trim().toLowerCase()
      for (const [cn, aliases] of Object.entries(CHEAT_NAME_MAP)) {
        if (aliases.some(a => name.includes(a))) return cn
      }
    }
    const yaraMatch = match.match(/YARA\s*\[([^\]]+)\]/i)
    if (yaraMatch) {
      const ruleName = yaraMatch[1].toLowerCase()
      for (const [cn, aliases] of Object.entries(CHEAT_NAME_MAP)) {
        if (aliases.some(a => ruleName.includes(a))) return cn
      }
    }
  }

  return null
}

function calculateConfidence(findings: ScanResult[]): number {
  if (findings.length === 0) return 0
  let score = 0
  const highCount = findings.filter(f => f.risk === 'high').length
  const mediumCount = findings.filter(f => f.risk === 'medium').length
  score += Math.min(findings.length * 15, 45)
  score += highCount * 20
  score += mediumCount * 5
  const types = new Set(findings.map(f => f.type))
  score += (types.size - 1) * 10
  return Math.min(score, 100)
}

export function groupResults(results: ScanResult[]): GroupedResults {
  const cheatGroupMap = new Map<string, ScanResult[]>()
  const otherHigh: ScanResult[] = []
  const otherMedium: ScanResult[] = []
  const otherLow: ScanResult[] = []
  const hardwareFindings: ScanResult[] = []

  // Separate hardware from software findings
  for (const finding of results) {
    if (finding.type === 'hardware') {
      hardwareFindings.push(finding)
      continue
    }

    const cheatName = extractCheatName(finding)
    if (cheatName) {
      const existing = cheatGroupMap.get(cheatName) || []
      existing.push(finding)
      cheatGroupMap.set(cheatName, existing)
    } else {
      if (finding.risk === 'high') otherHigh.push(finding)
      else if (finding.risk === 'medium') otherMedium.push(finding)
      else otherLow.push(finding)
    }
  }

  // Device summary from hardware findings
  const deviceSummary: DeviceSummary = {
    connectedSafe: [],
    connectedSuspicious: [],
    dmaHistory: [],
    hasSuspiciousDevices: false,
    hasDmaHistory: false,
  }

  for (const hw of hardwareFindings) {
    const lowerPath = hw.path.toLowerCase()
    const isDma = hw.matches.some(m => 
      m.toLowerCase().includes('dma device') || 
      m.toLowerCase().includes('fpga controller') ||
      m.toLowerCase().includes('dma cheat') ||
      m.toLowerCase().includes('ftdi ft601')
    )
    const isHistory = hw.matches.some(m => 
      m.toLowerCase().includes('was connected') || 
      m.toLowerCase().includes('previously connected')
    )

    if (lowerPath.includes('dma/fpga') || isDma) {
      deviceSummary.connectedSuspicious.push(hw)
      deviceSummary.hasSuspiciousDevices = true
    } else if (lowerPath.includes('dma history') || isHistory) {
      deviceSummary.dmaHistory.push(hw)
      deviceSummary.hasDmaHistory = true
    } else {
      deviceSummary.connectedSafe.push(hw)
    }
  }

  // Build cheat groups
  const cheatGroups: CheatGroup[] = []
  for (const [cheatName, findings] of cheatGroupMap) {
    const risk: 'high' | 'medium' | 'low' = findings.some(f => f.risk === 'high')
      ? 'high'
      : findings.some(f => f.risk === 'medium') ? 'medium' : 'low'

    const counts = {
      files: findings.filter(f => f.type === 'file').length,
      processes: findings.filter(f => f.type === 'process').length,
      registry: findings.filter(f => f.type === 'registry').length,
      browser: findings.filter(f => f.type === 'browser').length,
      hardware: findings.filter(f => f.type === 'hardware').length,
      other: findings.filter(f => !['file', 'process', 'registry', 'browser', 'hardware'].includes(f.type)).length,
    }

    const tagSet = new Set<string>()
    for (const f of findings) {
      for (const m of f.matches) {
        const clean = m
          .replace(/^(process|file|folder|lua|content|signatures|archive|binary-sig):/i, '')
          .replace(/^YARA\s*\[/i, '')
          .replace(/\]$/, '')
          .trim()
        if (clean.length > 3 && clean.length < 60) tagSet.add(clean)
      }
    }

    cheatGroups.push({ cheatName, risk, findings, counts, tags: Array.from(tagSet).slice(0, 8), confidence: calculateConfidence(findings) })
  }

  cheatGroups.sort((a, b) => {
    const riskOrder = { high: 0, medium: 1, low: 2 }
    const diff = riskOrder[a.risk] - riskOrder[b.risk]
    return diff !== 0 ? diff : b.confidence - a.confidence
  })

  return {
    cheatGroups,
    otherHigh,
    otherMedium,
    otherLow,
    deviceSummary,
    summary: {
      totalCheatsDetected: cheatGroups.length,
      totalHighRisk: results.filter(r => r.risk === 'high').length,
      totalMediumRisk: results.filter(r => r.risk === 'medium').length,
      totalLowRisk: results.filter(r => r.risk === 'low').length,
    },
  }
}
