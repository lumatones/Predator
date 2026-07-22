/**
 * Predator v3.0 — Cheat Rules Engine
 * YARA-like binary rules, trust whitelist, and PE analysis.
 *
 * Ported from predator_scanner_v3/rules/cheats.yar + whitelist + pe analysis.
 */

import fs from 'fs'
import path from 'path'

// ═══════════════════════════════════════════════
// YARA-LIKE RULES
// ═══════════════════════════════════════════════

export interface YaraRule {
  name: string
  description: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'WARNING'
  /** Binary string patterns to search for */
  strings: Buffer[]
  /** Number of strings that must match (default: anyOf = 1) */
  minMatch: number
  /** Case-insensitive string patterns (text) */
  textStrings?: string[]
}

const YARA_RULES: YaraRule[] = [
  {
    name: 'injector_api',
    description: 'Detects DLL injector API usage',
    risk: 'CRITICAL',
    strings: [
      Buffer.from('CreateRemoteThread'),
      Buffer.from('WriteProcessMemory'),
      Buffer.from('VirtualAllocEx'),
      Buffer.from('NtCreateThreadEx'),
      Buffer.from('RtlCreateUserThread'),
      Buffer.from('SetThreadContext'),
    ],
    minMatch: 2,
  },
  {
    name: 'debugger_api',
    description: 'Detects debugger API usage',
    risk: 'CRITICAL',
    strings: [
      Buffer.from('IsDebuggerPresent'),
      Buffer.from('CheckRemoteDebuggerPresent'),
      Buffer.from('NtQueryInformationProcess'),
      Buffer.from('DebugActiveProcess'),
      Buffer.from('HideThreadFromDebugger'),
    ],
    minMatch: 2,
  },
  {
    name: 'cheat_strings',
    description: 'Detects cheat menu related strings',
    risk: 'HIGH',
    strings: [],
    textStrings: ['aimbot', 'wallhack', 'esp', 'triggerbot', 'norecoil', 'bhop', 'speedhack', 'godmode'],
    minMatch: 2,
  },
  {
    name: 'bypass_strings',
    description: 'Detects anti-cheat bypass related strings',
    risk: 'CRITICAL',
    strings: [],
    textStrings: ['bypass', 'anti-cheat', 'anticheat', 'BattlEye', 'EasyAntiCheat', 'Vanguard', 'evade'],
    minMatch: 2,
  },
  {
    name: 'obfuscator_packer',
    description: 'Detects known packers/obfuscators',
    risk: 'HIGH',
    strings: [
      Buffer.from('VMProtect'),
      Buffer.from('Themida'),
      Buffer.from('Enigma'),
      Buffer.from('Obsidium'),
      Buffer.from('UPX!'),
      Buffer.from('ASPack'),
    ],
    minMatch: 1,
  },
  {
    name: 'imgui_overlay',
    description: 'Detects ImGui overlay framework (common in game cheats)',
    risk: 'HIGH',
    strings: [
      Buffer.from('ImGui'),
      Buffer.from('ImDrawList'),
      Buffer.from('ImFontAtlas'),
      Buffer.from('ImVec2'),
    ],
    minMatch: 3,
  },
  {
    name: 'dma_fpga',
    description: 'Detects DMA/FPGA related strings (memory dumping hardware)',
    risk: 'CRITICAL',
    strings: [],
    textStrings: ['pcileech', 'fuser', 'leechcore', 'memprocfs', 'coremap', 'ftd3xx', 'ftd2xx', 'screamer'],
    minMatch: 1,
  },
  {
    name: 'process_hacker',
    description: 'Detects process manipulation tools',
    risk: 'HIGH',
    strings: [],
    textStrings: ['process hacker', 'processhacker', 'Handle', 'OpenProcess', 'NtOpenProcess', 'NtDuplicateObject'],
    minMatch: 2,
  },
]

export function getYaraRules(): YaraRule[] {
  return YARA_RULES
}

/**
 * Evaluate YARA rules against a binary buffer.
 * Returns list of matched rule names with their risk level.
 */
export interface YaraMatch {
  ruleName: string
  description: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'WARNING'
  matchedStrings: string[]
}

export function evaluateYara(buffer: Buffer, stringsLower?: string[]): YaraMatch[] {
  const matches: YaraMatch[] = []

  for (const rule of YARA_RULES) {
    let matchCount = 0
    const matchedStrings: string[] = []

    // Binary string matching
    for (const sig of rule.strings) {
      if (buffer.includes(sig)) {
        matchCount++
        matchedStrings.push(sig.toString('utf-8').slice(0, 30))
      }
    }

    // Text string matching (case-insensitive)
    if (rule.textStrings && stringsLower) {
      for (const text of rule.textStrings) {
        if (stringsLower.some(s => s.includes(text.toLowerCase()))) {
          matchCount++
          matchedStrings.push(text)
        }
      }
    }

    if (matchCount >= rule.minMatch) {
      matches.push({
        ruleName: rule.name,
        description: rule.description,
        risk: rule.risk,
        matchedStrings,
      })
    }
  }

  return matches
}

// ═══════════════════════════════════════════════
// WHITELIST (TRUSTED_PATHS + TRUSTED_COMPANIES)
// ═══════════════════════════════════════════════

const TRUSTED_PATHS = [
  '\\Windows\\System32\\',
  '\\Windows\\SysWOW64\\',
  '\\Windows\\WinSxS\\',
  '\\Windows\\Microsoft.NET\\',
  '\\Program Files\\',
  '\\Program Files (x86)\\',
  '\\ProgramData\\Microsoft\\',
  '\\AppData\\Local\\Microsoft\\',
  '\\AppData\\Local\\Temp\\',
  '\\AppData\\Local\\Google\\Chrome\\',
  '\\AppData\\Local\\Yandex\\YandexBrowser\\',
  '\\AppData\\Roaming\\Opera Software\\',
  '\\AppData\\Roaming\\Microsoft\\',
  '\\Users\\Public\\',
  '\\Windows\\Temp\\',
]

const TRUSTED_COMPANIES = [
  'microsoft corporation',
  'google inc',
  'google llc',
  'mozilla corporation',
  'mozilla foundation',
  'apple inc.',
  'adobe inc.',
  'adobe systems incorporated',
  'oracle corporation',
  'intel corporation',
  'intel(r) corporation',
  'nvidia corporation',
  'amd',
  'advanced micro devices',
  'realtek semiconductor',
  'broadcom',
  'qualcomm',
  'spotify',
  'discord inc.',
  'slack technologies',
  'github',
  'docker',
  'node.js',
  'python software foundation',
  'the node.js foundation',
  'jetbrains s.r.o.',
  'microsoft',
]

/**
 * Check if a filepath is in a trusted location.
 */
export function isTrustedPath(filepath: string): boolean {
  const lower = filepath.toLowerCase()
  for (const trusted of TRUSTED_PATHS) {
    if (lower.includes(trusted.toLowerCase())) return true
  }
  return false
}

/**
 * Check if a company name is trusted.
 */
export function isTrustedCompany(company: string): boolean {
  const lower = company.toLowerCase()
  for (const trusted of TRUSTED_COMPANIES) {
    if (lower.includes(trusted)) return true
  }
  return false
}

// ═══════════════════════════════════════════════
// PE ANALYSIS
// ═══════════════════════════════════════════════

export interface PeAnalysisResult {
  /** Whether the file is a valid PE (has MZ + PE signatures) */
  isValidPe: boolean
  /** Number of sections in the PE */
  sectionCount: number
  /** Suspicious section names found */
  suspiciousSections: string[]
  /** Whether the PE has suspicious characteristics */
  isSuspicious: boolean
  /** Subsystem type */
  subsystem: string
  /** Whether IMAGE_FILE_RELOCS_STRIPPED is set */
  relocsStripped: boolean
  /** Whether the entry point is in a suspicious section */
  entryPointInSuspiciousSection: boolean
}

const KNOWN_SUSPICIOUS_SECTIONS = [
  '.text', '.rdata', '.data', '.pdata', '.rsrc', '.reloc',
  // Legitimate but often abused:
  // Actual suspicious sections:
  '.vmp', '.themida', '.enigma', '.packed', '.upx0', '.upx1',
  '.nsp0', '.nsp1', '.petite', '.morph', '.kkrunchy',
  // Unusual section names suggest packing/obfuscation:
  '.0000', 'PEC2MO', 'PEC2',
]

// Well-known legitimate section names
const LEGIT_SECTIONS = new Set([
  '.text', '.bss', '.rdata', '.data', '.pdata', '.rsrc', '.reloc',
  '.idata', '.edata', '.tls', '.debug', '.CRT', '.didat',
  '.sxdata', '.loadcfg', '.00cfg',
])

/**
 * Analyze PE headers of a binary file.
 * Reads: MZ signature → PE signature → COFF header → Optional header → Sections
 */
export function analyzePeHeaders(filepath: string): PeAnalysisResult | null {
  try {
    const stat = fs.statSync(filepath)
    if (stat.size < 64) return null // Too small to be a PE

    const fd = fs.openSync(filepath, 'r')
    const buffer = Buffer.alloc(Math.min(stat.size, 4096)) // Read first 4KB for headers
    fs.readSync(fd, buffer, 0, buffer.length, 0)
    fs.closeSync(fd)

    // Check MZ signature
    if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
      return { isValidPe: false, sectionCount: 0, suspiciousSections: [], isSuspicious: false, subsystem: '', relocsStripped: false, entryPointInSuspiciousSection: false }
    }

    // Read PE offset from MZ header at offset 0x3C
    const peOffset = buffer.readUInt32LE(0x3C)
    if (peOffset + 4 > buffer.length) {
      return { isValidPe: false, sectionCount: 0, suspiciousSections: [], isSuspicious: false, subsystem: '', relocsStripped: false, entryPointInSuspiciousSection: false }
    }

    // Check PE signature ("PE\0\0")
    if (buffer[peOffset] !== 0x50 || buffer[peOffset + 1] !== 0x45 ||
        buffer[peOffset + 2] !== 0x00 || buffer[peOffset + 3] !== 0x00) {
      return { isValidPe: true, sectionCount: 0, suspiciousSections: [], isSuspicious: false, subsystem: '', relocsStripped: false, entryPointInSuspiciousSection: false }
    }

    const peSigOffset = peOffset + 4

    // COFF header (20 bytes)
    const coffHeader = peSigOffset
    const machine = buffer.readUInt16LE(coffHeader)
    const sectionCount = buffer.readUInt16LE(coffHeader + 2)
    const characteristics = buffer.readUInt16LE(coffHeader + 18)

    // Optional header follows COFF header
    const optHeader = coffHeader + 20
    const magic = buffer.readUInt16LE(optHeader)

    let subsystem = 0
    let entryPointAddress = 0
    let imageBase = 0

    if (magic === 0x10B) { // PE32
      entryPointAddress = buffer.readUInt32LE(optHeader + 16)
      imageBase = buffer.readUInt32LE(optHeader + 28)
      subsystem = buffer.readUInt16LE(optHeader + 68)
    } else if (magic === 0x20B) { // PE32+
      entryPointAddress = buffer.readUInt32LE(optHeader + 16)
      imageBase = Number(buffer.readBigUInt64LE(optHeader + 24))
      subsystem = buffer.readUInt16LE(optHeader + 72)
    }

    // Section headers (each 40 bytes, starting after optional header)
    const sectionOffset = optHeader + (magic === 0x10B ? 0xF8 : 0xF0)
    const suspiciousSections: string[] = []
    let entryPointInSuspiciousSection = false

    for (let i = 0; i < sectionCount && i < 40; i++) {
      const secStart = sectionOffset + i * 40
      if (secStart + 8 > buffer.length) break

      // Section name is 8 bytes, null-terminated
      let nameBytes: number[] = []
      for (let j = 0; j < 8; j++) {
        const b = buffer[secStart + j]
        if (b === 0) break
        nameBytes.push(b)
      }
      const sectionName = '.' + String.fromCharCode(...nameBytes).replace(/^\./, '')

      // Virtual address for entry point check
      const virtualAddress = buffer.readUInt32LE(secStart + 12)

      // Check if entry point is in this section
      const sectionSize = buffer.readUInt32LE(secStart + 8)
      if (entryPointAddress >= virtualAddress && entryPointAddress < virtualAddress + sectionSize) {
        if (!LEGIT_SECTIONS.has(sectionName)) {
          entryPointInSuspiciousSection = true
        }
      }

      // Check section name
      if (!LEGIT_SECTIONS.has(sectionName) && sectionName.length > 1) {
        suspiciousSections.push(sectionName)
      }
    }

    const subsystemNames: Record<number, string> = {
      1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI',
      5: 'OS2_CUI', 7: 'POSIX_CUI',
      9: 'WINDOWS_CE_GUI', 10: 'EFI',
    }

    const relocsStripped = (characteristics & 0x0001) !== 0
    const isSuspicious = suspiciousSections.length > 0 || entryPointInSuspiciousSection || relocsStripped

    return {
      isValidPe: true,
      sectionCount,
      suspiciousSections,
      isSuspicious,
      subsystem: subsystemNames[subsystem] || `UNKNOWN(${subsystem})`,
      relocsStripped,
      entryPointInSuspiciousSection,
    }
  } catch {
    return null
  }
}
