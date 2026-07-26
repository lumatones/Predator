/**
 * Predator v3.0 — Cheat Rules Engine
 * YARA-like binary rules, trust whitelist, and PE analysis.
 *
 * Ported from predator_scanner_v3/rules/cheats.yar + whitelist + pe analysis.
 * Updated 2026-07-24: added cheat loader rules, enhanced PE heuristics.
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
  // ── v0.0.12: New rules for external cheat loaders ──
  {
    name: 'cheat_loader_d3d11',
    description: 'Detects cheat loaders using DirectX 11 hooking (d3d11.dll injection)',
    risk: 'CRITICAL',
    strings: [
      Buffer.from('d3d11.dll'),
      Buffer.from('D3D11CreateDevice'),
      Buffer.from('D3D11CreateDeviceAndSwapChain'),
    ],
    minMatch: 2,
  },
  {
    name: 'masquerading_loader',
    description: 'Detects executables masquerading as legitimate software',
    risk: 'HIGH',
    strings: [],
    textStrings: ['cheat engine', 'injector', 'dma tool', 'memory reader', 'process dump', 'memory dump', 'dump memory'],
    minMatch: 1,
  },
  {
    name: 'external_memory_access',
    description: 'Detects external memory access patterns (OpenProcess + ReadProcessMemory)',
    risk: 'CRITICAL',
    strings: [
      Buffer.from('OpenProcess'),
      Buffer.from('ReadProcessMemory'),
      Buffer.from('WriteProcessMemory'),
      Buffer.from('VirtualQueryEx'),
    ],
    minMatch: 3,
  },
  {
    name: 'gta5_hooking',
    description: 'Detects GTA 5 specific hooking techniques (ScriptHookV, ASI loader, etc.)',
    risk: 'HIGH',
    strings: [],
    textStrings: ['scripthook', 'nativeui', 'menyoo', 'dinput8', 'shvdn', 'asi loader'],
    minMatch: 1,
  },
  {
    name: 'five_m_bypass',
    description: 'Detects FiveM anticheat bypass related strings',
    risk: 'CRITICAL',
    strings: [],
    textStrings: ['citizenfx bypass', 'fivem bypass', 'cfx bypass', 'fivem anticheat', 'citizen evasion'],
    minMatch: 1,
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
  '\\Windows\\Temp\\',
  '\\Program Files\\',
  '\\Program Files (x86)\\',
  '\\ProgramData\\Microsoft\\',
  '\\ProgramData\\Package Cache\\',
  '\\AppData\\Local\\Microsoft\\',
  '\\AppData\\Local\\Temp\\',
  '\\AppData\\Local\\Google\\Chrome\\',
  '\\AppData\\Local\\Google\\Chrome SxS\\',
  '\\AppData\\Local\\Yandex\\YandexBrowser\\',
  '\\AppData\\Local\\BraveSoftware\\',
  '\\AppData\\Roaming\\Opera Software\\',
  '\\AppData\\Roaming\\Microsoft\\',
  '\\Users\\Public\\',
  // Game platform launchers (legitimate)
  '\\Steam\\steamapps\\',
  '\\Epic Games\\',
  '\\Rockstar Games\\Launcher\\',
  // Legitimate modding tools
  '\\AppData\\Local\\Discord\\',
  '\\AppData\\Roaming\\discord\\',
  '\\AppData\\Local\\Slack\\',
  '\\AppData\\Local\\Spotify\\',
  '\\AppData\\Local\\Programs\\',
  '\\AppData\\Local\\JetBrains\\',
  '\\AppData\\Local\\GitHubDesktop\\',
  '\\AppData\\Local\\Microsoft\\Teams\\',
]

const TRUSTED_COMPANIES = [
  'microsoft corporation',
  'google inc',
  'google llc',
  'mozilla corporation',
  'mozilla foundation',
  'apple inc.',
  'apple inc',
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
  'rockstar games',
  'rockstar north',
  'take-two interactive',
  'cfx.re',
  'rage mp',
  'altv',
  'epic games',
  'valve corporation',
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
  /** v0.0.12: Overall suspicion score from PE analysis (0-100) */
  peSuspicionScore: number
  /** Whether the PE has an import table directory (IMAGE_DIRECTORY_ENTRY_IMPORT) */
  hasImportTable?: boolean
}

// Well-known legitimate section names
const LEGIT_SECTIONS = new Set([
  '.text', '.bss', '.rdata', '.data', '.pdata', '.rsrc', '.reloc',
  '.idata', '.edata', '.tls', '.debug', '.CRT', '.didat',
  '.sxdata', '.loadcfg', '.00cfg',
])

// Section names that suggest packing / obfuscation
const PACKED_SECTIONS = new Set([
  '.vmp', '.themida', '.enigma', '.packed', '.upx0', '.upx1',
  '.nsp0', '.nsp1', '.petite', '.morph', '.kkrunchy',
  '.0000', 'PEC2MO', 'PEC2',
])

// ═══════════════════════════════════════════════
// SECTION ENTROPY ANALYSIS
// ═══════════════════════════════════════════════

export interface SectionEntropy {
  name: string
  rawOffset: number
  rawSize: number
  virtualSize: number
  entropy: number
  isSuspicious: boolean
  reason?: string
}

/**
 * Section entropy threshold map:
 *   .text → 5.5–7.5 = normal (code)
 *   .data → 2.0–5.5 = normal (usually structs, arrays)
 *   .rsrc  → < 5.0 = normal (icons, version info)
 *   .rdata → < 6.0 = normal (strings, constants)
 *   .reloc → < 4.5 = normal
 */
function getSectionEntropyThresholds(name: string): { low: number; high: number; suspicious: number } {
  switch (name) {
    case '.text': case 'CODE':
      return { low: 5.0, high: 7.8, suspicious: 8.0 }
    case '.data':
      return { low: 1.5, high: 6.0, suspicious: 7.0 }
    case '.rsrc':
      return { low: 0.5, high: 4.5, suspicious: 7.5 }
    case '.rdata':
      return { low: 1.0, high: 5.5, suspicious: 7.0 }
    case '.reloc':
      return { low: 0.5, high: 4.0, suspicious: 6.5 }
    case '.pdata':
      return { low: 1.0, high: 4.5, suspicious: 6.0 }
    default:
      return { low: 0.0, high: 7.0, suspicious: 7.8 }
  }
}

/**
 * Calculate Shannon entropy per section of a PE file.
 * Flags sections where entropy is anomalous for the section type:
 *   - .rsrc entropy > 7.5 → hidden shellcode/config
 *   - .text entropy < 5.0 → possibly packed/obfuscated
 *   - Unknown section with high entropy → packed
 */
export function analyzeSectionEntropy(filepath: string): SectionEntropy[] {
  const results: SectionEntropy[] = []

  try {
    const stat = fs.statSync(filepath)
    if (stat.size < 64) return results

    // Read full headers to find section table
    const headerSize = Math.min(stat.size, 4096)
    const headerBuf = Buffer.alloc(headerSize)
    const fd = fs.openSync(filepath, 'r')
    fs.readSync(fd, headerBuf, 0, headerSize, 0)

    // Validate MZ + PE
    if (headerBuf[0] !== 0x4D || headerBuf[1] !== 0x5A) { fs.closeSync(fd); return results }
    const peOff = headerBuf.readUInt32LE(0x3C)
    if (peOff + 24 > headerSize ||
        headerBuf[peOff] !== 0x50 || headerBuf[peOff + 1] !== 0x45) { fs.closeSync(fd); return results }

    const numSections = headerBuf.readUInt16LE(peOff + 4 + 2)
    const optHeaderSize = headerBuf.readUInt16LE(peOff + 4 + 16)
    const secOff = peOff + 4 + 20 + optHeaderSize

    // Read section table (40 bytes each)
    const tableSize = Math.min(numSections * 40, headerSize - secOff)
    if (tableSize < 40) { fs.closeSync(fd); return results }

    const sectionTable = Buffer.alloc(tableSize)
    // Re-read from the correct offset (might be past initial 4KB)
    fs.readSync(fd, sectionTable, 0, tableSize, secOff)
    fs.closeSync(fd)

    for (let i = 0; i < numSections && i < 40; i++) {
      const o = i * 40
      let name = ''
      for (let j = 0; j < 8 && sectionTable[o + j] !== 0; j++) name += String.fromCharCode(sectionTable[o + j])

      const secName = name.startsWith('.') ? name : `.${name}`
      const rawOffset = sectionTable.readUInt32LE(o + 20)
      const rawSize = sectionTable.readUInt32LE(o + 16)
      const virtualSize = sectionTable.readUInt32LE(o + 8)

      if (rawSize === 0 || rawOffset === 0) continue

      // Read section content from disk
      const readSize = Math.min(rawSize, 10 * 1024 * 1024) // max 10 MB per section
      if (rawOffset + readSize > stat.size) continue

      const secBuf = Buffer.alloc(readSize)
      const fd2 = fs.openSync(filepath, 'r')
      const bytesRead = fs.readSync(fd2, secBuf, 0, readSize, rawOffset)
      fs.closeSync(fd2)

      if (bytesRead < 16) continue

      // Calculate entropy
      const entropy = calculateEntropyFromBuf(secBuf.subarray(0, bytesRead))

      // Check thresholds
      const thresholds = getSectionEntropyThresholds(secName)
      let isSuspicious = false
      let reason: string | undefined

      // .rsrc with entropy > 7.5 = hidden shellcode/config
      if (entropy > thresholds.suspicious) {
        isSuspicious = true
        reason = `Entropy ${entropy.toFixed(2)} > ${thresholds.suspicious.toFixed(1)} — unusually high for section type (possible packed/hidden code)`
      }

      // .text with entropy < 5.0 = packed/obfuscated code
      if ((secName === '.text' || secName === 'CODE') && entropy < 5.0) {
        isSuspicious = true
        reason = `Entropy ${entropy.toFixed(2)} < 5.0 — unusually low for code section (obfuscated/packed)`
      }

      results.push({
        name: secName,
        rawOffset,
        rawSize,
        virtualSize,
        entropy,
        isSuspicious,
        reason,
      })
    }
  } catch { /* skip unreadable files */ }

  return results
}

/** Internal entropy calculator (avoids circular deps) */
function calculateEntropyFromBuf(data: Buffer): number {
  if (!data || data.length === 0) return 0
  const freq = new Array(256).fill(0)
  for (const b of data) freq[b]++
  const len = data.length
  let entropy = 0
  for (const count of freq) {
    if (count > 0) {
      const p = count / len
      entropy -= p * Math.log2(p)
    }
  }
  return entropy
}

/**
 * Analyze PE headers of a binary file.
 * Reads: MZ signature → PE signature → COFF header → Optional header → Sections
 */
export function analyzePeHeaders(filepath: string): PeAnalysisResult | null {
  try {
    const stat = fs.statSync(filepath)
    if (stat.size < 64) return null // Too small to be a PE

    const fd = fs.openSync(filepath, 'r')
    const buffer = Buffer.alloc(Math.min(stat.size, 4096))
    fs.readSync(fd, buffer, 0, buffer.length, 0)
    fs.closeSync(fd)

    // Check MZ signature
    if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
      return {
        isValidPe: false, sectionCount: 0, suspiciousSections: [],
        isSuspicious: false, subsystem: '', relocsStripped: false,
        entryPointInSuspiciousSection: false, peSuspicionScore: 0,
      }
    }

    // Read PE offset from MZ header at offset 0x3C
    const peOffset = buffer.readUInt32LE(0x3C)
    if (peOffset + 4 > buffer.length) {
      return {
        isValidPe: false, sectionCount: 0, suspiciousSections: [],
        isSuspicious: false, subsystem: '', relocsStripped: false,
        entryPointInSuspiciousSection: false, peSuspicionScore: 0,
      }
    }

    // Check PE signature ("PE\0\0")
    if (buffer[peOffset] !== 0x50 || buffer[peOffset + 1] !== 0x45 ||
        buffer[peOffset + 2] !== 0x00 || buffer[peOffset + 3] !== 0x00) {
      return {
        isValidPe: true, sectionCount: 0, suspiciousSections: [],
        isSuspicious: false, subsystem: '', relocsStripped: false,
        entryPointInSuspiciousSection: false, peSuspicionScore: 0,
      }
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

    if (magic === 0x10B) { // PE32
      entryPointAddress = buffer.readUInt32LE(optHeader + 16)
      subsystem = buffer.readUInt16LE(optHeader + 68)
    } else if (magic === 0x20B) { // PE32+
      entryPointAddress = buffer.readUInt32LE(optHeader + 16)
      subsystem = buffer.readUInt16LE(optHeader + 72)
    }

    // Section headers (each 40 bytes, starting after optional header)
    const sectionOffset = optHeader + (magic === 0x10B ? 0xF8 : 0xF0)
    const suspiciousSections: string[] = []
    let entryPointInSuspiciousSection = false
    let packedSectionFound = false

    for (let i = 0; i < sectionCount && i < 40; i++) {
      const secStart = sectionOffset + i * 40
      if (secStart + 8 > buffer.length) break

      // Section name is 8 bytes, null-terminated
      const nameBytes: number[] = []
      for (let j = 0; j < 8; j++) {
        const b = buffer[secStart + j]
        if (b === 0) break
        nameBytes.push(b)
      }
      const sectionName = '.' + String.fromCharCode(...nameBytes).replace(/^\./, '')

      // Virtual address for entry point check
      const virtualAddress = buffer.readUInt32LE(secStart + 12)
      const sectionSize = buffer.readUInt32LE(secStart + 8)

      // Check if entry point is in this section
      if (entryPointAddress >= virtualAddress && entryPointAddress < virtualAddress + sectionSize) {
        if (!LEGIT_SECTIONS.has(sectionName)) {
          entryPointInSuspiciousSection = true
        }
      }

      // Check section name
      if (!LEGIT_SECTIONS.has(sectionName) && sectionName.length > 1) {
        suspiciousSections.push(sectionName)
      }
      if (PACKED_SECTIONS.has(sectionName)) {
        packedSectionFound = true
      }
    }

    const subsystemNames: Record<number, string> = {
      1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI',
      5: 'OS2_CUI', 7: 'POSIX_CUI',
      9: 'WINDOWS_CE_GUI', 10: 'EFI',
    }

    const relocsStripped = (characteristics & 0x0001) !== 0
    const isSuspicious = suspiciousSections.length > 0 || entryPointInSuspiciousSection || relocsStripped

    // v0.0.12: Calculate overall suspicion score (0-100)
    let peSuspicionScore = 0
    // Suspicious sections: +10 each, max +40
    peSuspicionScore += Math.min(suspiciousSections.length * 10, 40)
    // Entry point in suspicious section: +20
    if (entryPointInSuspiciousSection) peSuspicionScore += 20
    // Relocs stripped: +15
    if (relocsStripped) peSuspicionScore += 15
    // Unknown subsystem: +15
    if (!subsystemNames[subsystem] || subsystem === 0) peSuspicionScore += 15
    // Many sections (> 6 suggests packing): +10
    if (sectionCount > 6) peSuspicionScore += 10

    return {
      isValidPe: true,
      sectionCount,
      suspiciousSections,
      isSuspicious,
      subsystem: subsystemNames[subsystem] || `UNKNOWN(${subsystem})`,
      relocsStripped,
      entryPointInSuspiciousSection,
      peSuspicionScore,
    }
  } catch {
    return null
  }
}
