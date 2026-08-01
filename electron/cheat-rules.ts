/**
 * Predator v3.0 — Cheat Rules Engine
 * YARA-like binary rules, trust whitelist, and PE analysis.
 *
 * Ported from predator_scanner_v3/rules/cheats.yar + whitelist + pe analysis.
 * Updated 2026-07-24: added cheat loader rules, enhanced PE heuristics.
 */

import fsp from 'fs/promises'
import { readFilePrefix, readFileRange } from './utils/file-io'

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
export async function analyzeSectionEntropy(
  filepath: string,
  signal?: AbortSignal,
): Promise<SectionEntropy[]> {
  const results: SectionEntropy[] = []

  try {
    const stat = await fsp.stat(filepath)
    if (stat.size < 64) return results

    // Read headers and the section table without blocking the main process.
    const headerBuf = await readFilePrefix(filepath, Math.min(stat.size, 4096), signal)
    if (headerBuf.length < 0x40 || headerBuf[0] !== 0x4D || headerBuf[1] !== 0x5A) return results

    const peOff = headerBuf.readUInt32LE(0x3C)
    if (peOff + 24 > headerBuf.length ||
        headerBuf[peOff] !== 0x50 || headerBuf[peOff + 1] !== 0x45) return results

    const numSections = headerBuf.readUInt16LE(peOff + 4 + 2)
    const optHeaderSize = headerBuf.readUInt16LE(peOff + 4 + 16)
    const secOff = peOff + 4 + 20 + optHeaderSize
    const tableSize = Math.min(numSections * 40, 40 * 40)
    if (secOff < 0 || secOff > stat.size || tableSize < 40) return results

    const sectionTable = await readFileRange(filepath, secOff, tableSize, signal)

    for (let i = 0; i < numSections && i < 40; i++) {
      if (signal?.aborted) throw new Error('Section entropy analysis aborted')
      const o = i * 40
      if (o + 40 > sectionTable.length) break

      let name = ''
      for (let j = 0; j < 8 && sectionTable[o + j] !== 0; j++) {
        name += String.fromCharCode(sectionTable[o + j])
      }

      const secName = name.startsWith('.') ? name : `.${name}`
      const rawOffset = sectionTable.readUInt32LE(o + 20)
      const rawSize = sectionTable.readUInt32LE(o + 16)
      const virtualSize = sectionTable.readUInt32LE(o + 8)

      if (rawSize === 0 || rawOffset === 0) continue

      // Read at most 10 MB per section and reject ranges outside the file.
      const readSize = Math.min(rawSize, 10 * 1024 * 1024)
      if (rawOffset > stat.size || readSize > stat.size - rawOffset) continue

      const secBuf = await readFileRange(filepath, rawOffset, readSize, signal)
      if (secBuf.length < 16) continue

      const entropy = calculateEntropyFromBuf(secBuf)
      const thresholds = getSectionEntropyThresholds(secName)
      let isSuspicious = false
      let reason: string | undefined

      if (entropy > thresholds.suspicious) {
        isSuspicious = true
        reason = `Entropy ${entropy.toFixed(2)} > ${thresholds.suspicious.toFixed(1)} — unusually high for section type (possible packed/hidden code)`
      }

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
  } catch (err) {
    if (signal?.aborted) throw err
    // Skip unreadable or malformed files, matching the previous API behavior.
  }

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
export async function analyzePeHeaders(
  filepath: string,
  signal?: AbortSignal,
): Promise<PeAnalysisResult | null> {
  try {
    const stat = await fsp.stat(filepath)
    if (stat.size < 64) return null // Too small to be a PE

    const buffer = await readFilePrefix(filepath, Math.min(stat.size, 4096), signal)
    if (buffer.length < 2) return null

    // Check MZ signature
    if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
      return {
        isValidPe: false, sectionCount: 0, suspiciousSections: [],
        isSuspicious: false, subsystem: '', relocsStripped: false,
        entryPointInSuspiciousSection: false, peSuspicionScore: 0,
      }
    }

    // Read PE offset from MZ header at offset 0x3C
    if (buffer.length < 0x40) return null
    const peOffset = buffer.readUInt32LE(0x3C)
    if (peOffset + 24 > buffer.length) {
      return {
        isValidPe: false, sectionCount: 0, suspiciousSections: [],
        isSuspicious: false, relocsStripped: false,
        entryPointInSuspiciousSection: false, peSuspicionScore: 0,
        subsystem: '',
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
    const coffHeader = peSigOffset
    if (coffHeader + 20 > buffer.length) return null

    const sectionCount = buffer.readUInt16LE(coffHeader + 2)
    const characteristics = buffer.readUInt16LE(coffHeader + 18)
    const optHeaderSize = buffer.readUInt16LE(coffHeader + 16)
    const optHeader = coffHeader + 20
    if (optHeaderSize === 0 || optHeader + optHeaderSize > buffer.length) return null

    const magic = buffer.readUInt16LE(optHeader)
    let subsystem = 0
    let entryPointAddress = 0
    if (magic === 0x10B) {
      if (optHeaderSize < 70 || optHeader + 70 > buffer.length) return null
      entryPointAddress = buffer.readUInt32LE(optHeader + 16)
      subsystem = buffer.readUInt16LE(optHeader + 68)
    } else if (magic === 0x20B) {
      if (optHeaderSize < 74 || optHeader + 74 > buffer.length) return null
      entryPointAddress = buffer.readUInt32LE(optHeader + 16)
      subsystem = buffer.readUInt16LE(optHeader + 72)
    }

    // Section headers (each 40 bytes, starting after the actual optional header).
    const sectionOffset = optHeader + optHeaderSize
    if (sectionOffset > buffer.length) return null
    const suspiciousSections: string[] = []
    let entryPointInSuspiciousSection = false

    for (let i = 0; i < sectionCount && i < 40; i++) {
      const secStart = sectionOffset + i * 40
      if (secStart + 40 > buffer.length) break

      const nameBytes: number[] = []
      for (let j = 0; j < 8; j++) {
        const b = buffer[secStart + j]
        if (b === 0) break
        nameBytes.push(b)
      }
      const sectionName = '.' + String.fromCharCode(...nameBytes).replace(/^\./, '')
      const virtualAddress = buffer.readUInt32LE(secStart + 12)
      const sectionSize = buffer.readUInt32LE(secStart + 8)

      if (entryPointAddress >= virtualAddress &&
          entryPointAddress < virtualAddress + sectionSize &&
          !LEGIT_SECTIONS.has(sectionName)) {
        entryPointInSuspiciousSection = true
      }

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

    let peSuspicionScore = Math.min(suspiciousSections.length * 10, 40)
    if (entryPointInSuspiciousSection) peSuspicionScore += 20
    if (relocsStripped) peSuspicionScore += 15
    if (!subsystemNames[subsystem] || subsystem === 0) peSuspicionScore += 15
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
  } catch (err) {
    if (signal?.aborted) throw err
    return null
  }
}
