/**
 * Predator — Heuristic Analysis Engine
 *
 * The core scoring logic that decides whether a file or process is suspicious.
 * Extracted from the monolithic scanner.ts for testability and clarity.
 */

import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import { execSync, spawnSync } from 'child_process'

import {
  KNOWN_PROCESSES,
  KNOWN_CHEAT_FILES,
  KNOWN_LUA_SCRIPTS,
  KNOWN_CHEAT_FOLDERS,
  KNOWN_CHEAT_HASHES,
  KNOWN_BINARY_SIGNATURES,
  TARGET_EXTENSIONS,
  MASQUERADING_FILENAMES,
  isPlatformWhitelisted,
} from './cheats-db'

import {
  evaluateYara,
  isTrustedPath,
  isTrustedCompany,
  analyzePeHeaders,
  analyzeSectionEntropy,
} from './cheat-rules'

import {
  checkAutoRules,
  learnFromFile,
} from './auto-yara'

import {
  analyzeApiHashingStatic,
  analyzeApiHashingInDump,
} from './api-hashing'

import type { HeuristicResult } from './types'
import type { PeAnalysisResult, SectionEntropy } from './cheat-rules'
import { _PF, _PF86, _HOME, _WR, ctx } from './types'
import { isFileSafe } from './safe-files-db'
import { calculateEntropy } from './analysis/entropy'
import { scanStrings } from './analysis/strings'

// ═══════════════════════════════════════════════════
// SIGNATURE DATA — imported from central registry
// ═══════════════════════════════════════════════════
// All detection data (categories, keywords, patterns) lives in
// signature-registry.ts — the single source of truth.
// heuristic.ts contains only SCORING LOGIC.

export { SUSPICIOUS_CATEGORIES, ALL_CHEAT_KEYWORDS, SUSPICIOUS_PATTERNS, MIN_KEYWORD_LENGTH } from './signature-registry'
import { SUSPICIOUS_CATEGORIES, ALL_CHEAT_KEYWORDS, SUSPICIOUS_PATTERNS, MIN_KEYWORD_LENGTH } from './signature-registry'

export const SUSPICIOUS_EXTENSIONS: Record<string, string> = {
  '.dll': 'Dynamic library (possible inject)',
  '.asi': 'ASI mod GTA (game modification)',
  '.lua': 'Lua script (often used in cheats)',
  '.luac': 'Compiled Lua script',
  '.exe': 'Executable file',
  '.sys': 'System driver',
  // '.bin' and '.dat' removed — handled by skippable extensions
  '.cfg': 'Configuration file',
  '.ini': 'Configuration file',
  '.js': 'JavaScript (may contain cheat loader)',
  '.ahk': 'AutoHotkey script',
  '.zip': 'Archive (may contain cheat files)',
  '.rar': 'Archive (may contain cheat files)',
  '.7z': 'Archive (may contain cheat files)',
  '.msi': 'Installer (may contain cheat)',
}

// MIN_KEYWORD_LENGTH is now imported from ./signature-registry.
// (removed from here — single source of truth)

/** Known Electron/Chromium DLLs that are bundled unsigned with Electron apps.
 *  These should NEVER be flagged by the combo-detector. */
export const KNOWN_ELECTRON_DLLS = new Set([
  'd3dcompiler_47.dll', 'ffmpeg.dll', 'libegl.dll', 'libglesv2.dll',
  'vk_swiftshader.dll', 'vulkan-1.dll', 'vulkaninfo.exe',
  'elevate.exe', 'nsis7z.dll', 'nsprocess.dll', 'stdutils.dll',
  'system.dll', '7zr.exe',
])

/** Extensions to skip entirely (noise files with no cheat value). */
export const SKIPPABLE_EXTENSIONS = new Set([
  '.d.ts', '.d.ts.map', '.js.map', '.css.map', '.map',
  '.tsbuildinfo', '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', '.webp',
  '.mp4', '.mp3', '.wav', '.ogg', '.flac', '.avi', '.mkv', '.mov',
  '.pak', '.bin', '.dat',
])

/** Check if filename is a known Electron bundled DLL (never flag these) */
export function isKnownElectronDll(fileName: string): boolean {
  return KNOWN_ELECTRON_DLLS.has(fileName.toLowerCase())
}

/** Check if extension is skippable (noise/asset files) */
export function isSkippableExtension(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase()
  return SKIPPABLE_EXTENSIONS.has(ext)
}

export const SCAN_CONFIG = {
  SCAN_DEPTH: 3,
  MAX_FILE_SIZE: 100 * 1024 * 1024,
  MIN_FILE_SIZE: 0, // Scan ALL files — small configs/loaders can be < 1KB
  SUSPICIOUS_AGE_DAYS: 90,
  ENTROPY_THRESHOLD: 7.5,
}

// ALL_CHEAT_KEYWORDS and SUSPICIOUS_PATTERNS are now imported from ./signature-registry.
// (removed from here — single source of truth)

// Protected paths — game mod directories where files should not be
export const PROTECTED_PATHS = [
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'mods'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'plugins'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'cache'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'data'),
  path.join(_HOME, 'AppData', 'Roaming', 'CitizenFX'),
  path.join(_PF, 'RAGEMP'),
  path.join(_PF86, 'RAGEMP'),
  path.join(_HOME, 'RAGEMP'),
  path.join(_HOME, 'AppData', 'Local', 'altv', 'modules'),
  path.join(_HOME, 'AppData', 'Local', 'altv', 'resources'),
  path.join(_PF, 'Rockstar Games', 'Grand Theft Auto V'),
  path.join(_PF86, 'Rockstar Games', 'Grand Theft Auto V'),
  path.join(_PF, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
  path.join(_PF86, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
]

/** System process names that cheat loaders commonly masquerade as */
export const SYSTEM_PROC_NAMES = new Set([
  'svchost.exe', 'csrss.exe', 'lsass.exe', 'services.exe', 'smss.exe',
  'winlogon.exe', 'explorer.exe', 'spoolsv.exe', 'conhost.exe',
  'rundll32.exe', 'taskhostw.exe', 'sihost.exe', 'ctfmon.exe',
  'dwm.exe', 'fontdrvhost.exe', 'RuntimeBroker.exe',
  'SearchIndexer.exe', 'SecurityHealthSystray.exe',
  'LogonUI.exe', 'SystemSettings.exe', 'LockApp.exe',
  'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
  'applicationframehost.exe', 'SearchApp.exe',
])

// ═══════════════════════════════════════════════════
// CACHES — managed by ctx (ScanContext in types.ts)

// Pre-normalized arrays for fast substring matching
const _PROC_BASES = KNOWN_PROCESSES.map(n =>
  n.toLowerCase()
    .replace(/\.exe$/i, '')
    .replace(/_\*\.exe$/i, '')
    .replace(/\*\.exe$/i, '')
)
const _FILE_NAMES = KNOWN_CHEAT_FILES.map(n => n.toLowerCase())
const _LUA_NAMES = KNOWN_LUA_SCRIPTS.map(n => n.toLowerCase())
const _FOLDER_NAMES = KNOWN_CHEAT_FOLDERS.map(n => n.toLowerCase())

// ═══════════════════════════════════════════════════
// PURE FUNCTIONS (re-exported from analysis/)
// ═══════════════════════════════════════════════════

export { calculateEntropy } from './analysis/entropy'
export { scanStrings } from './analysis/strings'

// ═══════════════════════════════════════════════════
// MASQUERADING EXECUTABLE HEURISTIC
// ═══════════════════════════════════════════════════

export function checkMasqueradingExecutable(
  fileName: string,
  filepath: string,
  stat: fs.Stats,
  peInfo: PeAnalysisResult | null,
  secEntropy: SectionEntropy[],
  entropy: number,
  sigValid: boolean,
): { isMasquerading: boolean; signals: string[] } {
  const signals: string[] = []
  const lowerName = fileName.toLowerCase()

  if (!MASQUERADING_FILENAMES.has(lowerName)) {
    return { isMasquerading: false, signals }
  }

  signals.push(`Filename matches masquerading target: ${fileName}`)

  const systemPaths = [
    path.join(_WR, 'System32').toLowerCase(),
    path.join(_WR, 'SysWOW64').toLowerCase(),
    path.join(_WR).toLowerCase(),
  ]
  const fpLower = filepath.toLowerCase()
  const inSystemDir = systemPaths.some(p => fpLower.startsWith(p))

  if (inSystemDir) {
    const winSysFiles = new Set(['conhost.exe', 'rundll32.exe', 'svchost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'explorer.exe', 'notepad.exe'])
    if (winSysFiles.has(lowerName)) {
      signals.push(`Located in System32 — legitimate Windows component, not flagged`)
      return { isMasquerading: false, signals }
    }
  }

  if (sigValid) {
    signals.push(`Has valid digital signature — likely legitimate version`)
    if (entropy > 7.0 || (peInfo && peInfo.sectionCount >= 7)) {
      signals.push('But file is packed/obfuscated despite valid signature — suspicious')
    } else {
      return { isMasquerading: false, signals }
    }
  } else {
    signals.push('No digital signature — legitimate versions of this software ALWAYS have one')
  }

  if (peInfo) {
    if (peInfo.sectionCount >= 7) {
      signals.push(`Suspicious: ${peInfo.sectionCount} PE sections (expected 3-5 for legitimate tool)`)
    }
    if (peInfo.relocsStripped) {
      signals.push('PE relocations stripped — suggests packing/obfuscation')
    }
    if (peInfo.entryPointInSuspiciousSection) {
      signals.push('Entry point in unusual section — packed executable')
    }
  }

  if (secEntropy.length > 0) {
    const highEntropySections = secEntropy.filter(s => s.entropy > 7.5)
    for (const sec of highEntropySections) {
      signals.push(`Section [${sec.name}] entropy ${sec.entropy.toFixed(2)} > 7.5 — packed`)
    }
  }

  if (entropy > 7.2) {
    signals.push(`Overall entropy ${entropy.toFixed(2)} > 7.2 — packed/encrypted`)
  }

  if (stat.size >= 15 * 1024 * 1024 && stat.size <= 35 * 1024 * 1024) {
    signals.push(`File size ${(stat.size / 1024 / 1024).toFixed(1)} MB — matches masquerading loader range`)
  }

  return { isMasquerading: signals.length >= 2, signals }
}

// ═══════════════════════════════════════════════════
// DIGITAL SIGNATURE CHECK
// ═══════════════════════════════════════════════════

export function checkDigitalSignature(filepath: string): boolean {
  const cached = ctx.sigCache.get(filepath)
  if (cached !== undefined) return cached
  try {
    const out = execSync(
      `powershell -Command "(Get-AuthenticodeSignature '${filepath.replace(/'/g, "''")}').Status"`,
      { encoding: 'utf-8', timeout: 2000 },
    )
    const valid = out.includes('Valid')
    ctx.sigCache.set(filepath, valid)
    return valid
  } catch (_e) {
    ctx.sigCache.set(filepath, false)
    return false
  }
}

// ═══════════════════════════════════════════════════
// CHEAT NAME MATCHING
// ═══════════════════════════════════════════════════

export function matchKnownCheat(name: string): string[] {
  const lower = name.toLowerCase()
  const cached = ctx.cheatNameCache.get(lower)
  if (cached !== undefined) return cached

  const matches: string[] = []
  for (const base of _PROC_BASES) {
    if (lower.includes(base)) matches.push(`process:${base}`)
  }
  for (const file of _FILE_NAMES) {
    if (lower.includes(file)) matches.push(`file:${file}`)
  }
  for (const lua of _LUA_NAMES) {
    if (lower.includes(lua)) matches.push(`lua:${lua}`)
  }
  for (const folder of _FOLDER_NAMES) {
    if (lower.includes(folder)) matches.push(`folder:${folder}`)
  }
  ctx.cheatNameCache.set(lower, matches)
  return matches
}

export function riskScoreToLevel(score: number): 'high' | 'medium' | 'low' {
  if (score > 80) return 'high'
  if (score > 50) return 'medium'
  return 'low'
}

export function getFileRiskLevel(fileName: string, matches: string[]): 'high' | 'medium' | 'low' {
  const ext = path.extname(fileName).toLowerCase()
  const highRiskExts = ['.exe', '.dll', '.sys', '.drv', '.bat', '.ps1', '.vbs', '.ahk']
  const mediumRiskExts = ['.js', '.lua', '.py', '.cs', '.asi', '.luac']

  const hasHighKeyword = matches.some(k =>
    ['dll inject', 'memory hack', 'injector', 'aimbot', 'wallhack',
     'triggerbot', 'dma', 'fpga', 'pcileech', 'fuser'].includes(k)
  )

  if ((highRiskExts.includes(ext) && hasHighKeyword) || matches.length >= 3) return 'high'
  if (highRiskExts.includes(ext) || mediumRiskExts.includes(ext) || matches.length >= 2) return 'medium'
  return 'low'
}

// ═══════════════════════════════════════════════════
// COMBO DETECTOR — Universal unsigned binary heuristic
// ═══════════════════════════════════════════════════

export function comboScoreUnsignedBinary(
  ext: string,
  sizeBytes: number,
  entropy: number,
  stringCount: number,
  filepath: string,
  sectionCount: number,
  sigValid: boolean,
): { signals: string[]; riskBonus: number } {
  if (ext !== '.exe' && ext !== '.dll') {
    return { signals: [], riskBonus: 0 }
  }

  if (sigValid) {
    return { signals: [], riskBonus: 0 }
  }

  let signalCount = 0
  const reasons: string[] = []

  const fpLow = filepath.toLowerCase()
  const inSuspiciousDir = fpLow.includes('downloads') || fpLow.includes('download') ||
    fpLow.includes('desktop') || fpLow.includes('temp') || fpLow.includes('загрузки')

  if (sizeBytes >= 5 * 1024 * 1024 && sizeBytes <= 100 * 1024 * 1024) {
    signalCount++
    reasons.push(`Strange size: ${(sizeBytes / 1024 / 1024).toFixed(1)} MB (unsigned binary of this size is unusual)`)
  }

  if (entropy > 7.0) {
    signalCount++
    reasons.push(`Entropy ${entropy.toFixed(2)} > 7.0 — packed/encrypted (VMProtect/Themida/obsufcation)`)
  }

  if (stringCount < 10) {
    signalCount++
    reasons.push(`Only ${stringCount} readable strings — fully obfuscated binary`)
  }

  if (inSuspiciousDir) {
    signalCount++
    reasons.push('Located in user directory (Downloads/Desktop/Temp)')
  }

  if (sectionCount >= 7) {
    signalCount++
    reasons.push(`${sectionCount} PE sections — typical for packed/VMProtected binaries (normal: 3–5)`)
  }

  const strongSignals = [entropy > 7.0, stringCount < 10, sectionCount >= 7].filter(Boolean).length

  if (signalCount >= 2 && strongSignals >= 1) {
    return { signals: reasons, riskBonus: 70 }
  }

  if (signalCount === 1 && inSuspiciousDir) {
    return { signals: reasons, riskBonus: 40 }
  }

  if (signalCount === 1) {
    return { signals: reasons, riskBonus: 15 }
  }

  return { signals: [], riskBonus: 0 }
}

// ═══════════════════════════════════════════════════
// HASH CHECK
// ═══════════════════════════════════════════════════

export async function checkFileHash(filePath: string): Promise<{ matched: boolean; hash: string }> {
  if (KNOWN_CHEAT_HASHES.length === 0) return { matched: false, hash: '' }
  try {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)
    for await (const chunk of stream) hash.update(chunk as Buffer)
    const hex = hash.digest('hex')
    return { matched: KNOWN_CHEAT_HASHES.includes(hex), hash: hex }
  } catch (_e) {
    return { matched: false, hash: '' }
  }
}

// ═══════════════════════════════════════════════════
// HEURISTIC FILE SCAN (core business logic)
// ═══════════════════════════════════════════════════

export function heuristicFileScan(filepath: string): HeuristicResult | null {
  try {
    const stat = fs.statSync(filepath)
    if (!stat.isFile() || stat.size > SCAN_CONFIG.MAX_FILE_SIZE || stat.size < SCAN_CONFIG.MIN_FILE_SIZE) {
      return null
    }

    const fileName = path.basename(filepath).toLowerCase()
    const ext = path.extname(filepath).toLowerCase()
    const ageDays = (Date.now() - stat.mtimeMs) / (1000 * 60 * 60 * 24)
    const suspicions: string[] = []
    let riskScore = 0

    // ── Skip files that produce zero signal (noise) ──
    // Asset files, map files, etc. have no cheat value.
    if (isSkippableExtension(filepath)) {
      return null
    }

    // 1. Extension check
    if (SUSPICIOUS_EXTENSIONS[ext]) {
      suspicions.push(`Extension ${ext}: ${SUSPICIOUS_EXTENSIONS[ext]}`)
      riskScore += 20
    }

    // ── Check safe-files database ──
    try {
      if (isFileSafe(filepath, stat.size, stat.mtimeMs)) {
        return null
      }
    } catch (_e) { /* safe-db optional */ }

    // ── Known Electron DLLs ──
    if (isKnownElectronDll(fileName)) {
      return null
    }

    // 2. Name check against categories (min length 4 chars to avoid false positives)
    const shadowRuleHits: string[] = []
    for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
      const isShadow = cat.shadow === true
      for (const nm of cat.names) {
        if (nm.length < MIN_KEYWORD_LENGTH) continue
        if (fileName.includes(nm)) {
          if (isShadow) {
            shadowRuleHits.push(`Name → [${catName}]: ${cat.description}`)
          } else {
            suspicions.push(`Name → [${catName}]: ${cat.description}`)
            riskScore += 40
          }
          break
        }
      }
    }

    // Masquerading as system file
    const system32Path = path.join(_WR, 'System32').toLowerCase()
    const syswow64Path = path.join(_WR, 'SysWOW64').toLowerCase()
    const filepathLower = filepath.toLowerCase()
    if (SYSTEM_PROC_NAMES.has(fileName)) {
      const isInSystemDir = filepathLower.startsWith(system32Path) || filepathLower.startsWith(syswow64Path)
      if (!isInSystemDir && !isTrustedPath(filepath)) {
        suspicions.push(`🎭 Masquerading as system process: ${fileName} (expected in System32, found in unexpected location)`)
        riskScore += 50
      }
    }

    // 3. Age check
    if (ageDays < SCAN_CONFIG.SUSPICIOUS_AGE_DAYS) {
      suspicions.push(`Recently created (${Math.round(ageDays)} days ago)`)
      riskScore += 15
    }

    // ── FAST PATH: skip expensive binary analysis for trusted system paths ──
    if (isTrustedPath(filepath) && riskScore === 0) {
      return null
    }

    // Whitelist check — reduce score for remaining trusted-path files with signals
    if (isTrustedPath(filepath)) {
      riskScore = Math.max(riskScore - 30, 0)
    }

    // 4. Binary analysis
    const binaryExts = new Set(['.exe', '.dll', '.asi', '.sys', '.drv'])
    const textExts = new Set(['.js', '.lua', '.cs', '.bat', '.ps1', '.vbs', '.ahk', '.cfg', '.ini', '.json', '.xml'])

    // Content scan for text-based files (JS loaders, Lua, scripts, configs)
    if (textExts.has(ext) && stat.size < 512 * 1024) {
      try {
        const content = fs.readFileSync(filepath, 'utf-8').toLowerCase()
        let contentMatches = 0
        for (const keyword of ALL_CHEAT_KEYWORDS) {
          // Skip short, generic keywords (< 4 chars) that falsely match everywhere
          if (keyword.length < MIN_KEYWORD_LENGTH) continue
          if (content.includes(keyword.toLowerCase())) {
            suspicions.push(`content:${keyword}`)
            contentMatches++
            riskScore += 25
            if (contentMatches >= 5) break
          }
        }
        for (const pattern of SUSPICIOUS_PATTERNS) {
          if (pattern.test(content)) {
            suspicions.push(`content-pattern:${pattern.source}`)
            riskScore += 20
          }
        }
      } catch (_e) { /* binary or unreadable */ }
    }

    // Archive content scan (.zip/.rar/.7z)
    if (ARCHIVE_EXTS.has(ext) && stat.size < 100 * 1024 * 1024) {
      try {
        const archiveMatches = scanArchiveContents(filepath)
        for (const m of archiveMatches) {
          suspicions.push(m)
          riskScore += 30
        }
      } catch (_e) { /* archive scan optional */ }
    }

    if (binaryExts.has(ext) && stat.size >= 4096 && stat.size < 50 * 1024 * 1024) {
      const fd = fs.openSync(filepath, 'r')
      const sampleSize = Math.min(65536, stat.size)
      const sample = Buffer.alloc(sampleSize)
      fs.readSync(fd, sample, 0, sampleSize, 0)
      fs.closeSync(fd)

      const entropy = calculateEntropy(sample)
      if (entropy > SCAN_CONFIG.ENTROPY_THRESHOLD) {
        suspicions.push(`High entropy (${entropy.toFixed(2)}) — possibly packed/encrypted`)
        riskScore += 30
      }

      const strings = scanStrings(filepath)
      const stringsLower = strings.map(s => s.toLowerCase())

      const yaraMatches = evaluateYara(sample, stringsLower)
      for (const yMatch of yaraMatches) {
        suspicions.push(`YARA [${yMatch.ruleName}]: ${yMatch.description}`)
        riskScore += yMatch.risk === 'CRITICAL' ? 60 : yMatch.risk === 'HIGH' ? 40 : 20
      }

      const peCacheKey = `${filepath}|${stat.mtimeMs}`
      let peInfo: PeAnalysisResult | null = null
      let secEntropy: SectionEntropy[] = []

      const cachedPe = ctx.peHeaderCache.get(peCacheKey)
      if (cachedPe) {
        peInfo = cachedPe.peInfo
        secEntropy = cachedPe.secEntropy
      } else {
        peInfo = (ext === '.exe' || ext === '.dll' || ext === '.sys') ? analyzePeHeaders(filepath) : null
        try {
          secEntropy = analyzeSectionEntropy(filepath)
        } catch (_e) { /* skip */ }
        ctx.peHeaderCache.set(peCacheKey, { peInfo, secEntropy, mtime: stat.mtimeMs, filepath })
        if (ctx.peHeaderCache.size > ctx.PE_CACHE_MAX) {
          const firstKey = ctx.peHeaderCache.keys().next().value
          if (firstKey) ctx.peHeaderCache.delete(firstKey)
        }
      }

      const sigValid = (ext === '.exe' || ext === '.dll' || ext === '.sys') ? checkDigitalSignature(filepath) : false

      // ── UNIVERSAL COMBO DETECTOR ──
      const comboResult = comboScoreUnsignedBinary(
        ext, stat.size, entropy, strings.length, filepath,
        peInfo?.sectionCount ?? 0, sigValid,
      )
      if (comboResult.riskBonus > 0) {
        for (const signal of comboResult.signals) {
          suspicions.push(`🧬 COMBO: ${signal}`)
        }
        const signalCount = comboResult.signals.length
        suspicions.push(`🧬 Combo-detector: ${signalCount} signals matched → +${comboResult.riskBonus} risk (ANY unsigned binary with these traits is suspicious)`)
        riskScore += comboResult.riskBonus
      }

      // ── PE-specific analysis ──
      if (ext === '.exe' || ext === '.dll' || ext === '.sys') {
        if (peInfo && peInfo.isValidPe && peInfo.isSuspicious) {
          if (peInfo.suspiciousSections.length > 0) {
            suspicions.push(`PE: Unusual sections: ${peInfo.suspiciousSections.join(', ')}`)
            riskScore += 25
          }
          if (peInfo.entryPointInSuspiciousSection) {
            suspicions.push('PE: Entry point in unusual section')
            riskScore += 20
          }
          if (peInfo.relocsStripped) {
            suspicions.push('PE: Relocations stripped (suggests packed/ASLR disabled)')
            riskScore += 15
          }
        }

        if (secEntropy.length > 0) {
          const suspiciousSections = secEntropy.filter(s => s.isSuspicious)
          for (const sec of suspiciousSections) {
            suspicions.push(`📊 Section [${sec.name}]: ${sec.reason}`)
            riskScore += 30
          }
          const rsrcHigh = secEntropy.find(s => s.name === '.rsrc' && s.entropy > 7.5)
          if (rsrcHigh) {
            suspicions.push(`🚩 .rsrc entropy ${rsrcHigh.entropy.toFixed(2)} > 7.5 — shellcode/config likely hidden in resources`)
            riskScore += 40
          }
        }

        const apiHashRes = analyzeApiHashingStatic(filepath)
        if (apiHashRes && apiHashRes.detected) {
          suspicions.push(`🔐 API Hashing detected (confidence: ${apiHashRes.confidence}%)`)
          for (const p of apiHashRes.patterns.slice(0, 3)) {
            suspicions.push(`  → ${p}`)
          }
          riskScore += Math.min(apiHashRes.confidence * 0.5, 45)
        }

        // Masquerading executable check
        const masqResult = checkMasqueradingExecutable(fileName, filepath, stat, peInfo, secEntropy, entropy, sigValid)
        if (masqResult.isMasquerading) {
          for (const signal of masqResult.signals) {
            suspicions.push(`🎭 ${signal}`)
            riskScore += 25
          }
        }

      }

      // ── Signature analysis (applies to all binary files) ──
      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        const isShadow = cat.shadow === true
        const found: string[] = []
        for (const sigBuf of cat.strings) {
          const sigStr = sigBuf.toString().toLowerCase()
          if (stringsLower.some(s => s.includes(sigStr))) {
            found.push(sigStr)
          }
        }
        if (found.length > 0) {
          if (isShadow) {
            shadowRuleHits.push(`Signatures [${catName}]: ${found.slice(0, 3).join(', ')}`)
          } else {
            suspicions.push(`Signatures [${catName}]: ${found.slice(0, 3).join(', ')}`)
            riskScore += 50
          }
        }
      }

      // ── Hash check against known cheat database ──
      if (KNOWN_CHEAT_HASHES.length > 0 && riskScore > 30) {
        try {
          const h = crypto.createHash('sha256')
          const fd2 = fs.openSync(filepath, 'r')
          const hashBuf = Buffer.alloc(Math.min(stat.size, 50 * 1024 * 1024))
          fs.readSync(fd2, hashBuf, 0, hashBuf.length, 0)
          fs.closeSync(fd2)
          h.update(hashBuf)
          const hex = h.digest('hex')
          if (KNOWN_CHEAT_HASHES.includes(hex)) {
            suspicions.push(`Hash match: known cheat file (SHA256: ${hex.slice(0, 16)}...)`)
            riskScore += 60
          }
        } catch (_e) { /* skip */ }
      }

      if (sigValid) {
        riskScore -= 10
      } else {
        suspicions.push('No digital signature')
        riskScore += 20
      }
    }

    // 5. Protected path check
    for (const protectedPath of PROTECTED_PATHS) {
      if (filepath.toLowerCase().includes(protectedPath.toLowerCase())) {
        suspicions.push(`File in protected folder: ${protectedPath}`)
        riskScore += 25
        break
      }
    }

    // Auto-YARA check
    if (binaryExts.has(ext) && stat.size < 50 * 1024 * 1024) {
      try {
        const auto = checkAutoRules(filepath)
        if (auto.matched) {
          suspicions.push(`AutoYara [${auto.rules.length} правил]: score ${auto.score.toFixed(0)}`)
          riskScore += auto.score * 0.6
        }
      } catch (_e) { /* skip */ }
    }

    // Auto-YARA: learn from high-risk files
    if (riskScore > 70 && binaryExts.has(ext)) {
      try {
        learnFromFile(filepath, riskScore)
      } catch (_e) { /* skip */ }
    }

    if (riskScore === 0 && shadowRuleHits.length === 0) return null

    return { riskScore, suspicions, shadowRuleHits: shadowRuleHits.length > 0 ? shadowRuleHits : undefined }
  } catch (_e) {
    return null
  }
}

// ═══════════════════════════════════════════════════
// ARCHIVE CONTENT SCANNING
// ═══════════════════════════════════════════════════

const ARCHIVE_EXTS = new Set(['.zip', '.rar', '.7z'])

export function scanArchiveContents(filepath: string): string[] {
  const matches: string[] = []
  const ext = path.extname(filepath).toLowerCase()
  if (!ARCHIVE_EXTS.has(ext)) return matches

  try {
    let output = ''
    if (ext === '.zip') {
      const shell = spawnSync('powershell', [
        '-NoProfile', '-Command',
        `[System.IO.Compression.ZipFile]::OpenRead('${filepath.replace(/'/g, "''")}').Entries | Select-Object -ExpandProperty FullName`,
      ], { encoding: 'utf-8', timeout: 10000 })
      output = shell.stdout || ''
    } else {
      const sevenZip = spawnSync('7z', ['l', '-slt', filepath], { encoding: 'utf-8', timeout: 10000 })
      output = sevenZip.stdout || ''
    }

    if (!output) return matches

    const lower = output.toLowerCase()
    const lines = lower.split(/[\r\n]+/)
    for (const line of lines) {
      const fName = path.basename(line.trim())
      if (!fName || fName.length < 3) continue
      for (const base of _PROC_BASES) {
        if (fName.includes(base)) {
          matches.push(`archive:${fName} → ${base}`)
          break
        }
      }
      for (const file of _FILE_NAMES) {
        if (fName.includes(file)) {
          matches.push(`archive:${fName} → ${file}`)
          break
        }
      }
      for (const kw of ALL_CHEAT_KEYWORDS) {
        if (kw.length >= 4 && fName.includes(kw.toLowerCase())) {
          matches.push(`archive-kw:${fName} → ${kw}`)
          break
        }
      }
      for (const pat of SUSPICIOUS_PATTERNS) {
        if (pat.test(fName)) {
          matches.push(`archive-pat:${pat.source}`)
          break
        }
      }
      if (matches.length >= 5) break
    }
  } catch (_e) { /* archive scanning optional */ }
  return matches
}
