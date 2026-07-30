/**
 * Predator — Heuristic Analysis Engine
 *
 * The core scoring logic that decides whether a file or process is suspicious.
 *
 * v2: Decomposed into heuristic/* modules. This file is the public barrel —
 * it keeps heuristicFileScan() and re-exports everything else from sub-modules.
 *
 * Modules:
 *   heuristic/constants.ts           — SUSPICIOUS_EXTENSIONS, SCAN_CONFIG, PROTECTED_PATHS, etc.
 *   heuristic/name-matcher.ts        — matchKnownCheat, riskScoreToLevel, getFileRiskLevel
 *   heuristic/combo-detector.ts      — comboScoreUnsignedBinary
 *   heuristic/signature-batch.ts     — batchCheckSignatures, checkDigitalSignature
 *   heuristic/masquerading.ts        — checkMasqueradingExecutable
 *   heuristic/archive-scan.ts        — scanArchiveContents, ARCHIVE_EXTS
 *   heuristic/cheat-names.ts         — pre-computed name arrays for matching
 */

import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

import { KNOWN_CHEAT_HASHES } from './cheats-db'

import {
  evaluateYara,
  isTrustedPath,
  analyzePeHeaders,
  analyzeSectionEntropy,
} from './cheat-rules'

import {
  checkAutoRules,
  learnFromFile,
} from './auto-yara'

import {
  analyzeApiHashingStatic,
} from './api-hashing'

import type { HeuristicResult } from './types'
import type { PeAnalysisResult, SectionEntropy } from './cheat-rules'
import { _WR, ctx } from './types'
import { isFileSafe } from './safe-files-db'
import { calculateEntropy } from './analysis/entropy'
import { scanStrings } from './analysis/strings'

// ═══════════════════════════════════════════════════
// RE-EXPORTS (from sub-modules)
// ═══════════════════════════════════════════════════

// Constants (pure data)
export { SUSPICIOUS_EXTENSIONS, KNOWN_ELECTRON_DLLS, SKIPPABLE_EXTENSIONS, SCAN_CONFIG, PROTECTED_PATHS, SYSTEM_PROC_NAMES } from './heuristic/constants'
import { SUSPICIOUS_EXTENSIONS, KNOWN_ELECTRON_DLLS, SKIPPABLE_EXTENSIONS, SCAN_CONFIG, PROTECTED_PATHS, SYSTEM_PROC_NAMES } from './heuristic/constants'

// Signature registry (pure data)
export { SUSPICIOUS_CATEGORIES, ALL_CHEAT_KEYWORDS, SUSPICIOUS_PATTERNS, MIN_KEYWORD_LENGTH, matchKeywords, matchPatterns } from './signature-registry'
import { SUSPICIOUS_CATEGORIES, MIN_KEYWORD_LENGTH, matchKeywords, matchPatterns } from './signature-registry'

// Heuristic sub-modules
export { comboScoreUnsignedBinary } from './heuristic/combo-detector'
export { batchCheckSignatures, checkDigitalSignature } from './heuristic/signature-batch'
export { checkMasqueradingExecutable } from './heuristic/masquerading'
export { scanArchiveContents, ARCHIVE_EXTS } from './heuristic/archive-scan'

// Cheat name arrays
export { PROC_BASES, FILE_NAMES, LUA_NAMES, FOLDER_NAMES } from './heuristic/cheat-names'

// Name matcher
export { matchKnownCheat, riskScoreToLevel, getFileRiskLevel, hasDoubleExtension } from './heuristic/name-matcher'

// Analysis engines
export { calculateEntropy } from './analysis/entropy'
export { scanStrings } from './analysis/strings'

// ═══════════════════════════════════════════════════
// LOCAL IMPORTS (for heuristicFileScan)
// ═══════════════════════════════════════════════════

import { comboScoreUnsignedBinary } from './heuristic/combo-detector'
import { checkDigitalSignature } from './heuristic/signature-batch'
import { checkMasqueradingExecutable } from './heuristic/masquerading'
import { scanArchiveContents, ARCHIVE_EXTS } from './heuristic/archive-scan'
import { matchKnownCheat } from './heuristic/name-matcher'

// ═══════════════════════════════════════════════════
// HELPERS (thin wrappers, kept in barrel for locality)
// ═══════════════════════════════════════════════════

/** Check if filename is a known Electron bundled DLL (never flag these) */
export function isKnownElectronDll(fileName: string): boolean {
  return KNOWN_ELECTRON_DLLS.has(fileName.toLowerCase())
}

/** Check if extension is skippable (noise/asset files) */
export function isSkippableExtension(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase()
  return SKIPPABLE_EXTENSIONS.has(ext)
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

    // 2. Name check against categories (min length 4 chars)
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

    // Whitelist check — reduce score for remaining trusted-path files
    if (isTrustedPath(filepath)) {
      riskScore = Math.max(riskScore - 30, 0)
    }

    // 4. Binary analysis
    const binaryExts = new Set(['.exe', '.dll', '.asi', '.sys', '.drv'])
    const textExts = new Set(['.js', '.lua', '.cs', '.bat', '.ps1', '.vbs', '.ahk', '.cfg', '.ini', '.json', '.xml'])

    // Content scan for text-based files
    if (textExts.has(ext) && stat.size < 512 * 1024) {
      try {
        const content = fs.readFileSync(filepath, 'utf-8').toLowerCase()
        const keywordMatches = matchKeywords(content)
        for (let i = 0; i < Math.min(keywordMatches.length, 5); i++) {
          suspicions.push(`content:${keywordMatches[i]}`)
          riskScore += 25
        }
        const patternMatches = matchPatterns(content)
        for (const pattern of patternMatches) {
          suspicions.push(`content-pattern:${pattern}`)
          riskScore += 20
        }
      } catch (err) { console.warn('[heuristic] binary/unreadable:', (err as Error).message) }
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

    let fileHasValidSignature: boolean | undefined

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
        } catch (err) { console.warn('[heuristic] section entropy failed:', (err as Error).message) }
        ctx.peHeaderCache.set(peCacheKey, { peInfo, secEntropy, mtime: stat.mtimeMs, filepath })
        if (ctx.peHeaderCache.size > ctx.PE_CACHE_MAX) {
          const firstKey = ctx.peHeaderCache.keys().next().value
          if (firstKey) ctx.peHeaderCache.delete(firstKey)
        }
      }

      const sigValid = (ext === '.exe' || ext === '.dll' || ext === '.sys') ? checkDigitalSignature(filepath) : false
      fileHasValidSignature = sigValid

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
        let fd2: number | undefined
        try {
          const h = crypto.createHash('sha256')
          fd2 = fs.openSync(filepath, 'r')
          const hashBuf = Buffer.alloc(Math.min(stat.size, 50 * 1024 * 1024))
          fs.readSync(fd2, hashBuf, 0, hashBuf.length, 0)
          h.update(hashBuf)
          const hex = h.digest('hex')
          if (KNOWN_CHEAT_HASHES.includes(hex)) {
            suspicions.push(`Hash match: known cheat file (SHA256: ${hex.slice(0, 16)}...)`)
            riskScore += 60
          }
        } catch (err) { console.warn('[heuristic] hash compute failed:', (err as Error).message) }
        finally { if (fd2 !== undefined) { try { fs.closeSync(fd2) } catch { /* best effort */ } } }
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
      } catch (err) { console.warn('[heuristic] auto-yara check failed:', (err as Error).message) }
    }

    // Auto-YARA: learn from high-risk files
    if (riskScore > 70 && binaryExts.has(ext)) {
      try {
        learnFromFile(filepath, riskScore)
      } catch (err) { console.warn('[heuristic] learn-from-file failed:', (err as Error).message) }
    }

    if (riskScore === 0 && shadowRuleHits.length === 0) return null

    return {
      riskScore,
      suspicions,
      shadowRuleHits: shadowRuleHits.length > 0 ? shadowRuleHits : undefined,
      hasValidSignature: fileHasValidSignature,
    }
  } catch (_e) {
    return null
  }
}
