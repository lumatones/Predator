/**
 * Predator — Heuristic Analysis Engine
 *
 * The core scoring logic that decides whether a file or process is suspicious.
 *
 * v3: Decomposed into heuristic/* modules. This file is the public barrel —
 * it keeps heuristicFileScan() as an orchestrator and re-exports everything else.
 *
 * Modules:
 *   heuristic/constants.ts           — SUSPICIOUS_EXTENSIONS, SCAN_CONFIG, PROTECTED_PATHS, etc.
 *   heuristic/name-matcher.ts        — matchKnownCheat, riskScoreToLevel, getFileRiskLevel
 *   heuristic/combo-detector.ts      — comboScoreUnsignedBinary
 *   heuristic/signature-batch.ts     — batchCheckSignatures, checkDigitalSignature
 *   heuristic/masquerading.ts        — checkMasqueradingExecutable
 *   heuristic/archive-scan.ts        — scanArchiveContents, ARCHIVE_EXTS
 *   heuristic/cheat-names.ts         — pre-computed name arrays for matching
 *   heuristic/content-scan.ts        — scanTextContent, scanArchiveContent
 *   heuristic/binary-analysis.ts     — analyzeBinary (entropy, PE, YARA, signatures, hash)
 */

import crypto from 'crypto'
import fs from 'fs'
import path from 'path'

import { getKnownCheatHashes } from './cheats-db'
import { isTrustedPath } from './cheat-rules'

import {
  checkAutoRules,
  learnFromFile,
} from './auto-yara'

import type { HeuristicResult } from './types'
import { _WR } from './types'
import { isFileSafe } from './safe-files-db'
import { scanTextContent, scanArchiveContent } from './heuristic/content-scan'
import { analyzeBinary } from './heuristic/binary-analysis'

// ═══════════════════════════════════════════════════
// RE-EXPORTS (from sub-modules)
// ═══════════════════════════════════════════════════

// Constants (pure data)
export { SUSPICIOUS_EXTENSIONS, KNOWN_ELECTRON_DLLS, SKIPPABLE_EXTENSIONS, SCAN_CONFIG, PROTECTED_PATHS, SYSTEM_PROC_NAMES } from './heuristic/constants'
import { SUSPICIOUS_EXTENSIONS, KNOWN_ELECTRON_DLLS, SKIPPABLE_EXTENSIONS, SCAN_CONFIG, PROTECTED_PATHS, SYSTEM_PROC_NAMES } from './heuristic/constants'

// Signature registry (pure data)
export { SUSPICIOUS_CATEGORIES, ALL_CHEAT_KEYWORDS, SUSPICIOUS_PATTERNS, MIN_KEYWORD_LENGTH, matchKeywords, matchPatterns } from './signature-registry'
import { SUSPICIOUS_CATEGORIES, MIN_KEYWORD_LENGTH } from './signature-registry'

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
  const hashes = getKnownCheatHashes()
  if (hashes.length === 0) return { matched: false, hash: '' }
  try {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)
    for await (const chunk of stream) hash.update(chunk as Buffer)
    const hex = hash.digest('hex')
    return { matched: hashes.includes(hex), hash: hex }
  } catch (_e) {
    return { matched: false, hash: '' }
  }
}

// ═══════════════════════════════════════════════════
// HEURISTIC FILE SCAN (core business logic)
// ═══════════════════════════════════════════════════

const BINARY_EXTENSIONS = new Set(['.exe', '.dll', '.asi', '.sys', '.drv'])

export async function heuristicFileScan(
  filepath: string,
  signal?: AbortSignal,
): Promise<HeuristicResult | null> {
  try {
    const stat = await fs.promises.stat(filepath)
    if (signal?.aborted) return null
    if (!stat.isFile() || stat.size > SCAN_CONFIG.MAX_FILE_SIZE || stat.size < SCAN_CONFIG.MIN_FILE_SIZE) {
      return null
    }

    const fileName = path.basename(filepath).toLowerCase()
    const ext = path.extname(filepath).toLowerCase()
    const ageDays = (Date.now() - stat.mtimeMs) / (1000 * 60 * 60 * 24)
    const suspicions: string[] = []
    let riskScore = 0

    // ── Skip files that produce zero signal (noise) ──
    if (isSkippableExtension(filepath)) return null

    // 1. Extension check
    if (SUSPICIOUS_EXTENSIONS[ext]) {
      suspicions.push(`Extension ${ext}: ${SUSPICIOUS_EXTENSIONS[ext]}`)
      riskScore += 20
    }

    // ── Check safe-files database ──
    try {
      if (isFileSafe(filepath, stat.size, stat.mtimeMs)) return null
    } catch (_e) { /* safe-db optional */ }

    // ── Known Electron DLLs ──
    if (isKnownElectronDll(fileName)) return null

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

    // ── FAST PATH: skip expensive analysis for trusted system paths ──
    if (isTrustedPath(filepath) && riskScore === 0) return null
    if (isTrustedPath(filepath)) riskScore = Math.max(riskScore - 30, 0)

    // 4. Content scan (text files + archives)
    const textResult = await scanTextContent(filepath, ext, stat.size, signal)
    suspicions.push(...textResult.suspicions)
    riskScore += textResult.riskScore

    const archiveResult = await scanArchiveContent(filepath, ext, stat.size, signal)
    suspicions.push(...archiveResult.suspicions)
    riskScore += archiveResult.riskScore
    if (signal?.aborted) return null

    // 5. Binary analysis (deep scan for .exe/.dll/.asi/.sys/.drv)
    let fileHasValidSignature: boolean | undefined
    if (BINARY_EXTENSIONS.has(ext) && stat.size >= 4096 && stat.size < 50 * 1024 * 1024) {
      const binResult = await analyzeBinary(filepath, fileName, ext, stat, riskScore, signal)
      suspicions.push(...binResult.suspicions)
      shadowRuleHits.push(...binResult.shadowRuleHits)
      riskScore += binResult.riskScore
      fileHasValidSignature = binResult.hasValidSignature
    }

    // 6. Protected path check
    for (const protectedPath of PROTECTED_PATHS) {
      if (filepath.toLowerCase().includes(protectedPath.toLowerCase())) {
        suspicions.push(`File in protected folder: ${protectedPath}`)
        riskScore += 25
        break
      }
    }

    // 7. Auto-YARA check + learning
    if (BINARY_EXTENSIONS.has(ext) && stat.size < 50 * 1024 * 1024) {
      try {
        const auto = checkAutoRules(filepath)
        if (auto.matched) {
          suspicions.push(`AutoYara [${auto.rules.length} правил]: score ${auto.score.toFixed(0)}`)
          riskScore += auto.score * 0.6
        }
      } catch (err) { console.warn('[heuristic] auto-yara check failed:', (err as Error).message) }
    }
    if (riskScore > 70 && BINARY_EXTENSIONS.has(ext)) {
      try { learnFromFile(filepath, riskScore) }
      catch (err) { console.warn('[heuristic] learn-from-file failed:', (err as Error).message) }
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
