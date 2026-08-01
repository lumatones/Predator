/**
 * Predator — Binary Analysis Engine
 *
 * Deep analysis of binary files (.exe, .dll, .asi, .sys, .drv):
 *   - Entropy calculation (detect packing/encryption)
 *   - String extraction + signature matching
 *   - YARA rule evaluation
 *   - PE header analysis (sections, entry point, relocations)
 *   - Section entropy analysis
 *   - Combo detector (multi-signal unsigned binary scoring)
 *   - API hashing detection
 *   - Masquerading executable detection
 *   - Binary signature category matching
 *   - SHA256 hash check against known cheat database
 *   - Digital signature validation
 *
 * Extracted from heuristic.ts to keep each phase focused and testable.
 */

import crypto from 'crypto'
import fs from 'fs'
import { readFilePrefix } from '../utils/file-io'

import { getKnownCheatHashes } from '../cheats-db'
import {
  evaluateYara,
  analyzePeHeaders,
  analyzeSectionEntropy,
} from '../cheat-rules'
import { analyzeApiHashingStatic } from '../api-hashing'
import type { PeAnalysisResult, SectionEntropy } from '../cheat-rules'
import { ctx } from '../types'
import { calculateEntropy } from '../analysis/entropy'
import { scanStrings } from '../analysis/strings'
import { SCAN_CONFIG } from './constants'
import { SUSPICIOUS_CATEGORIES } from '../signature-registry'
import { comboScoreUnsignedBinary } from './combo-detector'
import { checkDigitalSignature } from './signature-batch'
import { checkMasqueradingExecutable } from './masquerading'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface BinaryAnalysisResult {
  suspicions: string[]
  shadowRuleHits: string[]
  riskScore: number
  hasValidSignature: boolean | undefined
}

// ═══════════════════════════════════════════════════
// BINARY EXTENSIONS
// ═══════════════════════════════════════════════════

const PE_EXTENSIONS = new Set(['.exe', '.dll', '.sys'])

// ═══════════════════════════════════════════════════
// MAIN ANALYSIS FUNCTION
// ═══════════════════════════════════════════════════

/**
 * Run full binary analysis on a file.
 * Only called for files with binary extensions, size 4KB–50MB.
 *
 * @param filepath - Absolute path to the file
 * @param fileName - Lowercase basename
 * @param ext - Lowercase extension (e.g. '.exe')
 * @param stat - fs.Stats from statSync
 * @param riskScore - Current risk score before binary analysis (for threshold decisions)
 * @returns Analysis results to merge into the parent scan
 */
export async function analyzeBinary(
  filepath: string,
  fileName: string,
  ext: string,
  stat: fs.Stats,
  riskScore: number,
  signal?: AbortSignal,
): Promise<BinaryAnalysisResult> {
  const result: BinaryAnalysisResult = {
    suspicions: [],
    shadowRuleHits: [],
    riskScore: 0,
    hasValidSignature: undefined,
  }

  // ── Read sample bytes ──
  const sampleSize = Math.min(65536, stat.size)
  const sample = await readFilePrefix(filepath, sampleSize, signal)

  // ── 1. Entropy ──
  const entropy = calculateEntropy(sample)
  if (entropy > SCAN_CONFIG.ENTROPY_THRESHOLD) {
    result.suspicions.push(`High entropy (${entropy.toFixed(2)}) — possibly packed/encrypted`)
    result.riskScore += 30
  }

  // ── 2. Strings + YARA ──
  const strings = await scanStrings(filepath, 512 * 1024, signal)
  if (signal?.aborted) return result
  const stringsLower = strings.map(s => s.toLowerCase())

  const yaraMatches = evaluateYara(sample, stringsLower)
  for (const yMatch of yaraMatches) {
    result.suspicions.push(`YARA [${yMatch.ruleName}]: ${yMatch.description}`)
    result.riskScore += yMatch.risk === 'CRITICAL' ? 60 : yMatch.risk === 'HIGH' ? 40 : 20
  }

  // ── 3. PE Header Analysis (cached) ──
  const isPe = PE_EXTENSIONS.has(ext)
  const peCacheKey = `${filepath}|${stat.mtimeMs}`
  let peInfo: PeAnalysisResult | null = null
  let secEntropy: SectionEntropy[] = []

  const cachedPe = ctx.peHeaderCache.get(peCacheKey)
  if (cachedPe) {
    peInfo = cachedPe.peInfo
    secEntropy = cachedPe.secEntropy
  } else {
    peInfo = isPe ? await analyzePeHeaders(filepath, signal) : null
    if (signal?.aborted) return result
    try {
      secEntropy = await analyzeSectionEntropy(filepath, signal)
    } catch (err) {
      if (signal?.aborted) throw err
      console.warn('[binary-analysis] section entropy failed:', (err as Error).message)
    }
    if (signal?.aborted) return result
    ctx.peHeaderCache.set(peCacheKey, { peInfo, secEntropy, mtime: stat.mtimeMs, filepath })
    if (ctx.peHeaderCache.size > ctx.PE_CACHE_MAX) {
      const firstKey = ctx.peHeaderCache.keys().next().value
      if (firstKey) ctx.peHeaderCache.delete(firstKey)
    }
  }

  // ── 4. Digital Signature ──
  const sigValid = isPe ? await checkDigitalSignature(filepath, signal) : false
  if (signal?.aborted) return result
  result.hasValidSignature = sigValid

  // ── 5. Combo Detector (multi-signal unsigned binary scoring) ──
  const comboResult = comboScoreUnsignedBinary(
    ext, stat.size, entropy, strings.length, filepath,
    peInfo?.sectionCount ?? 0, sigValid,
  )
  if (comboResult.riskBonus > 0) {
    for (const signal of comboResult.signals) {
      result.suspicions.push(`🧬 COMBO: ${signal}`)
    }
    const signalCount = comboResult.signals.length
    result.suspicions.push(
      `🧬 Combo-detector: ${signalCount} signals matched → +${comboResult.riskBonus} risk (ANY unsigned binary with these traits is suspicious)`,
    )
    result.riskScore += comboResult.riskBonus
  }

  // ── 6. PE-specific Analysis ──
  if (isPe) {
    await analyzePeSpecific(result, peInfo, secEntropy, filepath, fileName, stat, entropy, sigValid, signal)
    if (signal?.aborted) return result
  }

  // ── 7. Binary Signature Matching ──
  matchBinarySignatures(result, stringsLower)

  // ── 8. Hash Check (SHA256 vs known cheat DB) ──
  if (riskScore + result.riskScore > 30) {
    await checkKnownCheatHash(result, filepath, stat.size, signal)
    if (signal?.aborted) return result
  }

  // ── 9. Digital Signature Verdict ──
  if (sigValid) {
    result.riskScore -= 10
  } else {
    result.suspicions.push('No digital signature')
    result.riskScore += 20
  }

  return result
}

// ═══════════════════════════════════════════════════
// PE-SPECIFIC ANALYSIS
// ═══════════════════════════════════════════════════

async function analyzePeSpecific(
  result: BinaryAnalysisResult,
  peInfo: PeAnalysisResult | null,
  secEntropy: SectionEntropy[],
  filepath: string,
  fileName: string,
  stat: fs.Stats,
  entropy: number,
  sigValid: boolean,
  signal?: AbortSignal,
): Promise<void> {
  // PE header anomalies
  if (peInfo && peInfo.isValidPe && peInfo.isSuspicious) {
    if (peInfo.suspiciousSections.length > 0) {
      result.suspicions.push(`PE: Unusual sections: ${peInfo.suspiciousSections.join(', ')}`)
      result.riskScore += 25
    }
    if (peInfo.entryPointInSuspiciousSection) {
      result.suspicions.push('PE: Entry point in unusual section')
      result.riskScore += 20
    }
    if (peInfo.relocsStripped) {
      result.suspicions.push('PE: Relocations stripped (suggests packed/ASLR disabled)')
      result.riskScore += 15
    }
  }

  // Section entropy anomalies
  if (secEntropy.length > 0) {
    const suspiciousSections = secEntropy.filter(s => s.isSuspicious)
    for (const sec of suspiciousSections) {
      result.suspicions.push(`📊 Section [${sec.name}]: ${sec.reason}`)
      result.riskScore += 30
    }
    const rsrcHigh = secEntropy.find(s => s.name === '.rsrc' && s.entropy > 7.5)
    if (rsrcHigh) {
      result.suspicions.push(
        `🚩 .rsrc entropy ${rsrcHigh.entropy.toFixed(2)} > 7.5 — shellcode/config likely hidden in resources`,
      )
      result.riskScore += 40
    }
  }

  // API hashing detection
  const apiHashRes = await analyzeApiHashingStatic(filepath, signal)
  if (signal?.aborted) return
  if (apiHashRes.detected) {
    result.suspicions.push(`🔐 API Hashing detected (confidence: ${apiHashRes.confidence}%)`)
    for (const p of apiHashRes.patterns.slice(0, 3)) {
      result.suspicions.push(`  → ${p}`)
    }
    result.riskScore += Math.min(apiHashRes.confidence * 0.5, 45)
  }

  // Masquerading executable check
  const masqResult = checkMasqueradingExecutable(fileName, filepath, stat, peInfo, secEntropy, entropy, sigValid)
  if (masqResult.isMasquerading) {
    for (const signal of masqResult.signals) {
      result.suspicions.push(`🎭 ${signal}`)
      result.riskScore += 25
    }
  }
}

// ═══════════════════════════════════════════════════
// BINARY SIGNATURE MATCHING
// ═══════════════════════════════════════════════════

function matchBinarySignatures(
  result: BinaryAnalysisResult,
  stringsLower: string[],
): void {
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
        result.shadowRuleHits.push(`Signatures [${catName}]: ${found.slice(0, 3).join(', ')}`)
      } else {
        result.suspicions.push(`Signatures [${catName}]: ${found.slice(0, 3).join(', ')}`)
        result.riskScore += 50
      }
    }
  }
}

// ═══════════════════════════════════════════════════
// KNOWN CHEAT HASH CHECK
// ═══════════════════════════════════════════════════

async function checkKnownCheatHash(
  result: BinaryAnalysisResult,
  filepath: string,
  fileSize: number,
  signal?: AbortSignal,
): Promise<void> {
  const hashes = getKnownCheatHashes()
  if (hashes.length === 0) return

  try {
    const h = crypto.createHash('sha256')
    const hashBuf = await readFilePrefix(filepath, Math.min(fileSize, 50 * 1024 * 1024), signal)
    h.update(hashBuf)
    const hex = h.digest('hex')
    if (hashes.includes(hex)) {
      result.suspicions.push(`Hash match: known cheat file (SHA256: ${hex.slice(0, 16)}...)`)
      result.riskScore += 60
    }
  } catch (err) {
    console.warn('[binary-analysis] hash compute failed:', (err as Error).message)
  }
}
