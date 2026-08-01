/**
 * Predator — Content Scanner (text files + archives)
 *
 * Scans text-based files (.js, .lua, .cs, .bat, .ps1, etc.) for cheat keywords
 * and patterns. Also scans archive contents (.zip, .rar, .7z) for suspicious files.
 *
 * Extracted from heuristic.ts to keep each phase focused and testable.
 */

import { readFilePrefix } from '../utils/file-io'
import { matchKeywords, matchPatterns } from '../signature-registry'
import { scanArchiveContents, ARCHIVE_EXTS } from './archive-scan'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface ContentScanResult {
  suspicions: string[]
  riskScore: number
}

// ═══════════════════════════════════════════════════
// TEXT FILE SCANNING
// ═══════════════════════════════════════════════════

/** Extensions treated as text files for keyword/pattern scanning */
const TEXT_EXTENSIONS = new Set([
  '.js', '.lua', '.cs', '.bat', '.ps1', '.vbs', '.ahk',
  '.cfg', '.ini', '.json', '.xml',
])

const MAX_TEXT_FILE_SIZE = 512 * 1024 // 512 KB

/**
 * Scan a text-based file for cheat keywords and patterns.
 * Returns suspicions found and accumulated risk score.
 */
export async function scanTextContent(
  filepath: string,
  ext: string,
  fileSize: number,
  signal?: AbortSignal,
): Promise<ContentScanResult> {
  const result: ContentScanResult = { suspicions: [], riskScore: 0 }

  if (!TEXT_EXTENSIONS.has(ext) || fileSize >= MAX_TEXT_FILE_SIZE || signal?.aborted) {
    return result
  }

  try {
    const content = (await readFilePrefix(filepath, Math.min(fileSize, MAX_TEXT_FILE_SIZE), signal))
      .toString('utf-8')
      .toLowerCase()
    if (signal?.aborted) return result

    // Keyword matching (high-confidence cheat indicators)
    const keywordMatches = matchKeywords(content)
    for (let i = 0; i < Math.min(keywordMatches.length, 5); i++) {
      result.suspicions.push(`content:${keywordMatches[i]}`)
      result.riskScore += 25
    }

    // Pattern matching (structural cheat patterns)
    const patternMatches = matchPatterns(content)
    for (const pattern of patternMatches) {
      result.suspicions.push(`content-pattern:${pattern}`)
      result.riskScore += 20
    }
  } catch (err) {
    if (!signal?.aborted) console.warn('[content-scan] text scan failed:', (err as Error).message)
  }

  return result
}

// ═══════════════════════════════════════════════════
// ARCHIVE SCANNING
// ═══════════════════════════════════════════════════

const MAX_ARCHIVE_SIZE = 100 * 1024 * 1024 // 100 MB

/**
 * Scan archive contents (.zip, .rar, .7z) for suspicious files.
 * Returns suspicions found and accumulated risk score.
 */
export async function scanArchiveContent(
  filepath: string,
  ext: string,
  fileSize: number,
  signal?: AbortSignal,
): Promise<ContentScanResult> {
  const result: ContentScanResult = { suspicions: [], riskScore: 0 }

  if (!ARCHIVE_EXTS.has(ext) || fileSize >= MAX_ARCHIVE_SIZE || signal?.aborted) {
    return result
  }

  try {
    const archiveMatches = await scanArchiveContents(filepath, signal)
    for (const m of archiveMatches) {
      result.suspicions.push(m)
      result.riskScore += 30
    }
  } catch (err) {
    if (!signal?.aborted) console.warn('[content-scan] archive scan failed:', (err as Error).message)
  }

  return result
}
