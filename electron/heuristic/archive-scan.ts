/**
 * Predator — Archive Content Scanning
 *
 * Scans .zip/.rar/.7z archives for known cheat filenames.
 * Uses PowerShell for .zip, 7z CLI for .rar/.7z.
 *
 * Pure data transformation — no heuristic state dependency.
 * Extracted from heuristic.ts for modularity.
 */

import path from 'path'
import { spawnAsyncWithTimeout } from '../utils/exec'
import { matchKeywords, matchPatterns } from '../signature-registry'
import { PROC_BASES, FILE_NAMES } from './cheat-names'

export const ARCHIVE_EXTS = new Set(['.zip', '.rar', '.7z'])

/**
 * Scan archive contents for known cheat filenames.
 * Checks each file inside the archive against:
 *   - Known cheat process names (PROC_BASES)
 *   - Known cheat filenames (FILE_NAMES)
 *   - Keyword matching (matchKeywords)
 *   - Pattern matching (matchPatterns)
 *
 * @param filepath - Path to .zip/.rar/.7z file
 * @returns Array of human-readable match descriptions (max 5)
 */
export async function scanArchiveContents(
  filepath: string,
  signal?: AbortSignal,
): Promise<string[]> {
  const matches: string[] = []
  const ext = path.extname(filepath).toLowerCase()
  if (!ARCHIVE_EXTS.has(ext) || signal?.aborted) return matches

  try {
    let output: string | null
    if (ext === '.zip') {
      const escapedPath = filepath.replace(/'/g, "''")
      const script = "$archive = [System.IO.Compression.ZipFile]::OpenRead('"
        + escapedPath
        + "'); try { $archive.Entries | Select-Object -ExpandProperty FullName } finally { $archive.Dispose() }"
      output = await spawnAsyncWithTimeout(
        'powershell',
        ['-NoProfile', '-Command', script],
        { timeout: 10000, signal },
      )
    } else {
      output = await spawnAsyncWithTimeout(
        '7z',
        ['l', '-slt', filepath],
        { timeout: 10000, signal },
      )
    }

    if (!output || signal?.aborted) return matches

    const lower = output.toLowerCase()
    const lines = lower.split(/[\r\n]+/)
    for (const line of lines) {
      if (signal?.aborted) return matches
      const trimmedLine = line.trim()
      const archiveEntry = trimmedLine.startsWith('path = ')
        ? trimmedLine.slice('path = '.length).trim()
        : trimmedLine
      const fName = path.basename(archiveEntry)
      if (!fName || fName.length < 3) continue
      for (const base of PROC_BASES) {
        if (fName.includes(base)) {
          matches.push(`archive:${fName} → ${base}`)
          break
        }
      }
      for (const file of FILE_NAMES) {
        if (fName.includes(file)) {
          matches.push(`archive:${fName} → ${file}`)
          break
        }
      }
      for (const kw of matchKeywords(fName)) {
        matches.push(`archive-kw:${fName} → ${kw}`)
        break
      }
      for (const pat of matchPatterns(fName)) {
        matches.push(`archive-pat:${pat}`)
        break
      }
      if (matches.length >= 5) break
    }
  } catch (err) {
    if (!signal?.aborted) console.warn('[archive-scan] failed:', (err as Error).message)
  }
  return matches
}
