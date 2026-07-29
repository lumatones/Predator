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
import { spawnSync } from 'child_process'
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
  } catch (_e) { /* archive scanning optional */ }
  return matches
}
