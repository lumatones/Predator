/**
 * Predator — Batch Signature Check
 *
 * Digital signature verification via PowerShell.
 *
 * BEFORE: checkDigitalSignature() spawned PowerShell per file (2s each).
 * 500 .exe/.dll files = 1000 seconds of blocking the Event Loop.
 *
 * AFTER: batchCheckSignatures() sends ALL paths in ONE PowerShell call.
 * PowerShell iterates internally (fast), returns JSON. Total: ~3-5 seconds.
 *
 * Results populate ctx.sigCache — subsequent checkDigitalSignature() calls
 * are instant cache hits. No per-file PowerShell overhead.
 *
 * Extracted from heuristic.ts for modularity.
 */

import path from 'path'
import { execPowerShell, execWithTimeout } from '../utils/exec'
import { ctx } from '../types'

export const BINARY_SIG_EXTS = new Set(['.exe', '.dll', '.sys', '.drv'])

/**
 * Batch-check digital signatures for multiple files in ONE PowerShell invocation.
 * Populates ctx.sigCache and returns results as Map.
 *
 * @param filepaths - Array of file paths to check (only .exe/.dll/.sys/.drv are checked)
 * @param batchSize - Max files per PowerShell call (default 500, prevents command-line overflow)
 */
export function batchCheckSignatures(
  filepaths: string[],
  batchSize: number = 500,
): Map<string, boolean> {
  const results = new Map<string, boolean>()

  // Filter to binary extensions only + skip already-cached files
  const toCheck: string[] = []
  for (const fp of filepaths) {
    if (!fp || typeof fp !== 'string') continue
    const ext = path.extname(fp).toLowerCase()
    if (!BINARY_SIG_EXTS.has(ext)) continue
    // Skip if already in cache
    const cached = ctx.sigCache.get(fp)
    if (cached !== undefined) {
      results.set(fp, cached)
      continue
    }
    toCheck.push(fp)
  }

  if (toCheck.length === 0) return results

  // Process in batches to avoid PowerShell command-line length limits
  for (let i = 0; i < toCheck.length; i += batchSize) {
    const batch = toCheck.slice(i, i + batchSize)

    // Build PowerShell array of paths (escape single quotes)
    const psPaths = batch
      .map(fp => `'${fp.replace(/'/g, "''")}'`)
      .join(',')

    const psScript = [
      '$ErrorActionPreference = "SilentlyContinue"',
      `$paths = @(${psPaths})`,
      '$results = @{}',
      'foreach ($p in $paths) {',
      '  try {',
      '    $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop',
      '    $results[$p] = ($sig.Status -eq "Valid")',
      '  } catch {',
      '    $results[$p] = $false',
      '  }',
      '}',
      '$results | ConvertTo-Json -Compress',
    ].join('\n')

    try {
      const out = execPowerShell(psScript, { timeout: Math.max(30000, batch.length * 100) }) || ''.trim()

      if (out && out.length > 2) {
        try {
          const parsed: Record<string, boolean> = JSON.parse(out)
          for (const [fp, valid] of Object.entries(parsed)) {
            const isValid = Boolean(valid)
            ctx.sigCache.set(fp, isValid)
            results.set(fp, isValid)
          }
          // Mark remaining batch files that weren't in JSON as unchecked
          // (don't cache them — let checkDigitalSignature() try per-file fallback)
          for (const fp of batch) {
            if (!results.has(fp)) {
              results.set(fp, false)
            }
          }
        } catch {
          // JSON parse failed — do NOT poison cache, let per-file fallback handle it
          for (const fp of batch) {
            results.set(fp, false)
          }
        }
      } else {
        // Empty output — do NOT poison cache
        for (const fp of batch) {
          results.set(fp, false)
        }
      }
    } catch {
      // PowerShell crashed — do NOT poison cache
      for (const fp of batch) {
        results.set(fp, false)
      }
    }
  }

  return results
}

/**
 * Check digital signature for a single file.
 * First checks ctx.sigCache (populated by batchCheckSignatures).
 * Falls back to per-file PowerShell ONLY on cache miss (should be rare).
 */
export function checkDigitalSignature(filepath: string): boolean {
  const cached = ctx.sigCache.get(filepath)
  if (cached !== undefined) return cached

  // Cache miss — fall back to single-file check (rare after batch pre-warming)
  try {
    const out = execPowerShell(
      `(Get-AuthenticodeSignature '${filepath.replace(/'/g, "''")}').Status`,
      { timeout: 2000 },
    ) || ''
    const valid = out.includes('Valid')
    ctx.sigCache.set(filepath, valid)
    return valid
  } catch (_e) {
    ctx.sigCache.set(filepath, false)
    return false
  }
}
