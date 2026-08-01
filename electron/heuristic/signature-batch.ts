/**
 * Predator — Batch Signature Check
 *
 * Digital signature verification via PowerShell.
 * Batch requests avoid starting one PowerShell process per binary.
 */

import path from 'path'
import { execPowerShellAsync } from '../utils/exec'
import { ctx } from '../types'

export const BINARY_SIG_EXTS = new Set(['.exe', '.dll', '.sys', '.drv'])
const AUTHENTICODE_FAILURE_STATUSES = new Set([
  'NotSigned',
  'UnknownError',
  'NotTrusted',
  'HashMismatch',
  'NotSupported',
  'Incompatible',
  'NotCataloged',
])

function markFailed(results: Map<string, boolean>, batch: string[]): void {
  for (const filepath of batch) results.set(filepath, false)
}

/**
 * Batch-check digital signatures for multiple files in one PowerShell call.
 * Failed or incomplete responses are returned as false but are not cached,
 * allowing a later single-file check to retry them.
 */
export async function batchCheckSignatures(
  filepaths: string[],
  batchSize: number = 500,
  signal?: AbortSignal,
): Promise<Map<string, boolean>> {
  const results = new Map<string, boolean>()
  if (!Number.isSafeInteger(batchSize) || batchSize <= 0) return results

  const toCheck: string[] = []
  for (const filepath of filepaths) {
    if (!filepath || typeof filepath !== 'string') continue
    if (!BINARY_SIG_EXTS.has(path.extname(filepath).toLowerCase())) continue

    const cached = ctx.sigCache.get(filepath)
    if (cached !== undefined) {
      results.set(filepath, cached)
    } else {
      toCheck.push(filepath)
    }
  }

  for (let i = 0; i < toCheck.length; i += batchSize) {
    if (signal?.aborted) throw new Error('Digital signature check aborted')
    const batch = toCheck.slice(i, i + batchSize)
    const psPaths = batch.map(filepath => `'${filepath.replace(/'/g, "''")}'`).join(',')
    const psScript = [
      '$ErrorActionPreference = "SilentlyContinue"',
      `$paths = @(${psPaths})`,
      '$results = @{}',
      'foreach ($p in $paths) {',
      '  try {',
      '    $sig = Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop',
      '    switch ($sig.Status.ToString()) {',
      '      "Valid" { $results[$p] = $true; break }',
      '      "NotSigned" { $results[$p] = $false; break }',
      '      "UnknownError" { $results[$p] = $false; break }',
      '      "NotTrusted" { $results[$p] = $false; break }',
      '      "HashMismatch" { $results[$p] = $false; break }',
      '      "NotSupported" { $results[$p] = $false; break }',
      '      "Incompatible" { $results[$p] = $false; break }',
      '      "NotCataloged" { $results[$p] = $false; break }',
      '      default { $results[$p] = $null; break }',
      '    }',
      '  } catch {',
      '    $results[$p] = $null',
      '  }',
      '}',
      '$results | ConvertTo-Json -Compress',
    ].join('\n')

    const out = await execPowerShellAsync(psScript, {
      timeout: Math.max(30000, batch.length * 100),
      signal,
    })
    if (signal?.aborted) throw new Error('Digital signature check aborted')

    if (!out || out.trim().length <= 2) {
      markFailed(results, batch)
      continue
    }

    try {
      const parsed: unknown = JSON.parse(out)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        markFailed(results, batch)
        continue
      }

      const parsedResults = parsed as Record<string, unknown>
      for (const filepath of batch) {
        const value = parsedResults[filepath]
        if (typeof value !== 'boolean') {
          // null/unknown status means the command did not produce a
          // trustworthy verdict; return false for this scan but do not cache it.
          results.set(filepath, false)
          continue
        }
        ctx.sigCache.set(filepath, value)
        results.set(filepath, value)
      }
    } catch {
      markFailed(results, batch)
    }
  }

  return results
}

/**
 * Check a single file, first using ctx.sigCache and then an async PowerShell
 * fallback. Timeout, missing PowerShell, and malformed output are not cached.
 */
export async function checkDigitalSignature(
  filepath: string,
  signal?: AbortSignal,
): Promise<boolean> {
  const cached = ctx.sigCache.get(filepath)
  if (cached !== undefined) return cached
  if (signal?.aborted) throw new Error('Digital signature check aborted')

  const escapedPath = filepath.replace(/'/g, "''")
  const out = await execPowerShellAsync(
    `(Get-AuthenticodeSignature -FilePath '${escapedPath}').Status`,
    { timeout: 2000, signal },
  )
  if (signal?.aborted) throw new Error('Digital signature check aborted')
  if (!out) return false

  const status = out.trim()
  if (status === 'Valid') {
    ctx.sigCache.set(filepath, true)
    return true
  }
  if (AUTHENTICODE_FAILURE_STATUSES.has(status)) {
    ctx.sigCache.set(filepath, false)
    return false
  }

  // Unexpected output is not a trustworthy verdict and must be retried.
  return false
}
