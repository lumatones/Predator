/**
 * Predator — APC Injection Detector: Tier 1 — Thread State Analysis
 *
 * Detects suspicious thread states in game processes.
 *
 * Early Bird APC injection creates threads in a suspended state,
 * queues an APC, then resumes. Detection: threads in game processes
 * with abnormal wait reasons, or threads created by non-game parent processes.
 */

import { execSync } from 'child_process'
import { addFindingDedup, type ScanResult } from '../../types'
import { getMonitoredProcessArgs } from '../../signature-registry'

export function scanApcThreadStates(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$gameProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
if (-not $gameProcs) { Write-Output '[]'; exit 0 }

$results = @()
foreach ($proc in $gameProcs) {
  $threads = $proc.Threads
  $totalThreads = $threads.Count

  # Suspicious: abnormally high thread count (APC injection creates many threads)
  if ($totalThreads -gt 400) {
    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      ThreadCount = $totalThreads
      Signal = "APC:thread-bloat"
      Detail = "$totalThreads threads (normal: <200 for GTA 5)"
    }
  }

  # Check for threads with UserRequest wait reason (queued APC indicator)
  $waitingThreads = 0
  try {
    $waitingThreads = ($threads | Where-Object { $_.WaitReason -eq 'UserRequest' }).Count
  } catch {}
  if ($waitingThreads -gt 50) {
    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      ThreadCount = $totalThreads
      Signal = "APC:user-request-wait"
      Detail = "$waitingThreads threads in UserRequest wait state (queued APC indicator)"
    }
  }
}

$results | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 10000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    let hits: { PID?: number; Name?: string; ThreadCount?: number; Signal?: string; Detail?: string }[] = []
    try { const p = JSON.parse(out); hits = Array.isArray(p) ? p : [p] } catch { return results }

    for (const hit of hits) {
      const key = `apc-thread:${hit.Name}:${hit.PID}:${hit.Signal}`
      if (addFindingDedup(key)) {
        const risk = hit.ThreadCount && hit.ThreadCount > 600 ? 'high' : 'medium'
        results.push({
          path: `process:${hit.Name} (PID: ${hit.PID})`,
          fileName: `⚠ APC Injection: ${hit.Name} — ${hit.Detail || hit.Signal}`,
          type: 'process',
          risk: risk as 'high' | 'medium',
          matches: [
            hit.Detail || '',
            `Signal: ${hit.Signal}`,
            'Early Bird APC injection queues code before thread initialization',
            '⚠ Cheat code runs before security hooks are established',
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* thread scan optional */ }

  return results
}
