/**
 * Predator — APC Injection Detector: Tier 4 — Thread Pool Abuse Detection
 *
 * Detect Windows Thread Pool abuse (Pool Party / WTH techniques).
 *
 * Modern cheats abuse the Windows Thread Pool API to inject code WITHOUT
 * calling CreateRemoteThread or NtCreateThreadEx — bypassing kernel callbacks.
 *
 * Two main attack vectors (2025-2026 research: SafeBreach, Check Point):
 *
 *   1. POOL PARTY — Attacker duplicates the process's worker factory handle,
 *      overwrites the start routine or queues malicious TP_WORK/TP_IO items
 *      directly into the target's thread pool task queue.
 *
 *   2. WAITING THREAD HIJACKING (WTH) — Attacker finds pool threads blocked
 *      in WrQueue wait state, overwrites their return address on the stack.
 *      When the pool work completes, the thread "returns" into shellcode.
 *
 * Detection via Get-Process thread WaitReason analysis:
 *   - WrQueue saturation (>40% of threads) → Pool Party / WTH indicator
 *   - Thread bloat (>150 total) → worker factory expansion
 *   - Absolute pool thread count (>100) → injected work items inflating pool
 *
 * NOTE: Uses Get-Process.Threads instead of WMI Win32_Thread because:
 *   - Get-Process is 15-20× faster (returns WaitReason natively, no CIM round-trip)
 *   - Win32_Thread doesn't expose ThreadWaitReason as a named string anyway
 *   - Win32_ThreadPool is not a real WMI class — no thread pool introspection via WMI exists
 *
 * No admin required. PowerShell only.
 */

import { execSync } from 'child_process'
import { addFindingDedup, type ScanResult } from '../../types'
import { getMonitoredProcessArgs } from '../../signature-registry'

export function scanThreadPoolAbuse(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$gameProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
if (-not $gameProcs) { Write-Output '[]'; exit 0 }

$results = @()
foreach ($proc in $gameProcs) {
  $threads = $proc.Threads
  $total = $threads.Count
  if ($total -lt 20) { continue }  # Skip tiny processes

  # ── Categorize threads by WaitReason ──
  $poolWait = 0    # WrQueue = thread pool queue wait (KQUEUE)
  $userWait = 0    # UserRequest = APC wait / UI thread wait
  $execWait = 0    # Executive = kernel object wait
  $lpcWait = 0     # WrLpcReceive = ALPC wait (possible TP_ALPC abuse)
  $otherWait = 0

  foreach ($t in $threads) {
    try {
      $reason = [string]$t.WaitReason
      if ($reason -eq 'WrQueue')          { $poolWait++ }
      elseif ($reason -eq 'UserRequest')  { $userWait++ }
      elseif ($reason -eq 'Executive')    { $execWait++ }
      elseif ($reason -match 'Lpc')       { $lpcWait++ }
      else                                { $otherWait++ }
    } catch { $otherWait++ }
  }

  $poolPct = if ($total -gt 0) { [math]::Round(($poolWait / $total) * 100, 1) } else { 0 }
  $lpcPct  = if ($total -gt 0) { [math]::Round(($lpcWait  / $total) * 100, 1) } else { 0 }

  # ── Composite heuristic: numeric score → risk level ──
  $score = 0

  # Thread bloat: 150+ = 10pts, 250+ = 20pts
  if ($total -gt 250)       { $score += 20 }
  elseif ($total -gt 150)   { $score += 10 }

  # WrQueue saturation: 35%+ = 8pts, 50%+ = 16pts
  if ($poolPct -gt 50)      { $score += 16 }
  elseif ($poolPct -gt 35)  { $score += 8 }

  # Absolute pool thread count: 100+ = 10pts
  if ($poolWait -gt 100)    { $score += 10 }

  # ALPC injection: 15+ threads or 20%+ = 8pts
  if ($lpcWait -gt 15 -or $lpcPct -gt 20) { $score += 8 }

  # Dual APC + pool attack: 30+ UserRequest AND 25%+ WrQueue = 8pts
  if ($userWait -gt 30 -and $poolPct -gt 25) { $score += 8 }

  # Map score to risk level
  if ($score -ge 35)        { $riskLevel = 'high' }
  elseif ($score -ge 20)    { $riskLevel = 'medium' }
  elseif ($score -ge 10)    { $riskLevel = 'low' }
  else                      { $riskLevel = 'none' }

  # ── Rebuild signals array from score components (for readable output) ──
  $signals = @()
  if ($total -gt 250)                     { $signals += 'TPABUSE:critical-thread-bloat' }
  elseif ($total -gt 150)                 { $signals += 'TPABUSE:thread-bloat' }
  if ($poolPct -gt 50)                    { $signals += 'TPABUSE:pool-saturation-critical' }
  elseif ($poolPct -gt 35)               { $signals += 'TPABUSE:pool-saturation' }
  if ($poolWait -gt 100)                  { $signals += 'TPABUSE:pool-count' }
  if ($lpcWait -gt 15 -or $lpcPct -gt 20) { $signals += 'TPABUSE:alpc-injection' }
  if ($userWait -gt 30 -and $poolPct -gt 25) { $signals += 'TPABUSE:dual-apc-pool' }

  if ($signals.Count -gt 0) {
    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      TotalThreads = $total
      WrQueue = $poolWait
      WrQueuePct = $poolPct
      UserRequest = $userWait
      Executive = $execWait
      LpcReceive = $lpcWait
      LpcReceivePct = $lpcPct
      Signals = $signals -join ', '
      RiskLevel = $riskLevel
      Detail = "$total threads: $poolWait WrQueue (${poolPct}%), $userWait UserRequest, $execWait Executive, $lpcWait LpcReceive"
    }
  }
}

$results | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 10000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    let hits: {
      PID?: number; Name?: string; TotalThreads?: number
      WrQueue?: number; WrQueuePct?: number; UserRequest?: number
      Executive?: number; LpcReceive?: number; LpcReceivePct?: number
      Signals?: string; RiskLevel?: string; Detail?: string
    }[] = []
    try { const p = JSON.parse(out); hits = Array.isArray(p) ? p : [p] } catch { return results }

    for (const hit of hits) {
      const key = `tpabuse:${hit.Name}:${hit.PID}`
      if (addFindingDedup(key)) {
        const riskLevel = hit.RiskLevel || 'medium'
        const risk: 'high' | 'medium' | 'low' =
          riskLevel === 'high' ? 'high' : riskLevel === 'low' ? 'low' : 'medium'

        const signalList = (hit.Signals || '').split(', ')
        const matches: string[] = [
          hit.Detail || '',
          `Total threads: ${hit.TotalThreads}`,
          `WrQueue (pool queue): ${hit.WrQueue} threads (${hit.WrQueuePct}%)`,
        ]
        if (hit.UserRequest && hit.UserRequest > 0) {
          matches.push(`UserRequest (APC wait): ${hit.UserRequest} threads`)
        }
        if (hit.LpcReceive && hit.LpcReceive > 0) {
          matches.push(`LpcReceive (TP_ALPC): ${hit.LpcReceive} threads (${hit.LpcReceivePct}%)`)
        }
        matches.push(`Signals: ${signalList.join(', ')}`)
        const hasPoolSpecific =
          signalList.some(s => s.includes('pool-saturation') || s.includes('pool-count'))
        if (hasPoolSpecific) {
          matches.push(
            '⚠ Pool Party: malicious TP_WORK items injected into thread pool',
            '⚠ Waiting Thread Hijacking: stack return address overwrite in pool threads',
          )
        }
        matches.push(
          '⚠ Thread pool abuse bypasses CreateRemoteThread kernel callbacks',
        )

        results.push({
          path: `process:${hit.Name} (PID: ${hit.PID})`,
          fileName: `⚠ Thread Pool Abuse: ${hit.Name} — ${hit.WrQueue} pool threads (${hit.WrQueuePct}%)`,
          type: 'process',
          risk,
          matches,
          size: hit.TotalThreads || 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* thread pool scan optional */ }

  return results
}
