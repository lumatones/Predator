/**
 * Predator — APC Injection Detector: Tier 3 — ETW Background Monitor (5 min)
 *
 * BACKGROUND ETW MONITOR — captures thread creation events in real time
 * over a 5-minute window with 30-second polling intervals.
 *
 * Why 5 minutes instead of 5 seconds:
 *   - Single 5s snapshot only catches injections happening DURING that window.
 *   - Most cheat injections take 10-60s (user launches game, then cheat).
 *   - 5 minutes covers the full game launch + cheat injection window.
 *   - Sustained pattern detection: a process must show elevated thread
 *     creation across MULTIPLE intervals (not just one random spike).
 *
 * Architecture:
 *   1. Start Kernel-Thread + Kernel-Process ETW trace on file_a.etl
 *   2. Every 30 seconds (× 10 = 5 min):
 *      a. Start NEW trace on file_b.etl (gap-free handoff)
 *      b. Stop OLD trace on file_a.etl
 *      c. Parse file_a.etl with Get-WinEvent → thread events per process
 *      d. Accumulate counts in cumulative tracker
 *      e. Swap a↔b
 *   3. Stop final trace
 *   4. Flag processes with sustained thread creation across 3+ intervals
 *
 * Sustained detection: a single 50-event spike could be a loading screen.
 * 3+ intervals with >30 events each = deliberate injection activity.
 *
 * Requires admin privileges. Gracefully fails if unavailable.
 */

import { execPowerShell, execWithTimeout } from '../../utils/exec'
import * as fs from 'fs'
import { addFindingDedup, type ScanResult, ctx } from '../../types'

/** Helper: create a finding for a process with sustained thread activity. */
function signalProcess(
  results: ScanResult[],
  pid: number,
  name: string,
  totalEvents: number,
  activeIntervals: number,
  signal: string,
  risk: 'high' | 'medium' | 'low',
  totalIntervals: number,
): void {
  const key = `ebapc-bg:${name}:${pid}`
  if (!addFindingDedup(key)) return

  results.push({
    path: `process:${name} (PID: ${pid})`,
    fileName: `⚠ ETW Background Monitor: ${name} — ${totalEvents} thread events over ${activeIntervals}/10 intervals`,
    type: 'process',
    risk,
    matches: [
      `Sustained thread creation: ${activeIntervals}/${totalIntervals} intervals with >30 events each`,
      `Total thread events in 5-min window: ${totalEvents} (Thread/Start + Thread/Ready)`,
      `Signal: ${signal}`,
      `Normal idle game client: <20 events per 30s interval`,
      '⚠ Sustained thread creation bursts → injection activity detected',
      '⚠ Injected code runs BEFORE security hooks are initialized (Early Bird APC)',
      '⚠ Detection via ETW Microsoft-Windows-Kernel-Thread background monitor',
    ],
    size: totalEvents,
    modifiedAt: new Date().toISOString(),
  })
}

export function scanEtwKernelThread(): ScanResult[] {
  const results: ScanResult[] = []
  const traceName = 'Predator_BG_Monitor'
  const tmpDir = process.env.TEMP || 'C:\\Windows\\Temp'
  const fileA = `${tmpDir}\\predator_bg_a.etl`
  const fileB = `${tmpDir}\\predator_bg_b.etl`
  const INTERVAL_SEC = 30   // seconds per polling interval
  const INTERVALS = 10      // total intervals = 5 minutes

  try {
    // Clean up stale trace sessions and ETL files from previous runs
    try { execWithTimeout(`logman stop "${traceName}" -ets 2>nul`, { timeout: 3000 }) } catch (err) { console.warn('[etw-trace] failed:', (err as Error).message) }
    try { fs.unlinkSync(fileA) } catch {}
    try { fs.unlinkSync(fileB) } catch {}

    // ── Start initial trace on file A ──
    execWithTimeout(
      `logman start "${traceName}" ` +
      `-p "Microsoft-Windows-Kernel-Thread" 0xFF ` +
      `-p "Microsoft-Windows-Kernel-Process" 0xFF ` +
      `-o "${fileA}" -ets`,
      { timeout: 5000 },
    )

    // ── Cumulative tracker: PID -> { name, intervalCounts[], totalEvents } ──
    const cumulative = new Map<number, {
      name: string
      eventsPerInterval: number[]
      totalEvents: number
    }>()

    let currentFile = fileA
    let nextFile = fileB

    // ── Polling loop: 10 intervals × 30 seconds ──
    for (let i = 0; i < INTERVALS; i++) {
      // Respect scan cancellation — abort early if user cancelled
      if (ctx.abortController?.signal.aborted) {
        break
      }

      // Wait 30 seconds (trace runs on current file)
      try {
        execWithTimeout(`timeout /t ${INTERVAL_SEC} /nobreak >nul`, {
          timeout: (INTERVAL_SEC + 5) * 1000,
        })
      } catch {
        // timeout may throw on Ctrl+C — still try to parse what we have
      }

      // ── Gap-free handoff: start NEW trace first, THEN stop old ──
      try {
        execWithTimeout(
          `logman start "${traceName}" ` +
          `-p "Microsoft-Windows-Kernel-Thread" 0xFF ` +
          `-p "Microsoft-Windows-Kernel-Process" 0xFF ` +
          `-o "${nextFile}" -ets`,
          { timeout: 5000 },
        )
      } catch {
        // Trace start failed — likely admin lost. Skip remaining intervals.
        break
      }

      // Stop old trace (gaps are <1s thanks to start-before-stop ordering)
      try {
        execWithTimeout(`logman stop "${traceName}" -ets`, {
          timeout: 5000,
        })
      } catch { /* trace already stopped */ }

      // ── Parse the completed ETL file ──
      try {
        const psParse = `
$ErrorActionPreference = 'SilentlyContinue'
$tracePath = '${currentFile.replace(/\\/g, '\\\\')}'

$threadEvents = Get-WinEvent -Path $tracePath ` +
  `-FilterXPath "*[System[Provider[@Name='Microsoft-Windows-Kernel-Thread'] and (EventID=1 or EventID=3)]]" ` +
  `-Oldest -MaxEvents 5000 -ErrorAction SilentlyContinue

if (-not $threadEvents) { Write-Output '[]'; exit 0 }

$perProc = @{}
foreach ($evt in $threadEvents) {
  $p = [int]$evt.ProcessId
  if ($p) {
    if (-not $perProc.ContainsKey($p)) {
      $perProc[$p] = @{ Count = 0; Name = '' }
    }
    $perProc[$p].Count++
  }
}

# Return only processes with >0 events (filter noise)
$out = @()
foreach ($kv in $perProc.GetEnumerator()) {
  if ($kv.Value.Count -gt 0) {
    $out += [PSCustomObject]@{ PID = $kv.Key; Count = $kv.Value.Count }
  }
}
$out | ConvertTo-Json -Compress
`
        const out = (execPowerShell(psParse, { timeout: 15000 }) || '').trim()

        if (out && out !== '[]' && out.length >= 3) {
          let intervalHits: { PID?: number; Count?: number }[] = []
          try { const p = JSON.parse(out); intervalHits = Array.isArray(p) ? p : [p] } catch {}

          for (const hit of intervalHits) {
            if (!hit.PID) continue
            const pid = hit.PID
            const count = hit.Count || 0

            if (!cumulative.has(pid)) {
              // Resolve process name once (only on first sighting)
              let procName = `PID:${pid}`
              try {
                const nameOut = (execPowerShell(`(Get-Process -Id ${pid} -ErrorAction SilentlyContinue).ProcessName`, { timeout: 3000 }) || '').trim()
                if (nameOut) procName = nameOut
              } catch {}

              cumulative.set(pid, {
                name: procName,
                eventsPerInterval: new Array(INTERVALS).fill(0),
                totalEvents: 0,
              })
            }

            const entry = cumulative.get(pid)!
            entry.eventsPerInterval[i] = count
            entry.totalEvents += count
          }
        }
      } catch { /* parse failed for this interval — skip */ }

      // Clean up the ETL file we just parsed
      try { fs.unlinkSync(currentFile) } catch {}

      // Swap files for next iteration
      ;[currentFile, nextFile] = [nextFile, currentFile]
    }

    // ── Stop final trace session (cleanup) ──
    try {
      execWithTimeout(`logman stop "${traceName}" -ets`, {
        timeout: 5000,
      })
    } catch (err) { console.warn('[etw-trace] failed:', (err as Error).message) }

    // ── Clean up remaining ETL files ──
    try { fs.unlinkSync(fileA) } catch {}
    try { fs.unlinkSync(fileB) } catch {}

    // ── Analyze cumulative data for sustained patterns ──
    for (const [pid, entry] of cumulative) {
      const activeIntervals = entry.eventsPerInterval.filter(c => c > 30).length
      const total = entry.totalEvents

      if (activeIntervals >= 5 && total >= 500) {
        signalProcess(results, pid, entry.name, total, activeIntervals,
          'EBAPC:sustained-critical', 'high', INTERVALS)
      } else if (activeIntervals >= 4 && total >= 300) {
        signalProcess(results, pid, entry.name, total, activeIntervals,
          'EBAPC:sustained-high', 'high', INTERVALS)
      } else if (activeIntervals >= 3 && total >= 200) {
        signalProcess(results, pid, entry.name, total, activeIntervals,
          'EBAPC:sustained', 'medium', INTERVALS)
      } else if (activeIntervals >= 2 && total >= 150) {
        signalProcess(results, pid, entry.name, total, activeIntervals,
          'EBAPC:intermittent', 'low', INTERVALS)
      }
    }
  } catch {
    // logman/Get-WinEvent unavailable (no admin, or not on Windows) — graceful skip
    try { execWithTimeout(`logman stop "${traceName}" -ets`, { timeout: 3000 }) } catch (err) { console.warn('[etw-trace] failed:', (err as Error).message) }
    try { fs.unlinkSync(fileA) } catch {}
    try { fs.unlinkSync(fileB) } catch {}
  }

  return results
}
