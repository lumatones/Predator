/**
 * Predator — Background Scan Scheduler (E12)
 *
 * Runs automatic background scans:
 *   - Every 6 hours (quiet periodic check)
 *   - On game launch (detected via process polling)
 *   - 2 minutes after app startup (initial baseline)
 *
 * Safety: never interrupts a user-initiated scan.
 * Uses quick-scan mode for minimal system impact.
 */

import { execPowerShell, execWithTimeout } from './utils/exec'
import type { BrowserWindow } from 'electron'
import { runQuickScan } from './scanner/quick-scan'
import { runPostScanPipeline } from './scan-pipeline'
import { filterNoiseFindings } from './result-grouper'
import { ctx } from './types'

// ── Config ──

const SCHEDULE_INTERVAL_MS = 6 * 60 * 60 * 1000  // 6 hours
const GAME_POLL_INTERVAL_MS = 60 * 1000           // 60 seconds
const STARTUP_DELAY_MS = 2 * 60 * 1000            // 2 minutes
const MIN_SCAN_INTERVAL_MS = 30 * 60 * 1000       // 30 min between scans

// ── Game process patterns (Get-Process -Name wildcards) ──

const GAME_PROCESS_NAMES = ["'GTA5*'", "'FiveM*'", "'ragemp*'", "'altv*'"]

// ── State ──

let _scheduleTimer: ReturnType<typeof setInterval> | null = null
let _gamePollTimer: ReturnType<typeof setInterval> | null = null
let _startupTimer: ReturnType<typeof setTimeout> | null = null
let _wasGameRunning = false
let _lastScanTime = 0
let _scanInProgress = false

// ── Helpers ──

function isGameRunning(): boolean {
  try {
    const psCmd = `Get-Process -Name ${GAME_PROCESS_NAMES.join(',')} -ErrorAction SilentlyContinue | Select -First 1`
    const out = execPowerShell(psCmd, { timeout: 5000 }) || ''
    return out.trim().length > 0
  } catch {
    return false
  }
}

function isUserScanActive(): boolean {
  return !!ctx.abortController && !ctx.abortController.signal.aborted
}

// ── Background scan ──

async function runBackgroundScan(win: BrowserWindow | null, reason: string): Promise<void> {
  // Never interrupt a user-initiated scan
  if (isUserScanActive()) {
    console.log(`  ⏰ Scheduler: skipping (user scan in progress) — reason: ${reason}`)
    return
  }

  if (_scanInProgress) {
    console.log(`  ⏰ Scheduler: skipping (background scan already running) — reason: ${reason}`)
    return
  }

  const now = Date.now()
  if (now - _lastScanTime < MIN_SCAN_INTERVAL_MS) {
    const ago = Math.round((now - _lastScanTime) / 1000)
    console.log(`  ⏰ Scheduler: skipping (last scan ${ago}s ago) — reason: ${reason}`)
    return
  }

  console.log(`  🔍 Background scan: ${reason}`)
  _scanInProgress = true
  _lastScanTime = now

  try {
    // Create a fresh context — don't reuse ctx from user scans
    ctx.resetScan()
    const result = await runQuickScan(win)
    const filtered = filterNoiseFindings(result.results)

    // Silently run post-scan pipeline (telemetry only, no token)
    await runPostScanPipeline(
      result.results,
      {
        totalScanned: result.filesScanned,
        suspiciousFiles: filtered.length,
        highRiskCount: filtered.filter(r => r.risk === 'high').length,
        scanTimeMs: Date.now() - now,
      },
      { tokenId: 0, pcUsername: '__scheduler__', mode: 'quick', startTime: now },
    )

    console.log(`  ✅ Background scan done: ${result.filesScanned} files, ${filtered.length} findings`)
  } catch (err) {
    console.warn('[scan-scheduler] background scan failed:', (err as Error).message)
  } finally {
    _scanInProgress = false
  }
}

// ── Lifecycle ──

export function startScanScheduler(win: BrowserWindow | null): void {
  console.log('  ⏰ Scan scheduler active (every 6h + game launch detection)')

  // Periodic scan every 6 hours
  _scheduleTimer = setInterval(() => {
    runBackgroundScan(win, 'scheduled (6h)')
  }, SCHEDULE_INTERVAL_MS)

  // Game launch detection — poll every 30s
  _gamePollTimer = setInterval(() => {
    const gameRunning = isGameRunning()
    if (gameRunning && !_wasGameRunning) {
      console.log('  🎮 Game process detected')
      runBackgroundScan(win, 'game launch')
    }
    _wasGameRunning = gameRunning
  }, GAME_POLL_INTERVAL_MS)

  // Initial scan after startup delay
  _startupTimer = setTimeout(() => {
    runBackgroundScan(win, 'initial (post-startup)')
  }, STARTUP_DELAY_MS)
}

export function stopScanScheduler(): void {
  if (_scheduleTimer) {
    clearInterval(_scheduleTimer)
    _scheduleTimer = null
  }
  if (_gamePollTimer) {
    clearInterval(_gamePollTimer)
    _gamePollTimer = null
  }
  if (_startupTimer) {
    clearTimeout(_startupTimer)
    _startupTimer = null
  }
  console.log('  ⏰ Scan scheduler stopped')
}
