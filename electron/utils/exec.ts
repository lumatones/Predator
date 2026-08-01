/**
 * Predator — Safe Execution Utilities
 *
 * execWithTimeout() — execSync wrapper with proper timeout + process kill.
 * Prevents orphaned PowerShell processes from freezing the UI.
 *
 * 161 execSync calls existed in the codebase. All synchronous.
 * Many had 8-25s timeouts, no kill fallback, no process cleanup.
 *
 * This wrapper:
 *   1. Sets a hard timeout (default 8s)
 *   2. Ensures child_process termination on timeout
 *   3. Windows-specific: uses taskkill /F for orphan cleanup
 *   4. Preserves all existing behavior (sync, captures stdout)
 *   5. Logs timeout events to stderr for debugging
 */

import { execSync, execFileSync, spawn } from 'child_process'

export interface ExecOptions {
  /** Max execution time in ms (default 8000) */
  timeout?: number
  /** Encoding (default 'utf-8') */
  encoding?: BufferEncoding
  /** Hide window (default true) */
  windowsHide?: boolean
  /** Max buffer size in bytes (default 1MB) */
  maxBuffer?: number
  /**
   * Collapse newlines in multi-line PowerShell scripts.
   * - 'spaces': replace \n with ' ' (for single-line expressions spanning multiple code lines)
   * - 'semicolons': replace \n with '; ' (for multi-statement scripts)
   * - undefined: keep newlines as-is
   */
  collapseLines?: 'spaces' | 'semicolons'
}

// Default options — NOT typed as Required<ExecOptions> because
// collapseLines should stay optional (no reasonable default).
const DEFAULT_OPTS = {
  timeout: 8000,
  encoding: 'utf-8' as BufferEncoding,
  windowsHide: true,
  maxBuffer: 1024 * 1024,
}

/**
 * Safe execSync wrapper — prevents orphaned processes on timeout.
 *
 * Use instead of raw execSync() everywhere PowerShell or long-running
 * commands are involved. Falls back gracefully on failure.
 *
 * @example
 *   // Before (blocks 25s with no cleanup):
 *   const out = execSync(`powershell ...`, { timeout: 25000 })
 *
 *   // After (kills process on timeout, logs warning):
 *   const out = execWithTimeout(`powershell ...`, { timeout: 25000 }) || ''
 */
export function execWithTimeout(
  command: string,
  options: ExecOptions = {},
): string | null {
  const opts = { ...DEFAULT_OPTS, ...options }

  try {
    return execSync(command, {
      encoding: opts.encoding,
      timeout: opts.timeout,
      windowsHide: opts.windowsHide,
      maxBuffer: opts.maxBuffer,
      killSignal: 'SIGTERM',
    }) as string
  } catch (err: unknown) {
    // Log timeout events for debugging (not a crash)
    const processError = err as { killed?: boolean; signal?: string | null }
    if (processError.killed || processError.signal) {
      console.warn(`[exec] Timed out after ${opts.timeout}ms: ${command.slice(0, 80)}...`)
    }
    return null
  }
}

/**
 * Safe execFileSync wrapper — avoids shell injection, auto-kills on timeout.
 * Preferred over execSync when shell features aren't needed.
 */
export function execFileWithTimeout(
  file: string,
  args: string[],
  options: ExecOptions = {},
): string | null {
  const opts = { ...DEFAULT_OPTS, ...options }

  try {
    return execFileSync(file, args, {
      encoding: opts.encoding,
      timeout: opts.timeout,
      windowsHide: opts.windowsHide,
      maxBuffer: opts.maxBuffer,
      killSignal: 'SIGTERM',
    }) as string
  } catch (err: unknown) {
    const processError = err as { killed?: boolean; signal?: string | null }
    if (processError.killed || processError.signal) {
      console.warn(`[exec] Timed out after ${opts.timeout}ms: ${file} ${args.slice(0, 3).join(' ')}...`)
    }
    return null
  }
}

/**
 * Run a PowerShell command with safe timeout + kill.
 * Auto-escaping of double-quotes included.
 * Supports multi-line scripts via collapseLines option.
 *
 * @example
 *   const out = execPowerShell(`Get-Process | ConvertTo-Json`, { timeout: 8000 })
 *
 *   // Multi-line C# Add-Type script:
 *   const out = execPowerShell(cSharpScript, { timeout: 15000, collapseLines: 'semicolons' })
 */
export interface AsyncExecOptions extends ExecOptions {
  /** Abort the child process when the scan is cancelled. */
  signal?: AbortSignal
}

/**
 * Execute a program without a shell and collect stdout asynchronously.
 *
 * Unlike execSync/execFileSync this never blocks the Electron event loop.
 * `args` are passed directly to the child process, so values cannot alter
 * shell syntax. Timeout and cancellation both terminate the child process.
 */
export function spawnAsyncWithTimeout(
  file: string,
  args: string[],
  options: AsyncExecOptions = {},
): Promise<string | null> {
  const opts = { ...DEFAULT_OPTS, ...options }

  return new Promise(resolve => {
    if (options.signal?.aborted) {
      resolve(null)
      return
    }

    let child: ReturnType<typeof spawn>
    let settled = false
    let stdout = ''
    const timerState: { handle?: ReturnType<typeof setTimeout> } = {}

    function cleanup() {
      if (timerState.handle) clearTimeout(timerState.handle)
      opts.signal?.removeEventListener('abort', abort)
    }

    function finish(result: string | null) {
      if (settled) return
      settled = true
      cleanup()
      resolve(result)
    }

    function terminate() {
      if (!child?.pid) return
      child.kill()
      // On Windows, PowerShell can create descendants while inspecting an
      // archive or process tree. Kill the whole tree to avoid orphan work.
      if (process.platform === 'win32') {
        const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
          windowsHide: true,
          shell: false,
          stdio: 'ignore',
        })
        killer.on('error', () => { /* best effort cleanup */ })
      }
    }

    function abort() {
      terminate()
      finish(null)
    }

    try {
      child = spawn(file, args, {
        windowsHide: opts.windowsHide,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch {
      resolve(null)
      return
    }

    child.stdout?.setEncoding(opts.encoding)
    child.stdout?.on('data', (chunk: string) => {
      stdout += chunk
      if (Buffer.byteLength(stdout, opts.encoding) > opts.maxBuffer) {
        terminate()
        finish(null)
      }
    })
    child.on('error', () => finish(null))
    child.on('close', (code, signal) => {
      if (code === 0) {
        finish(stdout)
      } else {
        if (signal) {
          console.warn(`[exec] Async process stopped (${signal}): ${file}`)
        }
        finish(null)
      }
    })

    if (settled) return
    opts.signal?.addEventListener('abort', abort, { once: true })
    timerState.handle = setTimeout(() => {
      terminate()
      console.warn(`[exec] Async process timed out after ${opts.timeout}ms: ${file}`)
      finish(null)
    }, opts.timeout)
    if (settled && timerState.handle) {
      clearTimeout(timerState.handle)
      timerState.handle = undefined
    }

    if (opts.signal?.aborted) abort()
  })
}

/** Run PowerShell asynchronously without shell interpolation. */
export function execPowerShellAsync(
  script: string,
  options: AsyncExecOptions = {},
): Promise<string | null> {
  let prepared = script

  if (options.collapseLines === 'semicolons') {
    prepared = prepared
      .split('\n')
      .map(l => l.trim())
      .filter(l => l)
      .join('; ')
  } else if (options.collapseLines === 'spaces') {
    prepared = prepared.split('\n').map(l => l.trim()).join(' ')
  }

  return spawnAsyncWithTimeout(
    'powershell',
    ['-NoProfile', '-Command', prepared],
    { ...options, windowsHide: true },
  )
}

export function execPowerShell(
  script: string,
  options: ExecOptions = {},
): string | null {
  let prepared = script

  // Collapse newlines for PowerShell -Command (which executes only the first line)
  if (options.collapseLines === 'semicolons') {
    prepared = prepared
      .split('\n')
      .map(l => l.trim())
      .filter(l => l)
      .join('; ')
  } else if (options.collapseLines === 'spaces') {
    prepared = prepared.split('\n').map(l => l.trim()).join(' ')
  }

  const escaped = prepared.replace(/"/g, '\\"')
  return execWithTimeout(
    `powershell -NoProfile -Command "${escaped}"`,
    { ...options, windowsHide: true },
  )
}
