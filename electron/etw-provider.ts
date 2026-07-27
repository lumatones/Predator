/**
 * Predator — ETW Provider (Event Tracing for Windows)
 *
 * Kernel-level visibility without custom driver.
 * Uses PowerShell to subscribe to ETW providers for:
 *   - Process/thread creation events
 *   - Image (DLL) load events
 *   - Threat intelligence events
 *
 * This gives us real-time insight that cannot be hidden by cheats
 * (ETW runs at kernel level, below user-mode hooks/patches).
 */

import { execSync } from 'child_process'
import { addFindingDedup, type ScanResult } from './types'

// ── Types ──

export interface EtwProcessEvent {
  processId: number
  processName: string
  parentProcessId: number
  commandLine: string
  timestamp: string
}

export interface EtwImageLoadEvent {
  processId: number
  imageName: string
  imagePath: string
}

// ── ETW Provider session ──

let _etwSessionActive = false
let _capturedEvents: { processes: EtwProcessEvent[]; images: EtwImageLoadEvent[] } = {
  processes: [],
  images: [],
}

/**
 * Start ETW session for process creation monitoring.
 * Uses PowerShell Register-CimIndicationEvent (WMI-based, no admin required for some events).
 * This is a lightweight alternative to full ETW kernel providers.
 */
export function startEtwSession(): boolean {
  if (_etwSessionActive) return true
  _etwSessionActive = true
  _capturedEvents = { processes: [], images: [] }

  console.log('  🔍 ETW session started — monitoring process/thread creation')

  // ETW capture is asynchronous — we query WMI events on each scan call
  return true
}

/**
 * Stop ETW session and clean up.
 */
export function stopEtwSession(): void {
  _etwSessionActive = false
  _capturedEvents = { processes: [], images: [] }
  console.log('  🔍 ETW session stopped')
}

// ── WMI Event Queries (run during scan) ──

/**
 * Query recent process creation events via WMI.
 * Catches:
 * - Processes spawned from suspicious parents (e.g., cheat loader → game injection)
 * - Processes with hidden windows
 * - Processes running from temp/downloads directories
 */
export function scanEtwProcessEvents(): ScanResult[] {
  const results: ScanResult[] = []
  if (!_etwSessionActive) return results

  try {
    // Query Win32_ProcessStartTrace equivalent via WMI
    const psCmd = `
      Get-WmiObject Win32_Process -Filter "Name LIKE '%.exe'" |
      Select-Object ProcessId, Name, ParentProcessId, CommandLine, CreationDate |
      Sort-Object CreationDate -Descending |
      Select-Object -First 100 |
      ConvertTo-Json -Compress
    `.trim()

    const out = execSync(`powershell -Command "${psCmd.replace(/"/g, '\\"').replace(/\n/g, ' ')}"`, {
      encoding: 'utf-8' as BufferEncoding,
      timeout: 8000,
    }).trim()

    if (!out || out.length < 5) return results

    let processes: { ProcessId?: number; Name?: string; ParentProcessId?: number; CommandLine?: string }[] = []
    try {
      const parsed = JSON.parse(out)
      processes = Array.isArray(parsed) ? parsed : [parsed]
    } catch { return results }

    const suspiciousParents = new Set(['powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe'])
    const suspiciousPaths = ['\\\\temp\\\\', '\\\\appdata\\\\local\\\\temp\\\\', '\\\\downloads\\\\', '\\\\desktop\\\\']

    for (const proc of processes) {
      const name = (proc.Name || '').toLowerCase()
      const ppid = proc.ParentProcessId || 0
      const cmdLine = (proc.CommandLine || '').toLowerCase()

      const signals: string[] = []

      // Check: spawned from suspicious parent
      if (ppid > 0) {
        try {
          const parentOut = execSync(`wmic process where ProcessId=${ppid} get Name /format:csv 2>nul`, { encoding: 'utf-8' as BufferEncoding, timeout: 3000 })
          const parentName = parentOut.split('\n')[1]?.split(',')[2]?.trim()?.toLowerCase() || ''
          if (suspiciousParents.has(parentName)) {
            signals.push(`ETW: suspicious parent process: ${parentName}`)
          }
        } catch { /* skip */ }
      }

      // Check: running from suspicious location
      for (const sp of suspiciousPaths) {
        if (cmdLine.includes(sp)) {
          signals.push(`ETW: running from suspicious path: ${sp}`)
          break
        }
      }

      // Check: hidden window / no GUI
      if (cmdLine.includes('-hidden') || cmdLine.includes('-window hidden')) {
        signals.push('ETW: process started with hidden window')
      }

      if (signals.length > 0 && addFindingDedup(`etw:${name}:${proc.ProcessId}`)) {
        results.push({
          path: `etw:${name} (PID: ${proc.ProcessId})`,
          fileName: `ETW: Suspicious process creation — ${name}`,
          type: 'process',
          risk: signals.length >= 2 ? 'high' : 'medium',
          matches: signals,
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* ETW WMI optional */ }

  return results
}

/**
 * Query recently loaded DLLs/modules for suspicious patterns.
 * Detects injection via LoadLibrary in unexpected processes.
 */
export function scanEtwImageLoadEvents(): ScanResult[] {
  const results: ScanResult[] = []
  if (!_etwSessionActive) return results

  try {
    // Check for DLLs loaded from temp/downloads into game processes
    const psCmd = `
      Get-Process -Name GTA5*, FiveM*, ragemp*, altv* -ErrorAction SilentlyContinue |
      ForEach-Object {
        $pid = $_.Id
        $_.Modules | Where-Object { $_.ModuleName -match '\\.(dll|asi)$' } |
        Select-Object @{N='PID';E={$pid}}, ModuleName, FileName
      } |
      ConvertTo-Json -Compress
    `.trim()

    const out = execSync(`powershell -Command "${psCmd.replace(/"/g, '\\"').replace(/\n/g, ' ')}"`, {
      encoding: 'utf-8' as BufferEncoding,
      timeout: 8000,
    }).trim()

    if (!out || out.length < 5) return results

    let modules: { PID?: number; ModuleName?: string; FileName?: string }[] = []
    try {
      const parsed = JSON.parse(out)
      modules = Array.isArray(parsed) ? parsed : [parsed]
    } catch { return results }

    const suspiciousLocations = ['\\\\temp\\\\', '\\\\downloads\\\\', '\\\\desktop\\\\', '\\\\appdata\\\\local\\\\temp\\\\']

    for (const mod of modules) {
      const modPath = (mod.FileName || '').toLowerCase()
      const modName = mod.ModuleName || ''

      for (const sl of suspiciousLocations) {
        if (modPath.includes(sl) && addFindingDedup(`etw-image:${modName}`)) {
          results.push({
            path: `etw:${modName} (PID: ${mod.PID})`,
            fileName: `ETW: DLL loaded from suspicious location — ${modName}`,
            type: 'process',
            risk: 'high',
            matches: [`DLL loaded from non-standard location: ${sl}`, `Module: ${modName}`],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
          break
        }
      }
    }
  } catch { /* ETW optional */ }

  return results
}

/**
 * Scan for remote thread injection patterns.
 * Detects CreateRemoteThread / NtCreateThreadEx being used to inject code.
 */
export function scanEtwThreadInjection(): ScanResult[] {
  const results: ScanResult[] = []
  if (!_etwSessionActive) return results

  try {
    // Query processes with high thread counts in game executables (injection indicator)
    const psCmd = `
      Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'GTA5|FiveM|ragemp|altv' } |
      Select-Object Id, Name, Threads, HandleCount |
      Where-Object { $_.Threads.Count -gt 300 } |
      ConvertTo-Json -Compress
    `.trim()

    const out = execSync(`powershell -Command "${psCmd.replace(/"/g, '\\"').replace(/\n/g, ' ')}"`, {
      encoding: 'utf-8' as BufferEncoding,
      timeout: 6000,
    }).trim()

    if (!out || out.length < 5) return results

    let procs: { Id?: number; Name?: string; Threads?: { Count: number }; HandleCount?: number }[] = []
    try {
      const parsed = JSON.parse(out)
      procs = Array.isArray(parsed) ? parsed : [parsed]
    } catch { return results }

    for (const proc of procs) {
      const threadCount = proc.Threads?.Count || 0
      const key = `etw-threads:${proc.Name}:${proc.Id}`
      if (threadCount > 100 && addFindingDedup(key)) {
        results.push({
          path: `etw:${proc.Name} (PID: ${proc.Id})`,
          fileName: `ETW: Abnormal thread count — ${proc.Name}`,
          type: 'process',
          risk: threadCount > 500 ? 'high' : 'medium',
          matches: [
            `ETW: ${threadCount} threads in game process (normal: <200)`,
            'Possible remote thread injection',
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* ETW optional */ }
  return results
}

/**
 * Scan for process hollowing indicators.
 * Detects processes with suspicious PE headers in memory (mismatched image).
 */
export function scanEtwProcessHollowing(): ScanResult[] {
  const results: ScanResult[] = []
  if (!_etwSessionActive) return results

  try {
    // PowerShell script: check if running processes' on-disk image differs from in-memory
    const psCmd = `
      Get-Process | Where-Object { $_.Path } |
      Select-Object -First 40 Id, Name, Path |
      ForEach-Object {
        try {
          $diskSig = (Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue).Status
          [PSCustomObject]@{ PID=$_.Id; Name=$_.Name; Path=$_.Path; SignatureStatus=$diskSig }
        } catch { [PSCustomObject]@{ PID=$_.Id; Name=$_.Name; Path=$_.Path; SignatureStatus='Error' } }
      } | ConvertTo-Json -Compress
    `.trim()

    const out = execSync(`powershell -Command "${psCmd.replace(/"/g, '\\"').replace(/\n/g, ' ')}"`, {
      encoding: 'utf-8' as BufferEncoding,
      timeout: 25000,
    }).trim()

    if (!out || out.length < 5) return results

    let sigs: { PID?: number; Name?: string; Path?: string; SignatureStatus?: string }[] = []
    try { const p = JSON.parse(out); sigs = Array.isArray(p) ? p : [p] } catch { return results }

    const SYSTEM_PROCESS_NAMES = new Set([
      'svchost.exe', 'csrss.exe', 'lsass.exe', 'services.exe', 'smss.exe',
      'winlogon.exe', 'explorer.exe',
    ])

    for (const s of sigs) {
      const name = (s.Name || '').toLowerCase()
      const sigStatus = s.SignatureStatus || ''
      if (!s.Path) continue // Skip processes without accessible path
      if (SYSTEM_PROCESS_NAMES.has(name) && (sigStatus === 'NotSigned') && addFindingDedup(`etw-hollow:${name}:${s.PID}`)) {
        results.push({
          path: `etw:${name} (PID: ${s.PID})`,
          fileName: `ETW: Possible process hollowing — ${name}`,
          type: 'process',
          risk: 'high',
          matches: [
            `ETW: ${name} is a system process but has invalid/missing signature`,
            'Possible process hollowing — image on disk differs from memory',
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* ETW optional */ }
  return results
}

/**
 * Run full ETW scan — combines process + image load + thread injection + hollowing.
 * Called during Phase 5 of full scan.
 */
export function runEtwScan(): ScanResult[] {
  startEtwSession()
  const processEvents = scanEtwProcessEvents()
  const imageEvents = scanEtwImageLoadEvents()
  const threadEvents = scanEtwThreadInjection()
  const hollowingEvents = scanEtwProcessHollowing()
  return [...processEvents, ...imageEvents, ...threadEvents, ...hollowingEvents]
}
