/**
 * Predator — APC Injection Detector: Tier 6 — Reflective DLL Injection
 *
 * Detect Reflective DLL Injection — a stealth technique that loads a DLL
 * into a target process WITHOUT calling LoadLibrary, bypassing module
 * registration callbacks (PsSetLoadImageNotifyRoutine).
 *
 * Reflective DLL Injection workflow:
 *   1. VirtualAllocEx → allocate memory in target process
 *   2. WriteProcessMemory → write the DLL + reflective loader into that memory
 *   3. CreateRemoteThread → execute the reflective loader
 *   4. The loader parses its own PE headers, maps sections, resolves imports,
 *      fixes relocations — all in-memory, without touching the disk
 *   5. DllMain is called → cheat DLL is now running
 *
 * Because LoadLibrary is never called, the DLL doesn't appear in:
 *   - PsSetLoadImageNotifyRoutine callbacks (bypasses EDR/AC module monitoring)
 *   - Process Environment Block (PEB) Ldr lists
 *   - Get-Process.Modules (in some implementations)
 *
 * However, most reflective loaders DO register the module in the PEB
 * after loading — which means Get-Process.Modules WILL list them.
 * The key indicators are:
 *
 *   Check A: DISK FILE DOESN'T EXIST (PHANTOM MODULE)
 *     Module is loaded in process, but its FileName points to a
 *     file that doesn't exist on disk → DEFINITE reflective injection.
 *     Normal DLLs always have a valid disk backing.
 *
 *   Check B: MODULE FROM SUSPICIOUS LOCATION
 *     Module's FileName points to Temp/Downloads/AppData/Desktop →
 *     DLL was dropped there by the injector. Legitimate game DLLs
 *     are in the game directory or System32.
 *
 *   Check C: MISMATCHED MODULE NAME vs PATH
 *     Module.ModuleName claims to be a system DLL (e.g. "kernel32.dll")
 *     but the FileName is NOT in System32 → reflective loader patched
 *     the module name to hide the real DLL identity.
 *
 *   Check D: ORPHANED HANDLE MODULE
 *     Module has empty FileName or "Unknown" → loaded via
 *     NtMapViewOfSection from a handle that has no disk path.
 *     Common in manual-map injectors.
 *
 *   Check E: MZ HEADER SCAN (in-memory PE signature vs disk)
 *     Reads first 2 bytes from each module's base address via
 *     ReadProcessMemory, checks for MZ (0x4D 0x5A) magic bytes,
 *     then compares with the disk file's MZ header. If the
 *     disk file doesn't exist OR the in-memory MZ differs →
 *     the module was loaded via reflective injection (memory
 *     image doesn't match any valid disk-backed PE).
 */

import { execSync } from 'child_process'
import { addFindingDedup, type ScanResult } from '../../types'
import { getMonitoredProcessArgs } from '../../signature-registry'

export function scanReflectiveDll(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'

$results = @()

# ═══════════════════════════════════════════════════
# CHECK A: Phantom modules — loaded but no disk file
# ═══════════════════════════════════════════════════
# Reflective DLLs are written into process memory directly,
# they never touch the disk. If a module claims a FileName
# but the file doesn't exist → loaded via reflective loader.

$gameProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
foreach ($proc in $gameProcs) {
  # Skip if process has exited
  if ($proc.HasExited) { continue }

  try {
    $modules = $proc.Modules
  } catch {
    # Access denied (protected process) — skip
    continue
  }

  $phantomCount = 0
  $phantomDetails = @()

  foreach ($mod in $modules) {
    try {
      $modPath = $mod.FileName
      $modName = $mod.ModuleName
    } catch {
      # Module disappeared between enumeration and property access
      continue
    }

    # Skip modules with no path (kernel-mapped sections)
    if (-not $modPath -or $modPath -eq '' -or $modPath -eq 'Unknown') {
      $phantomCount++
      $phantomDetails += [PSCustomObject]@{
        ModuleName = if ($modName) { $modName } else { '<unnamed>' }
        FileName = '<no disk path>'
        Reason = 'Memory-only module (no FileName) — NtMapViewOfSection from handle'
      }
      continue
    }

    # Check if the file actually exists on disk (faster than Test-Path)
    if (-not [System.IO.File]::Exists($modPath)) {
      $phantomCount++
      $phantomDetails += [PSCustomObject]@{
        ModuleName = if ($modName) { $modName } else { '<unnamed>' }
        FileName = $modPath
        Reason = "Claimed file does NOT exist on disk — reflective DLL"
      }
    }
  }

  if ($phantomCount -gt 0) {
    $detailList = ($phantomDetails | ForEach-Object {
      "$($_.ModuleName) @ $($_.FileName): $($_.Reason)"
    }) -join '; '

    # Escalate: 3+ phantoms = critical, 2 = high, 1 = medium
    # Rationale: a single phantom might be a COM DLL loaded via
    # CoCreateInstance from a handle, but 3+ = injection campaign
    if ($phantomCount -ge 3) {
      $risk = 'high'
      $signal = 'RDI:phantom-modules-critical'
    } elseif ($phantomCount -ge 2) {
      $risk = 'high'
      $signal = 'RDI:phantom-modules'
    } else {
      $risk = 'medium'
      $signal = 'RDI:phantom-module'
    }

    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = $signal
      ProcPath = try { $proc.MainModule.FileName } catch { '' }
      Detail = "$phantomCount modules with no valid disk backing. $detailList"
      Risk = $risk
    }
  }
}

# ═══════════════════════════════════════════════════
# CHECK B: Modules from suspicious directories
# ═══════════════════════════════════════════════════
# Reflective injectors often drop the DLL to Temp/Downloads
# before injecting. Even if LoadLibrary is used, the source
# location is suspicious.

$tempProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
$suspiciousDirs = @(
  '\\Temp\\', '\\Downloads\\', '\\AppData\\Local\\Temp\\',
  '\\Desktop\\', '\\OneDrive\\Temp\\', '\\Public\\',
  '\\AppData\\Roaming\\', '\\cache\\', '\\CrashDumps\\'
)

foreach ($proc in $tempProcs) {
  if ($proc.HasExited) { continue }

  try {
    $modules = $proc.Modules
  } catch { continue }

  $susMods = @()
  foreach ($mod in $modules) {
    try {
      $modPath = $mod.FileName
      $modName = $mod.ModuleName
    } catch { continue }

    if (-not $modPath -or $modPath -eq '' -or $modPath -eq 'Unknown') { continue }

    $lower = $modPath.ToLower()
    foreach ($dir in $suspiciousDirs) {
      if ($lower.Contains($dir.ToLower())) {
        # Don't flag if this is the MAIN module (the exe itself) —
        # we already detect game-from-temp in process hollowing Tier 5
        $isMainModule = $false
        try {
          $mainPath = $proc.MainModule.FileName
          if ($mainPath -and $modPath -eq $mainPath) { $isMainModule = $true }
        } catch {}

        if (-not $isMainModule) {
          $susMods += "$modName @ $modPath"
        }
        break
      }
    }
  }

  if ($susMods.Count -gt 0) {
    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = 'RDI:suspicious-module-location'
      ProcPath = try { $proc.MainModule.FileName } catch { '' }
      Detail = "$($susMods.Count) module(s) loaded from temp/downloads: $($susMods -join ', ')"
      Risk = if ($susMods.Count -ge 2) { 'high' } else { 'medium' }
    }
  }
}

# ═══════════════════════════════════════════════════
# CHECK C: Masquerading modules (name ≠ expected path)
# ═══════════════════════════════════════════════════
# Reflective loaders can patch the module name in PEB's Ldr list
# to impersonate a legitimate system DLL. Example:
#   ModuleName = "kernel32.dll"  ← looks legit
#   FileName   = "C:\\Temp\\cheat.dll"  ← actually a cheat DLL
#
# We detect this by checking that system32-named modules
# are actually loaded from System32/SysWOW64.

$systemDllPrefixes = @(
  'ntdll', 'kernel32', 'kernelbase', 'user32', 'gdi32',
  'advapi32', 'shell32', 'ole32', 'oleaut32', 'combase',
  'comctl32', 'ws2_32', 'shlwapi', 'rpcrt4', 'sechost',
  'winhttp', 'wininet', 'crypt32', 'bcrypt', 'ncrypt',
  'd3d9', 'd3d11', 'd3d12', 'dxgi', 'dinput8', 'xinput',
  'msvcp', 'msvcr', 'vcruntime', 'ucrtbase', 'imm32',
  'dbghelp', 'psapi', 'version', 'setupapi', 'wldap32'
)

$masqProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
foreach ($proc in $masqProcs) {
  if ($proc.HasExited) { continue }

  try {
    $modules = $proc.Modules
  } catch { continue }

  $masqMods = @()
  foreach ($mod in $modules) {
    try {
      $modPath = $mod.FileName
      $modName = $mod.ModuleName
    } catch { continue }

    if (-not $modPath -or -not $modName) { continue }

    # Extract the base name without .dll extension
    $baseName = if ($modName -match '^(.+)\\.dll$') { $matches[1] } else { $modName }

    # Check if the module name matches a known system DLL
    $matchedPrefix = $null
    foreach ($prefix in $systemDllPrefixes) {
      if ($baseName -eq $prefix) {
        $matchedPrefix = $prefix
        break
      }
    }
    if (-not $matchedPrefix) { continue }

    # System DLLs should be in System32 or SysWOW64
    $lowerPath = $modPath.ToLower()
    $isSystemPath = ($lowerPath -like '*\\system32\\*') -or
                    ($lowerPath -like '*\\syswow64\\*') -or
                    ($lowerPath -like '*\\winsxs\\*')

    if (-not $isSystemPath) {
      $masqMods += "IMPERSONATING $modName → actual path: $modPath"
    }
  }

  if ($masqMods.Count -gt 0) {
    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = 'RDI:masquerading-module'
      ProcPath = try { $proc.MainModule.FileName } catch { '' }
      Detail = "$($masqMods.Count) module(s) impersonating system DLLs: $($masqMods -join '; ')"
      Risk = 'high'
    }
  }
}

# ═══════════════════════════════════════════════════
# CHECK D: Orphaned handles — modules with no identity
# ═══════════════════════════════════════════════════
# Manual-map injectors use NtCreateSection + NtMapViewOfSection
# to create a section backed by the paging file (no disk file).
# These appear as modules with empty/missing ModuleName and no
# valid FileName. They're the hardest to detect but the most
# dangerous — completely invisible to file-based scanners.

$orphanProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
if (-not $orphanProcs) { $orphanProcs = @() }
foreach ($proc in $orphanProcs) {
  if (-not $proc -or $proc.HasExited) { continue }

  try {
    $modules = $proc.Modules
  } catch { continue }

  $orphanCount = 0
  $orphanMods = @()

  foreach ($mod in $modules) {
    try {
      $modPath = $mod.FileName
      $modName = $mod.ModuleName
      $modBase = $mod.BaseAddress
      $modSize = $mod.ModuleMemorySize
    } catch { continue }

    # Orphan: has a base address + size but no name AND no path
    # This is a manual-mapped section — NtMapViewOfSection from paging file
    if ((-not $modName -or $modName -eq '') -and
        (-not $modPath -or $modPath -eq '' -or $modPath -eq 'Unknown') -and
        $modBase -ne [IntPtr]::Zero -and $modSize -gt 4096) {
      $orphanCount++
      $orphanMods += [PSCustomObject]@{
        BaseAddress = "0x$($modBase.ToInt64().ToString('X'))"
        Size = "$([Math]::Round($modSize / 1024, 1))KB"
      }
    }
  }

  if ($orphanCount -gt 0) {
    $detailList = ($orphanMods | ForEach-Object {
      "Mystery section @ $($_.BaseAddress) ($($_.Size))"
    }) -join '; '

    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = 'RDI:orphaned-memory-section'
      ProcPath = try { $proc.MainModule.FileName } catch { '' }
      Detail = "$orphanCount nameless memory section(s): $detailList. Manual-map injection likely."
      Risk = if ($orphanCount -ge 3) { 'high' } else { 'medium' }
    }
  }
}

# ═══════════════════════════════════════════════════
# CHECK E: MZ header scan — in-memory PE signature vs disk
# ═══════════════════════════════════════════════════
# Reads the first 2 bytes (MZ magic) from each loaded module's
# base address via ReadProcessMemory, and compares with the
# disk file's MZ header. This catches reflective DLLs whose
# in-memory image differs from any disk file — the definitive
# signature of a DLL loaded without LoadLibrary.

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class PredatorMzScan {
  [DllImport("kernel32.dll")]
  public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll")]
  public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
  [DllImport("kernel32.dll")]
  public static extern bool CloseHandle(IntPtr hObject);

  public const uint PROCESS_VM_READ = 0x0010;
  public const uint PROCESS_QUERY_INFORMATION = 0x0400;

  public static bool IsMzHeader(byte[] bytes) {
    return bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A;
  }
}
'@

$mzProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
if (-not $mzProcs) { $mzProcs = @() }

foreach ($proc in $mzProcs) {
  if (-not $proc -or $proc.HasExited) { continue }

  # Open process handle once per game process
  $hProcess = [PredatorMzScan]::OpenProcess(
    [PredatorMzScan]::PROCESS_VM_READ -bor [PredatorMzScan]::PROCESS_QUERY_INFORMATION,
    $false, $proc.Id)
  if ($hProcess -eq [IntPtr]::Zero) { continue }

  try {
    $modules = $proc.Modules
  } catch {
    [PredatorMzScan]::CloseHandle($hProcess) | Out-Null
    continue
  }

  $mzMismatchCount = 0
  $mzMismatchMods = @()
  # Bail out after 10 hits to keep scan fast
  $mzBailout = $false

  foreach ($mod in $modules) {
    if ($mzBailout) { break }

    try {
      $modPath = $mod.FileName
      $modName = $mod.ModuleName
      $modBase = $mod.BaseAddress
      $modSize = $mod.ModuleMemorySize
    } catch { continue }

    # Skip tiny modules (<4KB — not real PE images)
    if ($modBase -eq [IntPtr]::Zero -or $modSize -le 4096) { continue }

    # ── Step 1: Read MZ magic from process memory ──
    $memBytes = New-Object byte[] 2
    $bytesRead = 0
    $readOk = [PredatorMzScan]::ReadProcessMemory($hProcess, $modBase, $memBytes, 2, [ref]$bytesRead)
    if (-not $readOk -or $bytesRead -lt 2) { continue }

    # Check for MZ header in memory
    $inMemoryIsMz = [PredatorMzScan]::IsMzHeader($memBytes)
    if (-not $inMemoryIsMz) { continue }  # Not a PE — skip (could be data section)

    # ── Step 2: Compare with disk file's MZ header ──
    $diskExists = $false
    $diskIsMz = $false

    if ($modPath -and $modPath -ne '' -and $modPath -ne 'Unknown' -and [System.IO.File]::Exists($modPath)) {
      $diskExists = $true
      $fs = $null
      try {
        $fs = [System.IO.File]::OpenRead($modPath)
        $diskBytes = New-Object byte[] 2
        $fs.Read($diskBytes, 0, 2) | Out-Null
        $diskIsMz = [PredatorMzScan]::IsMzHeader($diskBytes)
      } catch {}
      finally { if ($fs) { $fs.Dispose() } }
    }

    # ── Step 3: Decision logic ──
    if (-not $diskExists) {
      # Memory has MZ but disk file doesn't exist → reflective DLL
      $mzMismatchCount++
      $mzMismatchMods += [PSCustomObject]@{
        Module = if ($modName) { $modName } else { '<unnamed>' }
        BaseAddr = "0x$($modBase.ToInt64().ToString('X'))"
        Reason = "MZ header in memory but NO disk file — reflective DLL"
      }
    } elseif (-not $diskIsMz) {
      # Disk file exists but doesn't have MZ header (not a PE) →
      # the in-memory image has a PE that doesn't match any real file
      $mzMismatchCount++
      $mzMismatchMods += [PSCustomObject]@{
        Module = if ($modName) { $modName } else { '<unnamed>' }
        BaseAddr = "0x$($modBase.ToInt64().ToString('X'))"
        Reason = "MZ in memory but disk file is NOT a valid PE — memory injection"
      }
    } elseif ($diskBytes[0] -ne $memBytes[0] -or $diskBytes[1] -ne $memBytes[1]) {
      # Both are MZ but the bytes differ → same module name, different binary
      $mzMismatchCount++
      $mzMismatchMods += [PSCustomObject]@{
        Module = if ($modName) { $modName } else { '<unnamed>' }
        BaseAddr = "0x$($modBase.ToInt64().ToString('X'))"
        Reason = "MZ bytes differ: mem=$($memBytes[0].ToString('X2'))$($memBytes[1].ToString('X2')) disk=$($diskBytes[0].ToString('X2'))$($diskBytes[1].ToString('X2')) — DLL was replaced"
      }
    }

    # Bail out after 10 mismatches to avoid flooding results
    if ($mzMismatchCount -ge 10) { $mzBailout = $true }
  }

  [PredatorMzScan]::CloseHandle($hProcess) | Out-Null

  if ($mzMismatchCount -gt 0) {
    $detailList = ($mzMismatchMods | ForEach-Object {
      "$($_.Module) @ $($_.BaseAddr): $($_.Reason)"
    }) -join '; '

    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = if ($mzMismatchCount -ge 5) { 'RDI:mz-mismatch-critical' } else { 'RDI:mz-mismatch' }
      ProcPath = try { $proc.MainModule.FileName } catch { '' }
      HitCount = $mzMismatchCount
      Detail = "$mzMismatchCount module(s) with MZ header mismatch (in-memory ≠ disk). $detailList"
      Risk = if ($mzMismatchCount -ge 3) { 'high' } else { 'medium' }
    }
  }
}

if ($results.Count -gt 0) {
  $results | ConvertTo-Json -Compress
} else {
  Write-Output '[]'
}
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 12000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    let hits: {
      PID?: number; Name?: string; Signal?: string; ProcPath?: string
      Detail?: string; Risk?: string; HitCount?: number
    }[] = []
    try { const p = JSON.parse(out); hits = Array.isArray(p) ? p : [p] } catch { return results }

    for (const hit of hits) {
      const key = `rdi:${hit.Name}:${hit.PID}:${hit.Signal}`
      if (addFindingDedup(key)) {
        const risk: 'high' | 'medium' =
          hit.Risk === 'high' ? 'high' : 'medium'

        const matches: string[] = [
          hit.Detail || '',
          `Signal: ${hit.Signal}`,
        ]
        if (hit.ProcPath) {
          matches.push(`Process path: ${hit.ProcPath}`)
        }
        // Add attack-vector explanations based on signal type
        if (hit.Signal?.includes('phantom')) {
          matches.push(
            '⚠ Phantom module: loaded in memory but disk file does not exist',
            '⚠ Reflective DLL loader: VirtualAllocEx → WriteProcessMemory → CreateRemoteThread',
            '⚠ Bypasses PsSetLoadImageNotifyRoutine — EDR/AC never sees this DLL load',
          )
        } else if (hit.Signal?.includes('suspicious')) {
          matches.push(
            '⚠ DLL loaded from temp/downloads — likely dropped by injector',
            '⚠ Legitimate game DLLs are loaded from the game directory or System32',
          )
        } else if (hit.Signal?.includes('masquerading')) {
          matches.push(
            '⚠ Module name impersonates a system DLL — PEB Ldr list was patched',
            '⚠ Reflective loader overwrites BaseDllName to hide the real cheat DLL',
          )
        } else if (hit.Signal?.includes('orphaned')) {
          matches.push(
            '⚠ Manual-map injection: section backed by paging file, no disk identity',
            '⚠ NtCreateSection(SEC_COMMIT) → NtMapViewOfSection → shellcode',
            '⚠ Completely invisible to file-based scanners',
          )
        } else if (hit.Signal?.includes('mz-mismatch')) {
          matches.push(
            '⚠ MZ header mismatch: in-memory PE signature differs from disk file',
            '⚠ ReadProcessMemory confirms MZ magic bytes at base address',
            '⚠ DLL was loaded reflectively — memory image ≠ any valid disk-backed PE',
          )
        }
        matches.push(
          '⚠ Reflective DLL Injection: LoadLibrary bypassed, module monitors blind',
        )

        results.push({
          path: `process:${hit.Name} (PID: ${hit.PID})`,
          fileName: `⚠ Reflective DLL Injection: ${hit.Name} — ${hit.Signal}`,
          type: 'process',
          risk,
          matches,
          size: hit.HitCount || 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* reflective DLL scan optional */ }

  return results
}
