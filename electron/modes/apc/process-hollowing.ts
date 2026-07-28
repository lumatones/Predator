/**
 * Predator — APC Injection Detector: Tier 5 — Process Hollowing (RunPE)
 *
 * Detect Process Hollowing (RunPE) — the classic cheat injection technique.
 *
 * Process Hollowing workflow:
 *   1. CreateProcess(suspended) → spawn a legitimate process (e.g. svchost.exe)
 *   2. NtUnmapViewOfSection → remove the original executable from memory
 *   3. VirtualAllocEx → allocate new memory in the hollowed process
 *   4. WriteProcessMemory → write the cheat payload (cheat DLL loader)
 *   5. SetThreadContext → redirect entry point to payload
 *   6. ResumeThread → cheat code executes under a legitimate process name
 *
 * Detection via 6 sub-checks:
 *
 *   Check A: MODULE COUNT ANOMALY
 *     Hollowed processes have very few modules (original image unmapped).
 *     Normal GTA5.exe: 100-250 modules. Hollowed: <20 modules.
 *
 *   Check B: SYSTEM PROCESS PATH MISMATCH
 *     System-named processes (svchost, lsass, csrss) MUST run from System32.
 *
 *   Check C: GAME PROCESS FROM TEMP/DOWNLOADS
 *     Game processes running from temp/downloads/appdata directories.
 *
 *   Check D: PARENT-CHILD ANOMALY
 *     System processes with non-system parents → spawned for hollowing.
 *
 *   Check E: PEB PATH MISMATCH (StartInfo vs VAD)
 *     Compare WMI ExecutablePath (kernel's view) with MainModule.FileName
 *     (in-memory section object). If they differ, PEB ImageBaseAddress was
 *     patched to point to injected payload.
 *
 *   Check F: DISK vs MEMORY HASH (head + tail)
 *     Read first 8KB AND last 8KB of the on-disk EXE, read same regions
 *     from process memory via ReadProcessMemory, compare SHA256 for both.
 *     If EITHER region differs, the in-memory image was replaced.
 *     Covers hollowing techniques that leave PE header intact but
 *     patch the middle or overlay sections (e.g., .rsrc/.reloc at tail).
 */

import { execSync } from 'child_process'
import { addFindingDedup, type ScanResult } from '../../types'
import { getMonitoredProcessArgs, getMonitoredProcessWmiFilter } from '../../signature-registry'

export function scanProcessHollowing(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'

$results = @()

# ═══════════════════════════════════════════════════
# CHECK A: Module count anomaly in game processes
# ═══════════════════════════════════════════════════

$gameProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
foreach ($proc in $gameProcs) {
  try {
    $modCount = $proc.Modules.Count
    $procPath = try { $proc.MainModule.FileName } catch { '' }

    # Normal GTA5: 100-250 modules. Hollowed: <30 (original image unmapped)
    if ($modCount -gt 0 -and $modCount -lt 30) {
      $results += [PSCustomObject]@{
        PID = $proc.Id
        Name = $proc.Name
        Signal = 'HOLLOW:low-module-count'
        ProcPath = $procPath
        Detail = "$modCount modules (normal: 100-250 for $($proc.Name)). Original image likely unmapped."
        Risk = 'high'
      }
    } elseif ($modCount -gt 0 -and $modCount -lt 60) {
      $results += [PSCustomObject]@{
        PID = $proc.Id
        Name = $proc.Name
        Signal = 'HOLLOW:low-module-warning'
        ProcPath = $procPath
        Detail = "$modCount modules (normal: 100-250 for $($proc.Name)). Possible partial hollowing."
        Risk = 'medium'
      }
    }
  } catch {
    # Access denied — skip module check for this process
  }
}

# ═══════════════════════════════════════════════════
# CHECK B: System process path mismatch
# ═══════════════════════════════════════════════════

$systemProcesses = @{
  'svchost'   = 'C:\\Windows\\System32\\svchost.exe'
  'lsass'     = 'C:\\Windows\\System32\\lsass.exe'
  'csrss'     = 'C:\\Windows\\System32\\csrss.exe'
  'winlogon'  = 'C:\\Windows\\System32\\winlogon.exe'
  'services'  = 'C:\\Windows\\System32\\services.exe'
  'spoolsv'   = 'C:\\Windows\\System32\\spoolsv.exe'
  'smss'      = 'C:\\Windows\\System32\\smss.exe'
  'wininit'   = 'C:\\Windows\\System32\\wininit.exe'
}

foreach ($name in $systemProcesses.Keys) {
  $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
  foreach ($p in $procs) {
    try {
      $actualPath = $p.MainModule.FileName
      $expected = $systemProcesses[$name]
      if ($actualPath -and $expected -and $actualPath -ne $expected) {
        $results += [PSCustomObject]@{
          PID = $p.Id
          Name = $p.Name
          Signal = 'HOLLOW:system-path-mismatch'
          ProcPath = $actualPath
          Detail = "$($p.Name) running from WRONG path: $actualPath (expected: $expected). DEFINITE Process Hollowing."
          Risk = 'high'
        }
      }
    } catch {
      # Access denied — fall back to WMI ExecutablePath
      try {
        $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -Property ExecutablePath -ErrorAction SilentlyContinue
        $actualPath = $wmiProc.ExecutablePath
        $expected = $systemProcesses[$name]
        if ($actualPath -and $expected -and $actualPath -ne $expected) {
          $results += [PSCustomObject]@{
            PID = $p.Id
            Name = $p.Name
            Signal = 'HOLLOW:system-path-mismatch'
            ProcPath = $actualPath
            Detail = "$($p.Name) running from WRONG path: $actualPath (expected: $expected) [WMI fallback]. DEFINITE Process Hollowing."
            Risk = 'high'
          }
        }
      } catch { /* WMI also failed */ }
    }
  }
}

# ═══════════════════════════════════════════════════
# CHECK C: Game/system processes from suspicious dirs
# ═══════════════════════════════════════════════════

$suspiciousProcs = Get-Process -Name ${getMonitoredProcessArgs()}, svchost, lsass, csrss -ErrorAction SilentlyContinue
$suspiciousDirs = @('\\Temp\\', '\\Downloads\\', '\\AppData\\Local\\Temp\\',
                     '\\Desktop\\', '\\OneDrive\\Temp\\', '\\Public\\')

foreach ($proc in $suspiciousProcs) {
  try {
    $path = $proc.MainModule.FileName
    if (-not $path) { continue }
    
    $lower = $path.ToLower()
    foreach ($dir in $suspiciousDirs) {
      if ($lower.Contains($dir.ToLower())) {
        $results += [PSCustomObject]@{
          PID = $proc.Id
          Name = $proc.Name
          Signal = 'HOLLOW:suspicious-location'
          ProcPath = $path
          Detail = "$($proc.Name) running from suspicious directory: $path. Likely a hollowed copy."
          Risk = 'high'
        }
        break
      }
    }
  } catch { /* skip — access denied */ }
}

# ═══════════════════════════════════════════════════
# CHECK D: Parent-child anomaly (system procs)
# ═══════════════════════════════════════════════════

$expectedParents = @{
  'svchost' = @('services')
  'lsass'   = @('wininit')
  'spoolsv' = @('services')
}

foreach ($childName in $expectedParents.Keys) {
  $childProcs = Get-CimInstance Win32_Process -Filter "Name='$childName.exe'" \
    -Property ProcessId,ParentProcessId,Name,ExecutablePath -ErrorAction SilentlyContinue
  foreach ($cp in $childProcs) {
    $parentId = $cp.ParentProcessId
    if ($parentId -le 0) { continue }
    try {
      $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId=$parentId" \
        -Property Name -ErrorAction SilentlyContinue
      if ($parentProc) {
        $parentName = ($parentProc.Name -replace '\\.exe$', '')
        $expectedList = $expectedParents[$childName]
        if ($expectedList -and $parentName -notin $expectedList) {
          $results += [PSCustomObject]@{
            PID = $cp.ProcessId
            Name = ($cp.Name -replace '\\.exe$', '')
            Signal = 'HOLLOW:parent-anomaly'
            ProcPath = $cp.ExecutablePath
            Detail = "$($cp.Name) has unexpected parent: $parentName (expected: $($expectedList -join ', ')). Process spawned for hollowing."
            Risk = 'medium'
          }
        }
      }
    } catch { /* skip parent check */ }
  }
}

# ═══════════════════════════════════════════════════
# CHECK E: PEB path mismatch (ExecutablePath vs MainModule.FileName)
# ═══════════════════════════════════════════════════

$wmiProcs = Get-CimInstance Win32_Process -Filter "${getMonitoredProcessWmiFilter()}" \
  -Property ProcessId,Name,ExecutablePath,CommandLine -ErrorAction SilentlyContinue

foreach ($wp in $wmiProcs) {
  try {
    $wmiPath = $wp.ExecutablePath
    if (-not $wmiPath) { continue }

    $proc = Get-Process -Id $wp.ProcessId -ErrorAction SilentlyContinue
    $memPath = try { $proc.MainModule.FileName } catch { '' }

    if ($memPath -and $wmiPath -and $memPath -ne $wmiPath) {
      $results += [PSCustomObject]@{
        PID = $wp.ProcessId
        Name = ($wp.Name -replace '\\.exe$', '')
        Signal = 'HOLLOW:peb-path-mismatch'
        ProcPath = "Memory: $memPath | Disk: $wmiPath"
        Detail = "PEB ImageBaseAddress mismatch: in-memory section ($memPath) ≠ kernel executable path ($wmiPath). PEB patched by injector."
        Risk = 'high'
      }
    }
  } catch { /* access denied for this process */ }
}

# ═══════════════════════════════════════════════════
# CHECK F: Disk vs Memory hash comparison
# ═══════════════════════════════════════════════════

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
public class PredatorMemHash {
  [DllImport("kernel32.dll")]
  public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll")]
  public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
  [DllImport("kernel32.dll")]
  public static extern bool CloseHandle(IntPtr hObject);

  public const uint PROCESS_VM_READ = 0x0010;
  public const uint PROCESS_QUERY_INFORMATION = 0x0400;

  public static string ComputeSha256(byte[] data) {
    using (var sha = SHA256.Create()) {
      byte[] hash = sha.ComputeHash(data);
      return BitConverter.ToString(hash).Replace("-", "").ToLower();
    }
  }
}
'@

$checkableProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
foreach ($proc in $checkableProcs) {
  try {
    $diskPath = try { $proc.MainModule.FileName } catch { '' }
    if (-not $diskPath -or -not (Test-Path $diskPath)) { continue }

    $baseAddr = $proc.MainModule.BaseAddress
    $modSize = $proc.MainModule.ModuleMemorySize
    if ($baseAddr -eq [IntPtr]::Zero -or $modSize -le 0) { continue }

    $compareSize = [Math]::Min(8192, $modSize)

    # ── Read HEAD (first 8KB) from disk ──
    $diskHead = New-Object byte[] $compareSize
    try {
      $fs = [System.IO.File]::OpenRead($diskPath)
      $fs.Read($diskHead, 0, $compareSize) | Out-Null
      $fs.Close()
    } catch { continue }

    # ── Read TAIL (last 8KB) from disk ──
    $diskTail = $null
    $diskLen = (Get-Item $diskPath).Length
    $tailStartDisk = [Math]::Max(0, $diskLen - $compareSize)
    # Only read tail if it doesn't overlap with head (<8KB modules have overlap)
    if ($tailStartDisk -gt 0 -and $tailStartDisk -lt $diskLen -and $tailStartDisk -ge $compareSize) {
      $diskTail = New-Object byte[] $compareSize
      $fs = $null
      try {
        $fs = [System.IO.File]::OpenRead($diskPath)
        $fs.Seek($tailStartDisk, [System.IO.SeekOrigin]::Begin) | Out-Null
        $fs.Read($diskTail, 0, $compareSize) | Out-Null
      } catch { $diskTail = $null }
      finally { if ($fs) { $fs.Dispose() } }
    }

    # ── Open process handle once for both reads ──
    $hProcess = [PredatorMemHash]::OpenProcess(
      [PredatorMemHash]::PROCESS_VM_READ -bor [PredatorMemHash]::PROCESS_QUERY_INFORMATION,
      $false, $proc.Id)
    if ($hProcess -eq [IntPtr]::Zero) { continue }

    try {
      # ── Read HEAD from process memory ──
      $memHead = New-Object byte[] $compareSize
      $headRead = 0
      $hOk = [PredatorMemHash]::ReadProcessMemory($hProcess, $baseAddr, $memHead, $compareSize, [ref]$headRead)
      if (-not $hOk -or $headRead -lt 512) { continue }

      # ── Read TAIL from process memory ──
      $memTail = $null
      $tailStartMem = [Math]::Max(0, $modSize - 8192)
      if ($tailStartMem -gt 0) {
        $tailAddr = [IntPtr]::Add($baseAddr, $tailStartMem)
        $tailSize = [Math]::Min(8192, $modSize - $tailStartMem)
        $memTail = New-Object byte[] $tailSize
        $tailRead = 0
        try {
          $tOk = [PredatorMemHash]::ReadProcessMemory($hProcess, $tailAddr, $memTail, $tailSize, [ref]$tailRead)
          if (-not $tOk -or $tailRead -lt 256) { $memTail = $null }
        } catch { $memTail = $null }
      }

      # ── Compare HEAD hashes ──
      $headDiskHash = [PredatorMemHash]::ComputeSha256($diskHead)
      $headMemHash  = [PredatorMemHash]::ComputeSha256($memHead)
      $headDiffers = ($headDiskHash -ne $headMemHash)

      # ── Compare TAIL hashes (if we have both) ──
      $tailDiffers = $false
      $tailDiskHash = ''
      $tailMemHash  = ''
      if ($diskTail -and $memTail -and $memTail.Length -eq $diskTail.Length) {
        $tailDiskHash = [PredatorMemHash]::ComputeSha256($diskTail)
        $tailMemHash  = [PredatorMemHash]::ComputeSha256($memTail)
        $tailDiffers = ($tailDiskHash -ne $tailMemHash)
      }

      # ── Signal if EITHER region differs ──
      if ($headDiffers -or $tailDiffers) {
        $regions = @()
        if ($headDiffers) {
          $regions += "HEAD(0-8KB): disk=$headDiskHash mem=$headMemHash"
        }
        if ($tailDiffers) {
          $regions += "TAIL(last-8KB@$tailStartMem): disk=$tailDiskHash mem=$tailMemHash"
        }
        $regionDesc = $regions -join '; '

        $signalSuffix = ''
        if ($headDiffers -and $tailDiffers) { $signalSuffix = '-both' }
        elseif ($tailDiffers -and -not $headDiffers) { $signalSuffix = '-tail-only' }

        $results += [PSCustomObject]@{
          PID = $proc.Id
          Name = $proc.Name
          Signal = "HOLLOW:disk-memory-mismatch$signalSuffix"
          ProcPath = $diskPath
          Detail = "Memory image differs from disk: $regionDesc. DEFINITE Process Hollowing."
          Risk = 'high'
        }
      }
    } finally {
      [PredatorMemHash]::CloseHandle($hProcess) | Out-Null
    }
  } catch { /* access denied or protected process — skip */ }
}

if ($results.Count -gt 0) {
  $results | ConvertTo-Json -Compress
} else {
  Write-Output '[]'
}
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 15000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    let hits: {
      PID?: number; Name?: string; Signal?: string; ProcPath?: string
      Detail?: string; Risk?: string
    }[] = []
    try { const p = JSON.parse(out); hits = Array.isArray(p) ? p : [p] } catch { return results }

    for (const hit of hits) {
      const key = `hollow:${hit.Name}:${hit.PID}:${hit.Signal}`
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
        matches.push(
          '⚠ Process Hollowing: legitimate exe unmapped, cheat payload injected',
          '⚠ RunPE technique: CreateProcess(suspended) → NtUnmapViewOfSection → shellcode',
          '⚠ Original image section replaced — the process is NOT what the name says',
        )

        results.push({
          path: `process:${hit.Name} (PID: ${hit.PID})`,
          fileName: `⚠ Process Hollowing: ${hit.Name} — ${hit.Signal}`,
          type: 'process',
          risk,
          matches,
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* hollowing scan optional */ }

  return results
}
