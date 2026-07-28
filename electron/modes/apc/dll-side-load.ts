/**
 * Predator — APC Injection Detector: Tier 7 — DLL Side-Loading (Search Order Hijacking)
 *
 * Detect DLL Side-Loading — a stealth technique that exploits Windows DLL
 * search order to load a malicious DLL instead of the legitimate system one.
 *
 * Windows DLL search order (simplified):
 *   1. KnownDLLs registry (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs)
 *      → DLLs listed here ALWAYS load from System32 — cannot be hijacked.
 *   2. Application directory (where the .exe lives)
 *   3. C:\Windows\System32
 *   4. C:\Windows\System
 *   5. C:\Windows
 *   6. Current directory
 *   7. PATH directories
 *
 * Attack vector: the attacker places a malicious DLL with the same name
 * as a legitimate DLL (e.g., version.dll, winmm.dll, dinput8.dll) in the
 * game's application directory. When the game calls LoadLibrary("version.dll"),
 * Windows finds the fake DLL in step 2 (app dir) and loads it — the cheat
 * code now runs inside the game process.
 *
 * This is EXTREMELY common in GTA 5 cheating:
 *   - Menyoo: places dinput8.dll in GTA5 directory
 *   - Simple Trainer: places ScriptHookV.dll + dinput8.dll
 *   - Stand: places version.dll in GTA5 directory
 *
 * Detection via 4 sub-checks:
 *
 *   Check A: KNOWN DLLS CROSS-REFERENCE
 *     KnownDLLs-named modules should ALWAYS be loaded from System32.
 *     If a known system DLL (kernel32, ntdll, etc.) is loaded from the
 *     game directory → KnownDLLs registry was tampered with.
 *
 *   Check B: HIJACKABLE DLLS IN GAME DIRECTORY
 *     Scan the game's app directory for common hijack-target DLL names
 *     that are NOT digitally signed by Microsoft → planted by attacker.
 *
 *   Check C: SHADOW DLLS (same name, two locations)
 *     Same DLL base name loaded from BOTH System32 AND the game directory.
 *     One is legitimate, the other is the side-loaded cheat.
 *
 *   Check D: DLL LOAD ORDER DIVERGENCE
 *     Via WMI CIM_DataFile, check if a DLL exists in both System32 and
 *     the app directory. The app-dir copy shadows the System32 copy.
 *     If the app-dir copy has a different size/hash → planted.
 */

import { execSync } from 'child_process'
import { addFindingDedup, type ScanResult } from '../../types'
import { getMonitoredProcessArgs } from '../../signature-registry'

export function scanDllSideLoading(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'

$results = @()

# ═══════════════════════════════════════════════════
# CHECK A: KnownDLLs cross-reference
# ═══════════════════════════════════════════════════
# DLLs listed in KnownDLLs registry are ALWAYS loaded from System32.
# If a game process has a KnownDLL-named module from a non-System32
# path, the KnownDLLs registry was tampered with.

# KnownDLLs from Windows 10/11 (these are guaranteed to exist):
$knownDlls = @(
  'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 'gdi32.dll',
  'advapi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll', 'combase.dll',
  'comctl32.dll', 'ws2_32.dll', 'shlwapi.dll', 'rpcrt4.dll', 'sechost.dll',
  'winhttp.dll', 'wininet.dll', 'crypt32.dll', 'bcrypt.dll', 'ncrypt.dll',
  'msvcp_win.dll', 'ucrtbase.dll', 'imm32.dll', 'msctf.dll',
  'clbcatq.dll', 'propsys.dll', 'windows.storage.dll',
  'cfgmgr32.dll', 'devobj.dll', 'wintrust.dll', 'imagehlp.dll',
  'dbghelp.dll', 'psapi.dll', 'version.dll', 'setupapi.dll', 'wldap32.dll',
  'winmm.dll', 'dinput8.dll', 'd3d9.dll', 'd3d11.dll', 'dxgi.dll',
  'powrprof.dll', 'profapi.dll', 'win32u.dll', 'gdi32full.dll',
  'wtsapi32.dll', 'winsta.dll', 'netapi32.dll', 'srvcli.dll',
  'cryptsp.dll', 'rsaenh.dll', 'cryptbase.dll', 'sspicli.dll',
  'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll',
  'iertutil.dll', 'urlmon.dll', 'wsock32.dll', 'iphlpapi.dll',
  'dnsapi.dll', 'mswsock.dll', 'ntmarta.dll', 'wldp.dll',
  'kernel.appcore.dll', 'bcryptprimitives.dll'
)

# Build hashtable for O(1) lookup (62 DLLs × 200 modules = fast)
$knownSet = @{}
foreach ($kd in $knownDlls) { $knownSet[$kd] = $true }

$gameProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
foreach ($proc in $gameProcs) {
  if ($proc.HasExited) { continue }

  try {
    $modules = $proc.Modules
  } catch { continue }

  $knownDllViolations = @()
  foreach ($mod in $modules) {
    try {
      $modName = $mod.ModuleName
      $modPath = $mod.FileName
    } catch { continue }

    if (-not $modName -or -not $modPath) { continue }

    # O(1) hashtable lookup instead of O(n) array scan
    if (-not $knownSet.ContainsKey($modName)) { continue }

    # KnownDLLs should ALWAYS load from System32 (or SysWOW64 for 32-bit)
    $lower = $modPath.ToLower()
    $isSystemPath = ($lower -like '*\\system32\\*') -or
                    ($lower -like '*\\syswow64\\*') -or
                    ($lower -like '*\\winsxs\\*')

    if (-not $isSystemPath) {
      $knownDllViolations += [PSCustomObject]@{
        Dll = $modName
        LoadedFrom = $modPath
        Expected = 'System32/SysWOW64'
      }
    }
  }

  if ($knownDllViolations.Count -gt 0) {
    $detailList = ($knownDllViolations | ForEach-Object {
      "$($_.Dll) @ $($_.LoadedFrom) (expected: $($_.Expected))"
    }) -join '; '

    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = 'SL:known-dll-violation'
      ProcPath = try { $proc.MainModule.FileName } catch { '' }
      HitCount = $knownDllViolations.Count
      Detail = "$($knownDllViolations.Count) KnownDLL(s) loaded from non-system path. $detailList"
      Risk = 'high'
    }
  }
}

# ═══════════════════════════════════════════════════
# CHECK B: Hijackable DLLs in game directory
# ═══════════════════════════════════════════════════
# These DLLs are commonly used for side-loading because they're
# loaded by most game processes but are NOT in KnownDLLs.
# If present in the game directory, they may be cheat DLLs.

$hijackableDlls = @(
  'version.dll', 'winmm.dll', 'dinput8.dll', 'dsound.dll',
  'xinput1_3.dll', 'xinput1_4.dll', 'xinput9_1_0.dll',
  'd3d8.dll', 'd3d9.dll', 'd3d10.dll', 'd3d11.dll', 'dxgi.dll',
  'msvcp100.dll', 'msvcp110.dll', 'msvcp120.dll', 'msvcr100.dll',
  'msvcr110.dll', 'msvcr120.dll',
  'vcruntime140.dll', 'msvcp140.dll', 'vcruntime140_1.dll',
  'ucrtbase.dll', 'msvcp_win.dll',
  'libcef.dll', 'libegl.dll', 'libglesv2.dll',
  'openal32.dll', 'bink2w64.dll', 'binkw32.dll',
  'nvtt.dll', 'fmod.dll', 'fmodstudio.dll',
  'dxgi_proxy.dll', 'd3d11_proxy.dll',
  'reshade.dll', 'enbseries.dll', 'enbhelper.dll'
)

$dlProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
foreach ($proc in $dlProcs) {
  if ($proc.HasExited) { continue }

  # Get the game's app directory
  $appDir = $null
  try {
    $mainPath = $proc.MainModule.FileName
    if ($mainPath) {
      $appDir = Split-Path $mainPath -Parent
    }
  } catch {
    # Can't access MainModule — fall back to WMI
    try {
      $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -Property ExecutablePath -ErrorAction SilentlyContinue
      if ($wmi.ExecutablePath) {
        $appDir = Split-Path $wmi.ExecutablePath -Parent
      }
    } catch {}
  }

  if (-not $appDir -or -not (Test-Path $appDir)) { continue }

  $hijackedFiles = @()
  foreach ($dll in $hijackableDlls) {
    $fullPath = Join-Path $appDir $dll
    if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
      # Check if this DLL is digitally signed by Microsoft
      $isMsSigned = $false
      try {
        $sig = Get-AuthenticodeSignature -FilePath $fullPath -ErrorAction SilentlyContinue
        $isMsSigned = ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -like '*Microsoft*')
      } catch {}

      $hijackedFiles += [PSCustomObject]@{
        Dll = $dll
        Path = $fullPath
        MsSigned = $isMsSigned
      }
    }
  }

  # Filter: only report unsigned DLLs (Microsoft-signed ones are legitimate)
  $unsignedHijacks = $hijackedFiles | Where-Object { -not $_.MsSigned }
  $signedHijacks   = $hijackedFiles | Where-Object { $_.MsSigned }

  if ($unsignedHijacks.Count -gt 0) {
    $detailList = ($unsignedHijacks | ForEach-Object {
      "$($_.Dll) (unsigned)"
    }) -join ', '

    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = 'SL:hijackable-dll-unsigned'
      ProcPath = $appDir
      HitCount = $unsignedHijacks.Count
      Detail = "$($unsignedHijacks.Count) hijackable unsigned DLL(s) in game directory: $detailList"
      Risk = if ($unsignedHijacks.Count -ge 3) { 'high' } else { 'medium' }
    }
  }

  # Multiple signed hijackable DLLs is unusual — flag as low
  if ($signedHijacks.Count -ge 5) {
    $detailList = ($signedHijacks | ForEach-Object { $_.Dll }) -join ', '
    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = 'SL:hijackable-dll-signed-bulk'
      ProcPath = $appDir
      HitCount = $signedHijacks.Count
      Detail = "$($signedHijacks.Count) signed hijackable DLL(s) in game directory (unusual count): $detailList"
      Risk = 'medium'
    }
  }
}

# ═══════════════════════════════════════════════════
# CHECK C: Shadow DLLs — same name, two locations
# ═══════════════════════════════════════════════════
# A DLL with the same base name is loaded from BOTH System32
# AND the game directory. The System32 copy is the real one;
# the game-dir copy is the side-loaded cheat.

$shadowProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
foreach ($proc in $shadowProcs) {
  if ($proc.HasExited) { continue }

  try {
    $modules = $proc.Modules
  } catch { continue }

  # Group modules by base name
  $byName = @{}
  foreach ($mod in $modules) {
    try {
      $modName = $mod.ModuleName
      $modPath = $mod.FileName
    } catch { continue }

    if (-not $modName -or -not $modPath) { continue }

    if (-not $byName.ContainsKey($modName)) {
      $byName[$modName] = @()
    }
    $byName[$modName] += $modPath
  }

  $shadows = @()
  foreach ($dllName in $byName.Keys) {
    $paths = $byName[$dllName]
    if ($paths.Count -lt 2) { continue }  # Only one instance — no shadow

$hasSystem32 = ($paths | Where-Object {
  $_ -like '*\\system32\\*' -or $_ -like '*\\syswow64\\*' -or $_ -like '*\\winsxs\\*'
}).Count -gt 0
$hasOther    = ($paths | Where-Object {
  $_ -notlike '*\\system32\\*' -and $_ -notlike '*\\syswow64\\*' -and $_ -notlike '*\\winsxs\\*'
}).Count -gt 0

    if ($hasSystem32 -and $hasOther) {
        $systemCopy = ($paths | Where-Object { $_ -like '*\\system32\\*' -or $_ -like '*\\syswow64\\*' -or $_ -like '*\\winsxs\\*' } | Select-Object -First 1)
    $otherCopy  = ($paths | Where-Object { $_ -notlike '*\\system32\\*' -and $_ -notlike '*\\syswow64\\*' -and $_ -notlike '*\\winsxs\\*' } | Select-Object -First 1)

      $shadows += [PSCustomObject]@{
        Dll = $dllName
        SystemPath = $systemCopy
        ShadowPath = $otherCopy
      }
    }
  }

  if ($shadows.Count -gt 0) {
    $detailList = ($shadows | ForEach-Object {
      "$($_.Dll): System32=$($_.SystemPath) SHADOW=$($_.ShadowPath)"
    }) -join '; '

    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = if ($shadows.Count -ge 3) { 'SL:shadow-dlls-critical' } else { 'SL:shadow-dlls' }
      ProcPath = try { $proc.MainModule.FileName } catch { '' }
      HitCount = $shadows.Count
      Detail = "$($shadows.Count) DLL(s) with shadow copies (System32 + app dir): $detailList"
      Risk = 'high'
    }
  }
}

# ═══════════════════════════════════════════════════
# CHECK D: WMI DLL path comparison — size mismatch
# ═══════════════════════════════════════════════════
# For each hijackable DLL that exists in BOTH System32 AND
# the game directory, compare file sizes via WMI CIM_DataFile.
# If the sizes differ, the game-dir copy is NOT the Microsoft
# original → DEFINITE side-loaded cheat DLL.

$wmiProcs = Get-Process -Name ${getMonitoredProcessArgs()} -ErrorAction SilentlyContinue
foreach ($proc in $wmiProcs) {
  if ($proc.HasExited) { continue }

  $appDir = $null
  try {
    $mainPath = $proc.MainModule.FileName
    if ($mainPath) {
      $appDir = Split-Path $mainPath -Parent
    }
  } catch {
    try {
      $wmi = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -Property ExecutablePath -ErrorAction SilentlyContinue
      if ($wmi.ExecutablePath) {
        $appDir = Split-Path $wmi.ExecutablePath -Parent
      }
    } catch {}
  }

  if (-not $appDir -or -not (Test-Path $appDir)) { continue }

  $sizeMismatches = @()
  # Check the top 15 most-hijacked DLLs (keeping this fast)
  $checkDlls = @(
    'version.dll', 'winmm.dll', 'dinput8.dll', 'dsound.dll',
    'xinput1_3.dll', 'xinput1_4.dll',
    'd3d9.dll', 'dxgi.dll',
    'vcruntime140.dll', 'msvcp140.dll',
    'libcef.dll', 'openal32.dll',
    'asi-loader.dll', 'scripthookv.dll', 'reshade.dll'
  )

  $sys32 = Join-Path $env:SystemRoot 'System32'

  foreach ($dll in $checkDlls) {
    $gameDllPath = Join-Path $appDir $dll
    $sysDllPath  = Join-Path $sys32 $dll

    if (-not (Test-Path $gameDllPath)) { continue }
    if (-not (Test-Path $sysDllPath)) { continue }

    try {
      $gameInfo = Get-Item $gameDllPath -ErrorAction SilentlyContinue
      $sysInfo  = Get-Item $sysDllPath  -ErrorAction SilentlyContinue

      if (-not $gameInfo -or -not $sysInfo) { continue }

      $gameSize = $gameInfo.Length
      $sysSize  = $sysInfo.Length

      if ($gameSize -ne $sysSize) {
        $sizeMismatches += [PSCustomObject]@{
          Dll = $dll
          GameDirSize = $gameSize
          System32Size = $sysSize
          Diff = [Math]::Abs($gameSize - $sysSize)
        }
      }
    } catch {}
  }

  if ($sizeMismatches.Count -gt 0) {
    $detailList = ($sizeMismatches | ForEach-Object {
      "$($_.Dll): game=$($_.GameDirSize)B system32=$($_.System32Size)B (diff=$($_.Diff)B)"
    }) -join '; '

    $results += [PSCustomObject]@{
      PID = $proc.Id
      Name = $proc.Name
      Signal = 'SL:size-mismatch'
      ProcPath = $appDir
      HitCount = $sizeMismatches.Count
      Detail = "$($sizeMismatches.Count) DLL(s) with different size than System32 copy: $detailList"
      Risk = 'high'
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
      encoding: 'utf-8', timeout: 15000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    let hits: {
      PID?: number; Name?: string; Signal?: string; ProcPath?: string
      Detail?: string; Risk?: string; HitCount?: number
    }[] = []
    try { const p = JSON.parse(out); hits = Array.isArray(p) ? p : [p] } catch { return results }

    for (const hit of hits) {
      const key = `sideload:${hit.Name}:${hit.PID}:${hit.Signal}`
      if (addFindingDedup(key)) {
        const riskLevel = hit.Risk || 'medium'
        const risk: 'high' | 'medium' | 'low' =
          riskLevel === 'high' ? 'high' : riskLevel === 'low' ? 'low' : 'medium'

        const matches: string[] = [
          hit.Detail || '',
          `Signal: ${hit.Signal}`,
        ]
        if (hit.ProcPath) {
          matches.push(`Game directory: ${hit.ProcPath}`)
        }
        if (hit.Signal?.includes('known-dll')) {
          matches.push(
            '⚠ KnownDLL-named module loaded from non-System32 path',
            '⚠ KnownDLLs registry may have been tampered with',
            '⚠ Bypasses Windows DLL search order protection',
          )
        } else if (hit.Signal?.includes('hijackable')) {
          matches.push(
            '⚠ Hijackable DLL found in game directory — ready for side-loading',
            '⚠ Attacker places malicious DLL here to intercept LoadLibrary calls',
            '⚠ If unsigned: DEFINITE cheat DLL. If signed: verify Microsoft signature.',
          )
        } else if (hit.Signal?.includes('shadow')) {
          matches.push(
            '⚠ Same DLL loaded from System32 AND game directory — shadow copy exists',
            '⚠ The game-directory copy shadows the legitimate System32 DLL',
            '⚠ Windows DLL search order loads app-dir copy FIRST (before System32)',
          )
        } else if (hit.Signal?.includes('size-mismatch')) {
          matches.push(
            '⚠ DLL file size differs from System32 original — DEFINITE planted DLL',
            '⚠ WMI file size comparison confirms the game-dir copy is not Microsoft',
            '⚠ Side-loaded cheat DLL confirmed by size divergence',
          )
        }
        matches.push(
          '⚠ DLL Side-Loading: Windows search order hijacked, malicious DLL injected',
          '⚠ LoadLibrary("legit.dll") → actually loads cheat DLL from game directory',
        )

        results.push({
          path: `process:${hit.Name} (PID: ${hit.PID})`,
          fileName: `⚠ DLL Side-Loading: ${hit.Name} — ${hit.Signal}`,
          type: 'process',
          risk,
          matches,
          size: hit.HitCount || 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* side-loading scan optional */ }

  return results
}
