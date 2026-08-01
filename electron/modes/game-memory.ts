/**
 * Predator — Game Memory Pattern Scanner (E14)
 *
 * Reads game process memory regions and scans for known cheat byte patterns:
 *   - Aimbot angle calculation signatures (atan2, smooth aim, silent aim)
 *   - ESP/wallhack frame patterns (D3D11/D3D12 Present hooks)
 *   - Overlay injection markers (ImGui, DirectX hook stubs)
 *   - CEF/Chromium remote debugging (devtools protocol abuse)
 *
 * Uses PowerShell + C# ReadProcessMemory for safe memory access.
 * Only scans readable committed memory regions (skips PAGE_GUARD, PAGE_NOACCESS).
 */

import { execPowerShell } from '../utils/exec'
import { type ScanResult, addFindingDedup } from '../types'

// ═══════════════════════════════════════════════════
// CHEAT MEMORY PATTERNS (byte sequences)
// ═══════════════════════════════════════════════════

interface MemoryPattern {
  name: string
  /** Hex byte pattern (wildcards: ?? = any byte) */
  bytes: string
  risk: 'high' | 'medium'
  description: string
}

const AIMBOT_PATTERNS: MemoryPattern[] = [
  {
    name: 'aimbot_smooth',
    bytes: 'F3 0F 10 ?? ?? ?? ?? ?? F3 0F 59 ?? ?? ?? ?? ?? F3 0F 58',
    risk: 'high',
    description: 'Smooth aimbot angle interpolation (XMM float math chain)',
  },
  {
    name: 'aimbot_atan2',
    bytes: 'F3 0F 10 ?? F3 0F 10 ?? E8 ?? ?? ?? ?? 66 0F',
    risk: 'medium',
    description: 'atan2 aimbot angle calculation (typical rage-aimbot pattern)',
  },
  {
    name: 'silent_aim_patch',
    bytes: '48 8B ?? ?? ?? ?? ?? 48 89 ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48',
    risk: 'high',
    description: 'Silent aim bullet trajectory patch (CUserCmd manipulation)',
  },
  {
    name: 'norecoil_nospread',
    bytes: 'F3 0F 10 ?? ?? ?? ?? ?? F3 0F 5C ?? F3 0F 11 ?? 0F 2F',
    risk: 'high',
    description: 'No-recoil/no-spread weapon stat override (subtraction + compare)',
  },
]

const ESP_PATTERNS: MemoryPattern[] = [
  {
    name: 'esp_world2screen',
    bytes: 'F3 0F 10 ?? ?? ?? ?? ?? F3 0F 11 ?? ?? 0F 28 ?? F3 0F 59 ?? ?? ?? ?? ?? F3 0F 58',
    risk: 'high',
    description: 'World-to-screen coordinate transform (ESP drawing foundation)',
  },
  {
    name: 'esp_drawlist',
    bytes: '48 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B ?? ?? 48 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D',
    risk: 'high',
    description: 'Draw list / render queue population (ESP box/line drawing)',
  },
  {
    name: 'esp_glow',
    bytes: 'C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 F8 ?? 75',
    risk: 'medium',
    description: 'Glow ESP object highlight (CS:GO-style glow hack)',
  },
]

const OVERLAY_PATTERNS: MemoryPattern[] = [
  {
    name: 'imgui_present_hook',
    bytes: '48 8B ?? ?? ?? ?? ?? 48 8B ?? E8 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B',
    risk: 'high',
    description: 'ImGui Present hook (D3D11/12 swapchain hijack for overlay menu)',
  },
  {
    name: 'd3d11_hook_stub',
    bytes: '48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8B ?? ?? ?? ?? ?? 48 8B D9',
    risk: 'high',
    description: 'D3D11/D3D12 hook trampoline (swapchain / Present hijack)',
  },
  {
    name: 'detour_trampoline',
    bytes: 'FF 25 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??', // x64 absolute jump
    risk: 'high',
    description: 'Detours-style trampoline jump (hooking engine: MinHook, Detours)',
  },
]

// Combine all patterns
const ALL_MEMORY_PATTERNS: MemoryPattern[] = [
  ...AIMBOT_PATTERNS,
  ...ESP_PATTERNS,
  ...OVERLAY_PATTERNS,
]

// ═══════════════════════════════════════════════════
// CEF/CHROMIUM REMOTE DEBUGGING DETECTION
// ═══════════════════════════════════════════════════

const CEF_DEBUG_PORTS = [9222, 9229, 9223, 9224, 9225, 29999, 13172, 9220, 9221]

// ═══════════════════════════════════════════════════
// MEMORY REGION ENUMERATION + SCANNING
// ═══════════════════════════════════════════════════

/**
 * Convert hex pattern string to regex for byte matching.
 * "F3 0F 10 ?? 59" → /\xF3\x0F\x10.\x59/
 */
function patternToRegex(pattern: string): RegExp {
  const bytes = pattern.split(/\s+/).map(b => {
    if (b === '??') return '.'
    return '\\x' + b
  }).join('')
  return new RegExp(bytes, 'g')
}

/**
 * Scan process memory for cheat patterns using PowerShell + C# ReadProcessMemory.
 */
export function scanGameMemory(): ScanResult[] {
  const results: ScanResult[] = []

  // Game processes to scan
  const GAME_PROCESSES = ['GTA5.exe', 'FiveM_GTAProcess.exe', 'ragemp_v.exe', 'altv.exe']

  for (const procName of GAME_PROCESSES) {
    try {
      // Get PID
      const pidOut = (execPowerShell(`Get-Process -Name '${procName.replace('.exe', '')}' -ErrorAction SilentlyContinue | Select -ExpandProperty Id -First 1`, { timeout: 5000 }) || '').trim()
      if (!pidOut) continue
      const pid = parseInt(pidOut, 10)
      if (isNaN(pid)) continue

      // Enumerate readable committed memory regions
      const regions = enumerateReadableRegions(pid)
      if (regions.length === 0) continue

      // Scan each region for patterns
      for (const region of regions.slice(0, 20)) {
        // limit to 20 regions to avoid excessive scanning
        try {
          const memData = readProcessMemory(pid, region.base, Math.min(region.size, 256 * 1024))
          if (!memData) continue

          for (const pattern of ALL_MEMORY_PATTERNS) {
            const regex = patternToRegex(pattern.bytes)
            if (regex.test(memData)) {
              const dedupKey = `game-mem:${procName}:${pattern.name}`
              if (addFindingDedup(dedupKey)) {
                results.push({
                  path: `process:${procName} (PID: ${pid})`,
                  fileName: `🧠 Memory: ${pattern.name}`,
                  type: 'process',
                  risk: pattern.risk,
                  matches: [
                    pattern.description,
                    `Process: ${procName} (PID: ${pid})`,
                    `Memory region: 0x${region.base.toString(16)} (${(region.size / 1024).toFixed(0)} KB)`,
                    pattern.risk === 'high' ? '⚠ Cheat memory pattern detected in game process' : '',
                  ].filter(Boolean),
                  size: 0,
                  modifiedAt: new Date().toISOString(),
                })
              }
            }
          }
        } catch (err) { console.warn('[game-memory] region scan failed:', (err as Error).message) }
      }
    } catch (err) { console.warn('[game-memory] process scan failed:', (err as Error).message) }
  }

  return results
}

// ═══════════════════════════════════════════════════
// CEF REMOTE DEBUGGING DETECTION
// ═══════════════════════════════════════════════════

/**
 * Detect CEF/Chromium remote debugging ports opened by cheat frameworks.
 * Cheats abuse Chrome DevTools Protocol for JS injection in FiveM/ALT:V.
 */
export function detectCefDebugPorts(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psCmd = `Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { ${CEF_DEBUG_PORTS.map(p => `$_.LocalPort -eq ${p}`).join(' -or ')} } | Select-Object LocalPort,OwningProcess | ConvertTo-Json -Compress`
    const out = execPowerShell(psCmd, { timeout: 8000 })

    if (!out || out.trim().length < 5) return results

    const listeners = JSON.parse(out)
    const items = Array.isArray(listeners) ? listeners : [listeners]

    for (const entry of items) {
      if (!entry?.LocalPort) continue
      const port = entry.LocalPort
      const pid = entry.OwningProcess

      // Get process name for the PID
      let procName = 'unknown'
      try {
        procName = (execPowerShell(`Get-Process -Id ${pid} -ErrorAction SilentlyContinue | Select -ExpandProperty ProcessName`, { timeout: 3000 }) || '').trim()
      } catch { /* best effort */ }

      // Skip if it's not a game process
      const lower = procName.toLowerCase()
      const isGameProc = lower.includes('fivem') || lower.includes('gta') ||
        lower.includes('ragemp') || lower.includes('altv')
      if (!isGameProc) continue

      if (addFindingDedup(`cef-debug:${pid}:${port}`)) {
        results.push({
          path: `process:${procName} (PID: ${pid})`,
          fileName: `🌐 CEF Debug Port: ${port}`,
          type: 'process',
          risk: 'high',
          matches: [
            `CEF/Chromium remote debugging port OPEN on game process`,
            `Port: ${port} — Process: ${procName} (PID: ${pid})`,
            `⚠ Cheats use Chrome DevTools Protocol for JS injection`,
            `⚠ Remote debugging should NEVER be enabled in production`,
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (err) { console.warn('[game-memory] CEF debug check failed:', (err as Error).message) }

  return results
}

// ═══════════════════════════════════════════════════
// MEMORY HELPER: Region enumeration
// ═══════════════════════════════════════════════════

interface MemRegion {
  base: number
  size: number
}

/**
 * Enumerate readable committed memory regions of a process via PowerShell.
 */
function enumerateReadableRegions(pid: number): MemRegion[] {
  try {
    const psCmd = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class MemInfo {
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll")] public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
  [StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress, AllocationBase;
    public int AllocationProtect, RegionSize, State, Protect, Type;
  }
}
"@
$hProc = [MemInfo]::OpenProcess(0x0410, $false, ${pid})
if ($hProc -eq [IntPtr]::Zero) { exit 0 }
$addr = [IntPtr]::Zero
$results = @()
while ([MemInfo]::VirtualQueryEx($hProc, $addr, [ref](New-Object MemInfo+MEMORY_BASIC_INFORMATION), [Runtime.InteropServices.Marshal]::SizeOf([MemInfo+MEMORY_BASIC_INFORMATION])) -ne 0) {
  $info = New-Object MemInfo+MEMORY_BASIC_INFORMATION
  [MemInfo]::VirtualQueryEx($hProc, $addr, [ref]$info, [Runtime.InteropServices.Marshal]::SizeOf([MemInfo+MEMORY_BASIC_INFORMATION])) | Out-Null
  # Only committed + readable regions
  if ($info.State -eq 0x1000 -and ($info.Protect -band 0x66) -ne 0) {
    $results += @{ base = [int64]$info.BaseAddress; size = $info.RegionSize }
  }
  $addr = [IntPtr]::Add($info.BaseAddress, $info.RegionSize)
  if ([int64]$addr -gt 0x7FFFFFFFFFFF) { break }
}
[MemInfo]::CloseHandle($hProc)
$results | Select-Object -First 30 | ConvertTo-Json -Compress
`
    const out = (execPowerShell(psCmd, { timeout: 15000, collapseLines: 'semicolons' }) || '').trim()

    if (!out || out.length < 5) return []
    const parsed = JSON.parse(out)
    return Array.isArray(parsed) ? parsed : [parsed]
  } catch {
    return []
  }
}

/**
 * Read process memory at specified address via PowerShell.
 * Returns the memory contents as a string for pattern matching.
 */
function readProcessMemory(pid: number, baseAddress: number, size: number): string | null {
  try {
    const psCmd = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ProcMem {
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
}
"@
$hProc = [ProcMem]::OpenProcess(0x0010, $false, ${pid})
if ($hProc -eq [IntPtr]::Zero) { exit 0 }
$buf = New-Object byte[] ${size}
$read = 0
$ok = [ProcMem]::ReadProcessMemory($hProc, [IntPtr]${baseAddress}, $buf, ${size}, [ref]$read)
[ProcMem]::CloseHandle($hProc)
if (-not $ok -or $read -eq 0) { exit 0 }
# Encode as base64 for safe transfer
[Convert]::ToBase64String($buf, 0, $read)
`
    const out = (execPowerShell(psCmd, { timeout: 10000, collapseLines: 'semicolons' }) || '').trim()

    if (!out || out.length < 4) return null
    return Buffer.from(out, 'base64').toString('latin1')
  } catch {
    return null
  }
}
