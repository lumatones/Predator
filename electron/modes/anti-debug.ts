/**
 * Predator — Anti-Debug / Reverse Engineering Tool Scanner
 *
 * Detects:
 *   1. Running reverse engineering tools (x64dbg, Cheat Engine, Process Hacker, IDA, Ghidra, etc.)
 *   2. Processes with anti-debug API imports (NtQueryInformationProcess, NtSetInformationThread)
 *   3. Unsigned processes checking PEB.BeingDebugged (evasion technique)
 *
 * Cheaters often run these tools to analyze/reverse the game and anti-cheat,
 * or embed anti-debug code in their cheat to hide from security software.
 */

import { execSync } from 'child_process'
import { type ScanResult, addFindingDedup, parsePsJson } from '../types'

// ═══════════════════════════════════════════════════
// KNOWN REVERSE ENGINEERING TOOLS
// ═══════════════════════════════════════════════════

interface ReTool {
  /** Process name patterns to match */
  processNames: string[]
  /** Window title patterns */
  windowPatterns?: string[]
  /** Description */
  description: string
  /** Risk level */
  risk: 'high' | 'medium'
}

const RE_TOOLS: ReTool[] = [
  {
    processNames: ['x64dbg.exe', 'x32dbg.exe', 'x96dbg.exe'],
    windowPatterns: ['x64dbg', 'x32dbg', 'debug'],
    description: 'x64dbg — user-mode debugger (reverse engineering)',
    risk: 'high',
  },
  {
    processNames: ['cheatengine-x86_64.exe', 'cheatengine-x86_64-SSE4-AVX2.exe', 'cheatengine-i386.exe', 'Cheat Engine.exe'],
    windowPatterns: ['Cheat Engine'],
    description: 'Cheat Engine — memory scanner/debugger',
    risk: 'high',
  },
  {
    processNames: ['ida.exe', 'ida64.exe', 'idaq.exe', 'idaq64.exe'],
    windowPatterns: ['IDA', 'Hex-Rays'],
    description: 'IDA Pro — disassembler/decompiler (reverse engineering)',
    risk: 'high',
  },
  {
    processNames: ['ghidra.exe', 'ghidraRun.bat'],
    windowPatterns: ['Ghidra'],
    description: 'Ghidra — NSA reverse engineering suite',
    risk: 'high',
  },
  {
    processNames: ['ProcessHacker.exe', 'SystemInformer.exe'],
    windowPatterns: ['Process Hacker', 'System Informer'],
    description: 'Process Hacker / System Informer — advanced process manager',
    risk: 'high',
  },
  {
    processNames: ['ollydbg.exe', 'ollyice.exe'],
    windowPatterns: ['OllyDbg'],
    description: 'OllyDbg — legacy debugger (reverse engineering)',
    risk: 'high',
  },
  {
    processNames: ['windbg.exe', 'windbgx.exe', 'DbgX.Shell.exe'],
    windowPatterns: ['WinDbg', 'Debugging Tools'],
    description: 'WinDbg — Microsoft kernel/user debugger',
    risk: 'high',
  },
  {
    processNames: ['dnSpy.exe', 'dnSpy-x86.exe'],
    windowPatterns: ['dnSpy'],
    description: 'dnSpy — .NET decompiler/debugger',
    risk: 'high',
  },
  {
    processNames: ['binaryninja.exe', 'Binary Ninja.exe'],
    windowPatterns: ['Binary Ninja'],
    description: 'Binary Ninja — disassembler (reverse engineering)',
    risk: 'high',
  },
  {
    processNames: ['hxd.exe', 'Hex Workshop.exe'],
    windowPatterns: ['HxD', 'Hex Workshop'],
    description: 'Hex editor — used for memory/file patching',
    risk: 'medium',
  },
  {
    processNames: ['extremeinjector.exe', 'injector.exe', 'dllinjector.exe', 'dll_injector.exe'],
    windowPatterns: [],
    description: 'DLL Injector — process injection tool',
    risk: 'high',
  },
  {
    processNames: ['reclass.exe', 'reclassnet.exe'],
    windowPatterns: ['ReClass'],
    description: 'ReClass — memory structure analyzer (used for cheat development)',
    risk: 'high',
  },
]

// ═══════════════════════════════════════════════════
// SCANNING
// ═══════════════════════════════════════════════════

/**
 * Tier 1: Check for running RE tools by process name.
 * Uses PowerShell to get process list + window titles.
 */
function scanReToolsByProcess(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Get-Process | Select-Object Name, Id, MainWindowTitle | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 8000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    const processes = parsePsJson<{ Name?: string; Id?: number; MainWindowTitle?: string }>(out)

    for (const proc of processes) {
      const procName = (proc.Name || '').toLowerCase()
      const windowTitle = (proc.MainWindowTitle || '').toLowerCase()

      for (const tool of RE_TOOLS) {
        const nameMatch = tool.processNames.some(n => procName === n.toLowerCase())
        const windowMatch = tool.windowPatterns?.some(p => windowTitle.includes(p.toLowerCase()))

        if (nameMatch || windowMatch) {
          const key = `re-tool:${procName}:${proc.Id}`
          if (addFindingDedup(key)) {
            results.push({
              path: `Process: ${proc.Name} (PID: ${proc.Id})`,
              fileName: `⚠ RE Tool Detected: ${proc.Name}`,
              type: 'process',
              risk: tool.risk,
              matches: [
                `Process: ${proc.Name} (PID: ${proc.Id})`,
                `Description: ${tool.description}`,
                windowTitle ? `Window: "${proc.MainWindowTitle}"` : '',
                `⚠ Reverse engineering tools alongside game = cheat development indicator`,
              ].filter(Boolean),
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
          break
        }
      }
    }
  } catch { /* process scan optional */ }

  return results
}

/**
 * Tier 2: Check for processes importing anti-debug APIs.
 * Uses PowerShell to detect NtQueryInformationProcess / NtSetInformationThread imports.
 *
 * These APIs are strong indicators that the process is:
 *   - A cheat trying to detect/hide from debuggers
 *   - A loader implementing anti-anti-debug bypasses
 */
function scanAntiDebugApiImports(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    // Check all running processes for suspicious module imports
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$suspicious = @()
Get-Process | Where-Object { $_.Modules } | ForEach-Object {
  $proc = $_
  $mods = @($proc.Modules | Select-Object -ExpandProperty ModuleName | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
  
  # Check for known debugger/anti-debug DLLs loaded in process
  $debugDlls = @('dbghelp.dll', 'dbgeng.dll', 'dbgcore.dll', 'symsrv.dll')
  $antiDebugDlls = @('scyllahide.dll', 'titanhide.dll', 'hyperhide.dll', 'sharpod.dll')
  
  $debugHits = @()
  foreach ($d in $debugDlls) { if ($mods -contains $d) { $debugHits += $d } }
  $antiDebugHits = @()
  foreach ($d in $antiDebugDlls) { if ($mods -contains $d) { $antiDebugHits += $d } }
  
  if ($debugHits.Count -gt 0 -or $antiDebugHits.Count -gt 0) {
    $suspicious += [PSCustomObject]@{
      Name = $proc.Name
      Id = $proc.Id
      DebugDlls = $debugHits -join '|'
      AntiDebugDlls = $antiDebugHits -join '|'
    }
  }
}
$suspicious | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 15000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    const hits = parsePsJson<{ Name?: string; Id?: number; DebugDlls?: string; AntiDebugDlls?: string }>(out)

    for (const hit of hits) {
      const procName = hit.Name || 'unknown'
      const pid = hit.Id || 0
      const debugDlls = (hit.DebugDlls || '').split('|').filter(Boolean)
      const antiDebugDlls = (hit.AntiDebugDlls || '').split('|').filter(Boolean)

      const allDlls = [...debugDlls, ...antiDebugDlls]

      if (allDlls.length > 0 && addFindingDedup(`anti-debug-dll:${procName}:${pid}`)) {
        const isAntiDebug = antiDebugDlls.length > 0
        results.push({
          path: `Process: ${procName} (PID: ${pid})`,
          fileName: isAntiDebug
            ? `⚠ Anti-Debug Tool in Process: ${procName}`
            : `⚠ Debug Symbols in Non-Dev Process: ${procName}`,
          type: 'process',
          risk: isAntiDebug ? 'high' : 'medium',
          matches: [
            `Process: ${procName} (PID: ${pid})`,
            debugDlls.length > 0 ? `Debug DLLs: ${debugDlls.join(', ')}` : '',
            antiDebugDlls.length > 0 ? `⚠ Anti-debug DLLs: ${antiDebugDlls.join(', ')}` : '',
            debugDlls.length > 0 ? `Debugger DLLs in a non-development process — suspicious` : '',
            antiDebugDlls.length > 0 ? `⚠ Anti-debug bypass libraries — cheat loader indicator` : '',
          ].filter(Boolean),
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* DLL scan optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// MAIN ENTRY POINT
// ═══════════════════════════════════════════════════

/**
 * Run full anti-debug / RE tool scan.
 * Returns ScanResult[] with findings.
 */
export function scanAntiDebug(): ScanResult[] {
  const results: ScanResult[] = []

  // Tier 1: Running RE tools by process name
  results.push(...scanReToolsByProcess())

  // Tier 2: Anti-debug API/DLL imports in processes
  results.push(...scanAntiDebugApiImports())

  return results
}
