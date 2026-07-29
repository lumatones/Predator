/**
 * Predator — Anti-Debug / Reverse Engineering Tool Scanner (Hardened)
 *
 * Detects:
 *   1. Running reverse engineering tools (x64dbg, Cheat Engine, Process Hacker, IDA, Ghidra, etc.)
 *   2. Processes with anti-debug API/DLL imports
 *   3. Hardware breakpoints (Dr0-Dr3 debug registers via GetThreadContext)
 *   4. Debug port detection (NtQueryInformationProcess → ProcessDebugPort)
 *   5. PEB.BeingDebugged + NtGlobalFlag for all suspicious processes (x32/x64 aware)
 *   6. Parent process verification (debugger spawn detection)
 *   7. Timing-based debugger detection (QueryPerformanceCounter precision)
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
  processNames: string[]
  windowPatterns?: string[]
  description: string
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
// TIER 1: RE Tools by Process Name
// ═══════════════════════════════════════════════════

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
                '⚠ Reverse engineering tools alongside game = cheat development indicator',
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

// ═══════════════════════════════════════════════════
// TIER 2: Anti-Debug API/DLL Imports
// ═══════════════════════════════════════════════════

function scanAntiDebugApiImports(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$suspicious = @()
Get-Process | Where-Object { $_.Modules } | ForEach-Object {
  $proc = $_
  $mods = @($proc.Modules | Select-Object -ExpandProperty ModuleName | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
  
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
            debugDlls.length > 0 ? 'Debugger DLLs in a non-development process — suspicious' : '',
            antiDebugDlls.length > 0 ? '⚠ Anti-debug bypass libraries — cheat loader indicator' : '',
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
// TIER 3: Hardware Breakpoint Detection (Dr0-Dr3)
// ═══════════════════════════════════════════════════

function scanHardwareBreakpoints(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class HwBp {
  [DllImport("kernel32.dll")] public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
  [DllImport("kernel32.dll")] public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);

  public const uint THREAD_GET_CONTEXT = 0x0008;
  public const uint THREAD_QUERY_INFORMATION = 0x0040;

  [StructLayout(LayoutKind.Sequential)]
  public struct CONTEXT64 {
    public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
    public uint ContextFlags, MxCsr;
    public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
    public uint EFlags;
    public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip;
  }
}
'@

$results = @()
$suspectProcs = @(Get-Process | Where-Object { $_.Name -notmatch '^(Idle|System|svchost|csrss|wininit|services|lsass|winlogon|smss|spoolsv|dwm|RuntimeBroker|SearchIndexer|SecurityHealth|SgrmBroker|WmiPrvSE|explorer)$' } | Select-Object -First 80)

foreach ($proc in $suspectProcs) {
  foreach ($thread in $proc.Threads) {
    try {
      $hThread = [HwBp]::OpenThread([HwBp]::THREAD_GET_CONTEXT -bor [HwBp]::THREAD_QUERY_INFORMATION, $false, $thread.Id)
      if ($hThread -eq [IntPtr]::Zero) { continue }
      $ctx = New-Object HwBp+CONTEXT64
      $ctx.ContextFlags = 0x100010
      $ok = [HwBp]::GetThreadContext($hThread, [ref]$ctx)
      [HwBp]::CloseHandle($hThread) | Out-Null
      if (-not $ok) { continue }
      if ($ctx.Dr0 -ne 0 -or $ctx.Dr1 -ne 0 -or $ctx.Dr2 -ne 0 -or $ctx.Dr3 -ne 0) {
        $results += [PSCustomObject]@{
          Name = $proc.Name; Pid = $proc.Id; Tid = $thread.Id
          Dr0 = [string]$ctx.Dr0; Dr1 = [string]$ctx.Dr1
          Dr2 = [string]$ctx.Dr2; Dr3 = [string]$ctx.Dr3; Dr7 = [string]$ctx.Dr7
        }
        break
      }
    } catch { }
  }
}
$results | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 20000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    const hits = parsePsJson<{ Name?: string; Pid?: number; Tid?: number; Dr0?: string; Dr1?: string; Dr2?: string; Dr3?: string; Dr7?: string }>(out)
    for (const hit of hits) {
      const procName = hit.Name || 'unknown'
      const pid = hit.Pid || 0
      if (addFindingDedup(`hwbp:${procName}:${pid}`)) {
        const activeRegs: string[] = []
        if (hit.Dr0 && hit.Dr0 !== '0') activeRegs.push(`Dr0=0x${parseInt(hit.Dr0).toString(16)}`)
        if (hit.Dr1 && hit.Dr1 !== '0') activeRegs.push(`Dr1=0x${parseInt(hit.Dr1).toString(16)}`)
        if (hit.Dr2 && hit.Dr2 !== '0') activeRegs.push(`Dr2=0x${parseInt(hit.Dr2).toString(16)}`)
        if (hit.Dr3 && hit.Dr3 !== '0') activeRegs.push(`Dr3=0x${parseInt(hit.Dr3).toString(16)}`)
        results.push({
          path: `Process: ${procName} (PID: ${pid})`,
          fileName: `⚠ Hardware Breakpoints: ${procName}`,
          type: 'process', risk: 'high',
          matches: [
            `Process: ${procName} (PID: ${pid}), Thread: ${hit.Tid || '?'}`,
            `Active debug registers: ${activeRegs.join(', ')}`,
            `Dr7=${hit.Dr7 || '0'} (control register)`,
            '⚠ Hardware breakpoints outside debugger — cheat code interception',
          ],
          size: 0, modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* HWBP scan optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// TIER 4: Debug Port Detection
// ═══════════════════════════════════════════════════
//
// NtQueryInformationProcess(ProcessDebugPort) is the canonical
// Windows anti-debug API. When a debugger attaches, the kernel
// sets the process's DebugPort to a non-zero value.
// Much more reliable than ObjectTypeIndex (boot-dependent).

function scanDebugPorts(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class DbgPort {
  [DllImport("ntdll.dll")] public static extern int NtQueryInformationProcess(IntPtr hProcess, int ic, IntPtr pi, int sz, out int len);
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);

  public const uint PROCESS_QUERY_INFORMATION = 0x0400;
  public const int ProcessDebugPort = 7;
}
'@

$results = @()
$targets = @(Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 -and $_.Id -ne $pid } | Select-Object -First 200)

foreach ($proc in $targets) {
  try {
    $hProcess = [DbgPort]::OpenProcess([DbgPort]::PROCESS_QUERY_INFORMATION, $false, $proc.Id)
    if ($hProcess -eq [IntPtr]::Zero) { continue }

    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
    $retLen = 0
    $status = [DbgPort]::NtQueryInformationProcess($hProcess, [DbgPort]::ProcessDebugPort, $buf, 8, [ref]$retLen)
    
    if ($status -eq 0 -and $retLen -ge 4) {
      $debugPort = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf)
      if ($debugPort -ne [IntPtr]::Zero) {
        $results += [PSCustomObject]@{ Name = $proc.Name; Pid = $proc.Id; DebugPort = $debugPort.ToInt64() }
      }
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    [DbgPort]::CloseHandle($hProcess) | Out-Null
  } catch { }
}
$results | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 15000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    const hits = parsePsJson<{ Name?: string; Pid?: number; DebugPort?: number }>(out)
    for (const hit of hits) {
      const procName = hit.Name || 'unknown'
      const pid = hit.Pid || 0
      if (addFindingDedup(`debug-port:${procName}:${pid}`)) {
        results.push({
          path: `Process: ${procName} (PID: ${pid})`,
          fileName: `⚠ Debug Port Active: ${procName}`,
          type: 'process', risk: 'high',
          matches: [
            `Process: ${procName} (PID: ${pid})`,
            `DebugPort: ${hit.DebugPort || '?'}`,
            '⚠ NtQueryInformationProcess(ProcessDebugPort) returned non-zero — debugger attached',
          ],
          size: 0, modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* DebugPort scan optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// TIER 5: PEB.BeingDebugged + NtGlobalFlag Scan (x32/x64 aware)
// ═══════════════════════════════════════════════════

function scanPebFlags(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class PebReader {
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
  [DllImport("kernel32.dll")] public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);
  [DllImport("ntdll.dll")] public static extern int NtQueryInformationProcess(IntPtr hProcess, int ProcessInformationClass, IntPtr ProcessInformation, int ProcessInformationLength, out int ReturnLength);

  public const uint PROCESS_QUERY_INFORMATION = 0x0400;
  public const uint PROCESS_VM_READ = 0x0010;
  public const int ProcessBasicInformation = 0;
}
'@

$results = @()
$targets = @(Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 } | Select-Object -First 150)

foreach ($proc in $targets) {
  try {
    $hProcess = [PebReader]::OpenProcess([PebReader]::PROCESS_QUERY_INFORMATION -bor [PebReader]::PROCESS_VM_READ, $false, $proc.Id)
    if ($hProcess -eq [IntPtr]::Zero) { continue }

    # Check if target is 32-bit (WoW64) to use correct PEB offset
    $isWow64 = $false
    [PebReader]::IsWow64Process($hProcess, [ref]$isWow64) | Out-Null

    $pbiSize = [IntPtr]::Size * 6
    $pbi = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($pbiSize)
    $retLen = 0
    $status = [PebReader]::NtQueryInformationProcess($hProcess, [PebReader]::ProcessBasicInformation, $pbi, $pbiSize, [ref]$retLen)

    if ($status -eq 0 -and $retLen -gt 0) {
      $pebOff = if ([IntPtr]::Size -eq 8) { 8 } else { 4 }
      $pebAddr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($pbi, $pebOff)
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pbi)

      if ($pebAddr -ne [IntPtr]::Zero) {
        $pebBuf = New-Object byte[] 256
        $bytesRead = 0
        $ok = [PebReader]::ReadProcessMemory($hProcess, $pebAddr, $pebBuf, 256, [ref]$bytesRead)
        if ($ok -and $bytesRead -ge 4) {
          $beingDebugged = $pebBuf[2]
          # NtGlobalFlag is at PEB+0xBC for 64-bit processes, PEB+0x68 for 32-bit (WoW64)
          $ntGlobalFlagOffset = if ($isWow64) { 0x68 } else { 0xBC }
          $ntGlobalFlag = [BitConverter]::ToUInt32($pebBuf, $ntGlobalFlagOffset)
          $debugFlags = $ntGlobalFlag -band 0x70

          if ($beingDebugged -ne 0 -or $debugFlags -ne 0) {
            $results += [PSCustomObject]@{
              Name = $proc.Name; Pid = $proc.Id
              BeingDebugged = $beingDebugged
              NtGlobalFlag = [string]$ntGlobalFlag; DebugFlags = $debugFlags
              IsWow64 = $isWow64
            }
          }
        }
      }
    } else {
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pbi)
    }
    [PebReader]::CloseHandle($hProcess) | Out-Null
  } catch { }
}
$results | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 25000, windowsHide: true,
    }).trim()

    if (!out || out === '[]' || out.length < 5) return results

    const hits = parsePsJson<{ Name?: string; Pid?: number; BeingDebugged?: number; NtGlobalFlag?: string; DebugFlags?: number }>(out)
    for (const hit of hits) {
      const procName = hit.Name || 'unknown'
      const pid = hit.Pid || 0
      const reasons: string[] = []
      if (hit.BeingDebugged) reasons.push('PEB.BeingDebugged=1')
      if (hit.DebugFlags) reasons.push(`NtGlobalFlag=0x${parseInt(hit.NtGlobalFlag || '0').toString(16)} (debugger heap flags)`)

      if (reasons.length > 0 && addFindingDedup(`peb:${procName}:${pid}`)) {
        results.push({
          path: `Process: ${procName} (PID: ${pid})`,
          fileName: `⚠ Debugger Flag in PEB: ${procName}`,
          type: 'process', risk: 'high',
          matches: [
            `Process: ${procName} (PID: ${pid})`,
            ...reasons,
            '⚠ Process Environment Block indicates active debugging',
          ],
          size: 0, modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* PEB scan optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// TIER 6: Parent Process Verification
// ═══════════════════════════════════════════════════

function checkParentProcess(): ScanResult[] {
  const results: ScanResult[] = []
  const ourPid = process.pid

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$parent = Get-CimInstance Win32_Process -Filter "ProcessId = ${ourPid}" | Select-Object -ExpandProperty ParentProcessId
$parentProc = Get-Process -Id $parent -ErrorAction SilentlyContinue
$parentName = if ($parentProc) { $parentProc.Name } else { 'unknown' }

$debugLaunchers = @('x64dbg', 'x32dbg', 'x96dbg', 'ollydbg', 'windbg', 'windbgx', 'ida', 'ida64', 'dnspy', 'ghidra')
$isDebugger = $false
foreach ($d in $debugLaunchers) {
  if ($parentName -match $d) { $isDebugger = $true; break }
}

[PSCustomObject]@{ Pid = $parent; Name = $parentName; IsDebugger = $isDebugger } | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 8000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    const parent = JSON.parse(out)
    if (parent.IsDebugger) {
      results.push({
        path: `process:parent:${parent.Name}`,
        fileName: `⚠ Launched by Debugger: ${parent.Name}`,
        type: 'system', risk: 'high',
        matches: [
          `Parent process: ${parent.Name} (PID: ${parent.Pid})`,
          'Predator was launched from a debugger process',
          '⚠ Scanner is being debugged — results may be compromised',
        ],
        size: 0, modifiedAt: new Date().toISOString(),
      })
    }
  } catch { /* parent check optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// TIER 7: Timing-Based Debugger Detection (QPC precision)
// ═══════════════════════════════════════════════════

function detectDebuggerByTiming(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class DbgTiming {
  [DllImport("kernel32.dll")] public static extern bool QueryPerformanceCounter(out long lpPerformanceCount);
  [DllImport("kernel32.dll")] public static extern bool QueryPerformanceFrequency(out long lpFrequency);
  [DllImport("kernel32.dll")] public static extern void OutputDebugString(string lpOutputString);
  [DllImport("kernel32.dll")] public static extern bool IsDebuggerPresent();
}
'@

$freq = 0L
[DbgTiming]::QueryPerformanceFrequency([ref]$freq) | Out-Null
if ($freq -eq 0) { $freq = 10000000 } # 10MHz default

# RISK #10 mitigation: Use OutputDebugString + IsDebuggerPresent as test payloads
# instead of DateTime.UtcNow (which measured .NET overhead, not syscall).

# Test 1: OutputDebugString overhead (debugger captures output → blocks thread)
$odbT1 = 0L; $odbT2 = 0L
[DbgTiming]::QueryPerformanceCounter([ref]$odbT1)
[DbgTiming]::OutputDebugString("Predator timing probe") | Out-Null
[DbgTiming]::QueryPerformanceCounter([ref]$odbT2)
$odbUs = ($odbT2 - $odbT1) * 1.0e6 / $freq

# Test 2: IsDebuggerPresent overhead (hooked = slower)
$idpT1 = 0L; $idpT2 = 0L
[DbgTiming]::QueryPerformanceCounter([ref]$idpT1)
$idpResult = [DbgTiming]::IsDebuggerPresent()
[DbgTiming]::QueryPerformanceCounter([ref]$idpT2)
$idpUs = ($idpT2 - $idpT1) * 1.0e6 / $freq

# Direct return (no baseline test — OutputDebugString already covers syscall timing)
[PSCustomObject]@{
  OdbUs = [string]$odbUs
  IdpUs = [string]$idpUs
  IdpResult = $idpResult
  Suspicious = ($odbUs -gt 100.0 -or $idpUs -gt 50.0 -or $idpResult)
} | ConvertTo-Json -Compress
`
    const out = execSync(`powershell -NoProfile -Command "${psScript.replace(/"/g, '\\"')}"`, {
      encoding: 'utf-8', timeout: 8000, windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    const timing = JSON.parse(out)
    if (timing.Suspicious) {
      const details: string[] = []
      if (parseFloat(timing.OdbUs) > 100) details.push(`OutputDebugString overhead: ${parseFloat(timing.OdbUs).toFixed(0)}μs (debugger capturing output)`)
      if (parseFloat(timing.IdpUs) > 50) details.push(`IsDebuggerPresent overhead: ${parseFloat(timing.IdpUs).toFixed(0)}μs (hooked/slowed)`)
      if (timing.IdpResult) details.push('IsDebuggerPresent returned TRUE')

      results.push({
        path: 'system:debugger-timing',
        fileName: '⚠ Debugger Timing Anomaly Detected',
        type: 'system', risk: 'high',
        matches: [
          ...details,
          '⚠ Timing analysis indicates active debugger or stealth debugging',
          'API call overhead significantly above normal thresholds',
        ],
        size: 0, modifiedAt: new Date().toISOString(),
      })
    }
  } catch { /* timing check optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// MAIN ENTRY POINT
// ═══════════════════════════════════════════════════

/**
 * Run full anti-debug / RE tool scan.
 *
 * RISK #2/#4 mitigation: Tiers that don't depend on each other
 * are grouped to minimise PowerShell spawn latency.
 * Tiers 1+2 (simple process listing) run first, then
 * Tiers 3-7 (expensive P/Invoke-heavy checks).
 *
 * Each tier fails gracefully — PowerShell blocked = 0 findings, no crash.
 * For production, critical tiers (4+5) should be migrated to koffi FFI
 * (see native-hv-detect.ts for reference pattern).
 *
 * Returns ScanResult[] with findings.
 */
export function scanAntiDebug(): ScanResult[] {
  const results: ScanResult[] = []

  // Fast tiers (process listing + DLL imports) — ~2-3s total
  results.push(...scanReToolsByProcess())
  results.push(...scanAntiDebugApiImports())

  // Expensive tiers (P/Invoke loops) — each 2-10s
  // Note: These run sequentially to avoid overwhelming the system.
  // If PowerShell is blocked, all fail gracefully returning [].
  results.push(...scanHardwareBreakpoints())
  results.push(...scanDebugPorts())
  results.push(...scanPebFlags())
  results.push(...checkParentProcess())
  results.push(...detectDebuggerByTiming())

  return results
}
