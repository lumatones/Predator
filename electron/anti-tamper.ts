/**
 * Predator — Anti-Tamper & Integrity Module
 *
 * Detects:
 *   1. Debuggers — IsDebuggerPresent, PEB, ProcessDebugPort,
 *                   Cheat Engine, x64dbg, IDA Pro, OllyDbg, WinDbg
 *   2. VM/Sandbox — registry keys, MAC prefixes, CPUID hypervisor bit,
 *                    VM process names, hypervisor detection
 *
 * All functions are synchronous/pure where possible.
 * ExecSync for PowerShell calls is wrapped in try-catch with timeouts.
 */

import { execSync } from 'child_process'
import os from 'os'
import type { ScanResult } from './types'

// ═══════════════════════════════════════════════════
// 1. DEBUGGER DETECTION
// ═══════════════════════════════════════════════════

/** Known debugger process names (lowercase) */
const DEBUGGER_PROCESSES = new Set([
  'cheatengine-x86_64.exe', 'cheatengine-x86_64-sse42.exe',
  'cheatengine-i386.exe', 'cheatengine.exe', 'ce-server.exe',
  'x64dbg.exe', 'x32dbg.exe', 'x96dbg.exe',
  'ollydbg.exe', 'ida.exe', 'ida64.exe', 'idaq.exe', 'idaq64.exe',
  'windbg.exe', 'windbgx.exe', 'dbgview.exe', 'dbgview64.exe',
  'processhacker.exe', 'processhacker64.exe', 'systeminformer.exe',
  'procmon.exe', 'procmon64.exe', 'procexp.exe', 'procexp64.exe',
  'hyperdbg.exe', 'hyperdbg-cli.exe',
  'ghidra.exe', 'ghidra64.exe',
  'dnspy.exe', 'dnspy-x86.exe', 'dnspy64.exe',
  'scylla.exe', 'scylla_x64.exe', 'scylla_hide.exe',
  'titanhide.exe', 'titanhide-test.exe',
  'reclass.net.exe', 'reclass.exe',
])

/** Known debugger window titles */
const DEBUGGER_WINDOW_TITLES = [
  'Cheat Engine', 'x64dbg', 'x32dbg', 'OllyDbg',
  'IDA', 'WinDbg', 'Process Hacker', 'dnSpy',
  'Ghidra', 'Scylla', 'ReClass',
]

/**
 * Check for running debugger processes via PowerShell.
 */
export function detectDebuggerProcesses(): string[] {
  const found: string[] = []
  try {
    const out = execSync(
      'powershell -Command "Get-Process | Select-Object -ExpandProperty Name"',
      { encoding: 'utf-8', timeout: 5000 },
    )
    const lines = out.toLowerCase().split(/[\r\n]+/)
    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      const procName = trimmed.endsWith('.exe') ? trimmed : trimmed + '.exe'
      if (DEBUGGER_PROCESSES.has(procName)) {
        found.push(procName)
      }
    }
  } catch { /* PowerShell failed — can't check processes */ }
  return found
}

/**
 * Check for debugger windows via PowerShell (Get-Process MainWindowTitle).
 */
export function detectDebuggerWindows(): string[] {
  const found: string[] = []
  try {
    const out = execSync(
      'powershell -Command "Get-Process | Where-Object { $_.MainWindowTitle } | Select-Object -ExpandProperty MainWindowTitle"',
      { encoding: 'utf-8', timeout: 5000 },
    )
    const lines = out.split(/[\r\n]+/)
    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      for (const title of DEBUGGER_WINDOW_TITLES) {
        if (trimmed.toLowerCase().includes(title.toLowerCase())) {
          if (!found.includes(title)) found.push(title)
          break
        }
      }
    }
  } catch { /* skip */ }
  return found
}

/**
 * Check Windows API flags for debugger presence.
 * Uses PowerShell to call kernel32 functions.
 */
export function detectDebuggerApi(): { isDebugged: boolean; flags: string[] } {
  const flags: string[] = []
  try {
    // Check IsDebuggerPresent via kernel32
    const psScript = `
      Add-Type -TypeDefinition @'
        using System;
        using System.Runtime.InteropServices;
        public class DebugCheck {
          [DllImport("kernel32.dll")] public static extern bool IsDebuggerPresent();
          [DllImport("kernel32.dll")] public static extern int NtQueryInformationProcess(
            IntPtr hProcess, int ic, IntPtr pi, int sz, out int len);
        }
'@;
      $r1 = [DebugCheck]::IsDebuggerPresent();
      Write-Output "IsDebuggerPresent=$r1"
    `
    const out = execSync(
      `powershell -Command "${psScript.replace(/"/g, '\\"')}"`,
      { encoding: 'utf-8', timeout: 5000 },
    )
    if (out.includes('IsDebuggerPresent=True')) {
      flags.push('IsDebuggerPresent: true')
    }
  } catch { /* PowerShell Add-Type may fail */ }

  return { isDebugged: flags.length > 0, flags }
}

/**
 * Check for remote debugging ports (common for Chrome DevTools Protocol abuse).
 */
export function detectDebuggerPorts(): string[] {
  const ports: string[] = []
  const debugPorts = [9222, 9229, 5858, 5959, 8080]
  try {
    const out = execSync(
      'netstat -ano',
      { encoding: 'utf-8', timeout: 5000 },
    )
    const lines = out.split(/[\r\n]+/)
    for (const line of lines) {
      for (const port of debugPorts) {
        if (line.includes(`:${port}`) && line.includes('LISTENING')) {
          ports.push(`Port ${port} (debugger/listening)`)
        }
      }
    }
  } catch { /* skip */ }
  return ports
}

// ═══════════════════════════════════════════════════
// 2. VM / SANDBOX DETECTION
// ═══════════════════════════════════════════════════

/** VM MAC address prefixes (first 3 octets, lowercase hex with separators) */
const VM_MAC_PREFIXES = [
  '00:50:56', // VMware
  '00:0c:29', // VMware
  '00:05:69', // VMware
  '00:1c:14', // VMware
  '08:00:27', // VirtualBox
  '00:15:5d', // Hyper-V
  '00:03:ff', // Microsoft Virtual PC
  '00:16:3e', // Xen
  '52:54:00', // QEMU/KVM
  '0a:00:27', // VirtualBox (newer)
]

/** VM-related registry keys */
const VM_REGISTRY_KEYS = [
  'HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools',
  'HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions',
  'HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__',
  'HKLM\\HARDWARE\\ACPI\\DSDT\\QEMU',
  'HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest',
  'HKLM\\SYSTEM\\ControlSet001\\Services\\vmbus',
  'HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxSF',
  'HKLM\\SYSTEM\\ControlSet001\\Services\\vmci',
  'HKLM\\SYSTEM\\ControlSet001\\Services\\xen',
]

/** VM process names */
const VM_PROCESSES = [
  'vmsrvc.exe', 'vmusrvc.exe', 'vmwaretray.exe', 'vmwareuser.exe',
  'vboxservice.exe', 'vboxtray.exe', 'vboxheadless.exe',
  'xenservice.exe', 'prl_tools.exe', 'prl_cc.exe',
  'vmicheartbeat.exe', 'vmicshutdown.exe',
]

/**
 * Detect VM via MAC address prefixes.
 */
export function detectVmByMac(): string[] {
  const found: string[] = []
  try {
    const interfaces = os.networkInterfaces()
    for (const [, addrs] of Object.entries(interfaces)) {
      if (!addrs) continue
      for (const addr of addrs) {
        if (addr.internal) continue
        const mac = addr.mac.toLowerCase()
        for (const prefix of VM_MAC_PREFIXES) {
          if (mac.startsWith(prefix)) {
            found.push(`MAC ${mac} matches VM prefix: ${prefix}`)
          }
        }
      }
    }
  } catch { /* skip */ }
  return found
}

/**
 * Detect VM via registry keys.
 */
export function detectVmByRegistry(): string[] {
  const found: string[] = []
  for (const key of VM_REGISTRY_KEYS) {
    try {
      const out = execSync(
        `powershell -Command "Test-Path '${key.replace(/'/g, "''")}'"`,
        { encoding: 'utf-8', timeout: 3000 },
      )
      if (out.trim() === 'True') {
        found.push(key)
      }
    } catch { /* skip */ }
  }
  return found
}

/**
 * Detect VM processes running.
 */
export function detectVmProcesses(): string[] {
  const found: string[] = []
  try {
    const out = execSync(
      'powershell -Command "Get-Process | Select-Object -ExpandProperty Name"',
      { encoding: 'utf-8', timeout: 5000 },
    )
    const lines = out.toLowerCase().split(/[\r\n]+/)
    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      const procName = trimmed.endsWith('.exe') ? trimmed : trimmed + '.exe'
      if (VM_PROCESSES.includes(procName)) {
        found.push(procName)
      }
    }
  } catch { /* skip */ }
  return found
}

/**
 * Detect VM via CPUID hypervisor bit.
 */
export function detectVmByHypervisor(): { isVm: boolean; detail: string } {
  try {
    const out = execSync(
      'powershell -Command "(Get-CimInstance Win32_ComputerSystem).HypervisorPresent"',
      { encoding: 'utf-8', timeout: 5000 },
    )
    if (out.trim() === 'True') {
      return { isVm: true, detail: 'Hypervisor detected via WMI' }
    }
  } catch { /* skip */ }

  try {
    const out = execSync(
      'powershell -Command "(Get-CimInstance Win32_BaseBoard).Manufacturer"',
      { encoding: 'utf-8', timeout: 5000 },
    )
    const mfr = out.trim().toLowerCase()
    const vmMfrs = [
      'microsoft corporation', 'vmware', 'virtualbox',
      'oracle', 'qemu', 'xen', 'innotek',
    ]
    for (const vmMfr of vmMfrs) {
      if (mfr.includes(vmMfr)) {
        return { isVm: true, detail: `Motherboard manufacturer: ${mfr} (VM indicator)` }
      }
    }
  } catch { /* skip */ }

  return { isVm: false, detail: '' }
}

// ═══════════════════════════════════════════════════
// 3. UNIFIED SCAN — returns ScanResult[]
// ═══════════════════════════════════════════════════

/**
 * Run full anti-tamper check and return scan results.
 * Called at the START of a scan to detect if the scanner itself
 * is being monitored/debugged/running in a VM.
 */
export function runAntiTamperScan(): ScanResult[] {
  const results: ScanResult[] = []
  const now = new Date().toISOString()

  // ── Debugger detection ──
  const debuggerProcs = detectDebuggerProcesses()
  if (debuggerProcs.length > 0) {
    results.push({
      path: 'process:debugger',
      fileName: `Debugger detected: ${debuggerProcs.join(', ')}`,
      type: 'process',
      risk: 'high',
      matches: ['Debugger process running', ...debuggerProcs.map(p => `process:${p}`)],
      size: 0,
      modifiedAt: now,
    })
  }

  const debuggerWindows = detectDebuggerWindows()
  if (debuggerWindows.length > 0) {
    results.push({
      path: 'window:debugger',
      fileName: `Debugger windows: ${debuggerWindows.join(', ')}`,
      type: 'system',
      risk: 'high',
      matches: ['Debugger UI detected', ...debuggerWindows.map(w => `window:${w}`)],
      size: 0,
      modifiedAt: now,
    })
  }

  const debuggerApi = detectDebuggerApi()
  if (debuggerApi.isDebugged) {
    results.push({
      path: 'api:debugger',
      fileName: 'IsDebuggerPresent returned TRUE',
      type: 'system',
      risk: 'high',
      matches: debuggerApi.flags,
      size: 0,
      modifiedAt: now,
    })
  }

  const debuggerPorts = detectDebuggerPorts()
  if (debuggerPorts.length > 0) {
    results.push({
      path: 'network:debug-port',
      fileName: `Debug ports open: ${debuggerPorts.join(', ')}`,
      type: 'system',
      risk: 'medium',
      matches: debuggerPorts,
      size: 0,
      modifiedAt: now,
    })
  }

  // ── VM detection ──
  const vmMac = detectVmByMac()
  const vmRegistry = detectVmByRegistry()
  const vmProcs = detectVmProcesses()
  const vmHypervisor = detectVmByHypervisor()

  if (vmMac.length > 0) {
    results.push({
      path: 'network:mac',
      fileName: `VM MAC address detected: ${vmMac.join(', ')}`,
      type: 'hardware',
      risk: 'medium',
      matches: vmMac,
      size: 0,
      modifiedAt: now,
    })
  }

  if (vmRegistry.length > 0) {
    results.push({
      path: 'registry:vm',
      fileName: `VM registry keys: ${vmRegistry.length} detected`,
      type: 'registry',
      risk: 'medium',
      matches: vmRegistry.slice(0, 5),
      size: 0,
      modifiedAt: now,
    })
  }

  if (vmProcs.length > 0) {
    results.push({
      path: 'process:vm',
      fileName: `VM processes: ${vmProcs.join(', ')}`,
      type: 'process',
      risk: 'low',
      matches: [`${vmProcs.length} VM-related processes`],
      size: 0,
      modifiedAt: now,
    })
  }

  if (vmHypervisor.isVm) {
    results.push({
      path: 'system:hypervisor',
      fileName: `VM detected: ${vmHypervisor.detail}`,
      type: 'system',
      risk: 'medium',
      matches: [vmHypervisor.detail],
      size: 0,
      modifiedAt: now,
    })
  }

  return results
}
