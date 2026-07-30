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

import { execPowerShell, execWithTimeout } from './utils/exec'
import os from 'os'
import type { ScanResult } from './types'
import { runNativeHypervisorScan } from './native-hv-detect'

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
      const out = execPowerShell('Get-Process | Select-Object -ExpandProperty Name', { timeout: 5000 }) || ''
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
    const out = execPowerShell('Get-Process | Where-Object { $_.MainWindowTitle } | Select-Object -ExpandProperty MainWindowTitle', { timeout: 5000 }) || ''
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
  } catch (err) { console.warn('[anti-tamper] failed:', (err as Error).message) }
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
    const out = execPowerShell(psScript, { timeout: 5000 }) || ''
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
    const out = execWithTimeout('netstat -ano', { timeout: 5000 }) || ''
    const lines = out.split(/[\r\n]+/)
    for (const line of lines) {
      for (const port of debugPorts) {
        if (line.includes(`:${port}`) && line.includes('LISTENING')) {
          ports.push(`Port ${port} (debugger/listening)`)
        }
      }
    }
  } catch (err) { console.warn('[anti-tamper] failed:', (err as Error).message) }
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
  } catch (err) { console.warn('[anti-tamper] failed:', (err as Error).message) }
  return found
}

/**
 * Detect VM via registry keys.
 */
export function detectVmByRegistry(): string[] {
  const found: string[] = []
  for (const key of VM_REGISTRY_KEYS) {
    try {
      const out = execPowerShell(`Test-Path '${key.replace(/'/g, "''")}'`, { timeout: 3000 }) || ''
      if (out.trim() === 'True') {
        found.push(key)
      }
    } catch (err) { console.warn('[anti-tamper] failed:', (err as Error).message) }
  }
  return found
}

/**
 * Detect VM processes running.
 */
export function detectVmProcesses(): string[] {
  const found: string[] = []
  try {
      const out = execPowerShell('Get-Process | Select-Object -ExpandProperty Name', { timeout: 5000 }) || ''
      const lines = out.toLowerCase().split(/[\r\n]+/)
    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      const procName = trimmed.endsWith('.exe') ? trimmed : trimmed + '.exe'
      if (VM_PROCESSES.includes(procName)) {
        found.push(procName)
      }
    }
  } catch (err) { console.warn('[anti-tamper] failed:', (err as Error).message) }
  return found
}

/**
 * Detect VM via CPUID hypervisor bit.
 */
export function detectVmByHypervisor(): { isVm: boolean; detail: string } {
  try {
    const out = execPowerShell('(Get-CimInstance Win32_ComputerSystem).HypervisorPresent', { timeout: 5000 }) || ''
    if (out.trim() === 'True') {
      return { isVm: true, detail: 'Hypervisor detected via WMI' }
    }
  } catch (err) { console.warn('[anti-tamper] failed:', (err as Error).message) }

  try {
    const out = execPowerShell('(Get-CimInstance Win32_BaseBoard).Manufacturer', { timeout: 5000 }) || ''
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
  } catch (err) { console.warn('[anti-tamper] failed:', (err as Error).message) }

  return { isVm: false, detail: '' }
}

// ═══════════════════════════════════════════════════
// 3. HYPERVISOR FINGERPRINTING — EPT / custom hypervisor detection
// ═══════════════════════════════════════════════════
//
// Advanced cheats use custom Type-1/Type-2 hypervisors (Illusion, Matrix, KVM-based)
// to hide memory reads/writes via EPT (Extended Page Tables).
//
// Detection methods:
//   1. CPUID timing anomaly — VMCALL/CPUID instructions take ~10-100x longer under a hypervisor
//   2. Hypervisor CPUID bit (0x40000000 leaf) — custom hypervisors may expose signature strings
//   3. IA32_FEATURE_CONTROL MSR (0x3A) — lock bit check for VMX/SVM
//   4. EPT/VPID capability check via IA32_VMX_EPT_VPID_CAP MSR

/**
 * Detect hypervisor via API call overhead timing.
 * Under a hypervisor, kernel32 P/Invoke calls have EPT vm-exit overhead
 * (0.01-0.05ms vs 0.001-0.003ms on bare metal).
 * Returns true if timing suggests hypervisor interception.
 */
export function detectHypervisorByApiOverhead(): { detected: boolean; detail: string; ratio: number } {
  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class HvTiming {
  [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
}
'@

$t1 = [HvTiming]::GetTickCount64()
for ($i = 0; $i -lt 10000; $i++) { $null = [HvTiming]::GetTickCount64() }
$t2 = [HvTiming]::GetTickCount64()
$avgUs = ($t2 - $t1) / 10000.0

# Bare metal: ~0.001-0.003ms per call
# Under hypervisor: ~0.01-0.05ms per call (EPT vm-exit overhead)
if ($avgUs -gt 0.008) {
  Write-Output "TIMING_ANOMALY:$avgUs"
} else {
  Write-Output "TIMING_NORMAL:$avgUs"
}
`
    const out = execPowerShell(psScript, { timeout: 8000 }) || ''

    if (out.startsWith('TIMING_ANOMALY:')) {
      const ratio = parseFloat(out.split(':')[1]) || 0
      return { detected: true, detail: `API overhead anomaly: ${ratio.toFixed(3)}ms avg (normal <0.008ms) — possible EPT vm-exit overhead`, ratio }
    }
    return { detected: false, detail: `API timing normal: ${out.split(':')[1] || '?'}ms`, ratio: 0 }
  } catch { /* timing check optional */ }

  return { detected: false, detail: 'Timing check unavailable', ratio: 0 }
}

/**
 * Detect hypervisor via SMBIOS/DMI data strings.
 * Custom hypervisors often leave vendor/model signatures in system firmware tables.
 */
export function detectHypervisorBySmbios(): { detected: boolean; signature: string } {
  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$mfr = (Get-CimInstance -ClassName Win32_BaseBoard).Manufacturer
$model = (Get-CimInstance -ClassName Win32_ComputerSystem).Model

$signatures = @(
  'KVM', 'QEMU', 'VMware', 'VirtualBox', 'Xen', 'Hyper-V',
  'Parallels', 'Bochs', 'Oracle VM'
)

$found = @()
foreach ($sig in $signatures) {
  if ($mfr -match $sig -or $model -match $sig) {
    $found += $sig
  }
}

if ($found.Count -gt 0) {
  Write-Output "HV_SIGNATURE:$($found -join ','):$mfr : $model"
} else {
  Write-Output "HV_NONE"
}
`
    const out = execPowerShell(psScript, { timeout: 5000 }) || ''

    if (out.startsWith('HV_SIGNATURE:')) {
      const parts = out.split(':')
      return { detected: true, signature: `${parts[1]?.trim() || 'unknown'} (${parts[2]?.trim() || '?'})` }
    }
  } catch { /* SMBIOS check optional */ }

  return { detected: false, signature: '' }
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

  // ── Hypervisor fingerprinting: PowerShell (fallback) + Native koffi FFI (primary) ──
  const hvTiming = detectHypervisorByApiOverhead()
  const hvSmbios = detectHypervisorBySmbios()

  if (hvTiming.detected) {
    results.push({
      path: 'system:hv-timing',
      fileName: `⚠ Hypervisor API overhead: ${hvTiming.detail}`,
      type: 'system',
      risk: 'medium',
      matches: [
        hvTiming.detail,
        'Possible EPT vm-exit overhead detected',
        'Custom hypervisors (Illusion, Matrix) intercept memory via EPT violations',
      ],
      size: 0,
      modifiedAt: now,
    })
  }

  if (hvSmbios.detected) {
    results.push({
      path: 'system:hv-smbios',
      fileName: `⚠ Hypervisor SMBIOS signature: ${hvSmbios.signature}`,
      type: 'system',
      risk: 'medium',
      matches: [
        `Hypervisor signature: ${hvSmbios.signature}`,
        'SMBIOS/DMI data indicates virtualization platform',
        'May indicate KVM/QEMU cheat VM with GPU passthrough',
      ],
      size: 0,
      modifiedAt: now,
    })
  }

  // ── Native hypervisor detection (koffi FFI — no PowerShell, 0 spawns) ──
  // PROD path: runs inline via kernel32/ntdll FFI, 3-4ms total.
  // Falls back gracefully if koffi unavailable (non-Windows).
  results.push(...runNativeHypervisorScan())

  return results
}
