/**
 * Predator — Native Hypervisor Detection (koffi FFI)
 *
 * Replaces PowerShell-based hypervisor checks with native Windows API calls
 * via koffi FFI (foreign function interface). No PowerShell overhead, no process spawn.
 *
 * NOTE: CPUID and RDTSC are x86 CPU instructions — not callable from Node.js
 * without native addons. This module uses functionally equivalent Windows APIs:
 *   - NtQuerySystemInformation (kernel-level hypervisor detection — authoritative)
 *   - QueryPerformanceCounter overhead (VM-exit timing ≈ RDTSC + CPUID latency)
 *   - SMBIOS registry fingerprinting (KVM/QEMU/VMware/Xen string matching)
 *
 * Detection techniques:
 *   1. NtQuerySystemInformation(SystemHypervisorDetailInformation) —
 *      Direct kernel query for hypervisor presence, enlightenments, and
 *      hardware virtualization features. Authoritative — no heuristics.
 *   2. QueryPerformanceCounter timing — measures system call overhead.
 *      Under hypervisor, kernel32 calls cause VM-exits (EPT violations),
 *      making them 10-50x slower than on bare metal. Equivalent to RDTSC+CPUID.
 *   3. SMBIOS fingerprinting via registry — KVM/QEMU/VMware/Xen strings.
 */

import koffi from 'koffi'
import type { ScanResult } from './types'

// ═══════════════════════════════════════════════════
// KOFFI FFI BINDINGS
// ═══════════════════════════════════════════════════

// kernel32.dll — timing functions
const kernel32 = koffi.load('kernel32.dll')

const QueryPerformanceCounter = kernel32.func('int QueryPerformanceCounter(_Out_ int64_t *lpPerformanceCount)')
const QueryPerformanceFrequency = kernel32.func('int QueryPerformanceFrequency(_Out_ int64_t *lpFrequency)')
const GetTickCount64 = kernel32.func('uint64_t GetTickCount64()')

// ntdll.dll — system information
const ntdll = koffi.load('ntdll.dll')

// NtQuerySystemInformation: class 196 = SystemHypervisorDetailInformation
const NtQuerySystemInformation = ntdll.func(
  'long NtQuerySystemInformation(int SystemInformationClass, _Out_ void *SystemInformation, uint32_t SystemInformationLength, _Out_ uint32_t *ReturnLength)',
)

const SYSTEM_HYPERVISOR_DETAIL_INFORMATION_CLASS = 196
const HV_DETAIL_BUFFER_SIZE = 4096

// ═══════════════════════════════════════════════════
// 1. TIMING-BASED HYPERVISOR DETECTION
// ═══════════════════════════════════════════════════

export interface TimingResult {
  avgCallOverheadUs: number
  suspicious: boolean
  detail: string
}

/**
 * Measure system call overhead via GetTickCount64 in a tight loop.
 * Under a hypervisor, each call causes EPT vm-exit — 10-50x slower.
 *
 * Bare metal: 0.001-0.003 ms per call
 * Hypervisor: 0.01-0.05 ms per call (VM-exit overhead)
 */
export function detectHypervisorByTiming(): TimingResult {
  try {
    GetTickCount64() // Warm up FFI binding

    const ITERATIONS = 10000
    const t1 = GetTickCount64()

    for (let i = 0; i < ITERATIONS; i++) {
      GetTickCount64()
    }

    const t2 = GetTickCount64()
    const elapsedMs = Number(t2 - t1)
    const avgUs = (elapsedMs / ITERATIONS) * 1000

    const suspicious = avgUs > 5.0

    return {
      avgCallOverheadUs: avgUs,
      suspicious,
      detail: suspicious
        ? `System call overhead: ${avgUs.toFixed(1)}μs avg (normal <5μs) — possible EPT vm-exit overhead`
        : `System call overhead normal: ${avgUs.toFixed(1)}μs avg`,
    }
  } catch {
    return { avgCallOverheadUs: 0, suspicious: false, detail: 'Native timing unavailable' }
  }
}

/**
 * High-precision timing using QueryPerformanceCounter (RDTSC-equivalent).
 * Measures QPC call overhead — under hypervisor, each QPC call may cause VM-exit.
 *
 * Bare metal: 20-80ns per QPC call
 * Hypervisor: 500-3000ns per QPC call (VM-exit latency)
 */
export function detectHypervisorByQpcTiming(): { suspicious: boolean; ratio: number; detail: string } {
  try {
    const freqBuf = Buffer.alloc(8)
    if (!QueryPerformanceFrequency(freqBuf)) {
      return { suspicious: false, ratio: 0, detail: 'QPC unavailable' }
    }
    const freq = Number(freqBuf.readBigInt64LE(0))

    // Pre-allocate buffers (avoids GC thrash in timing loop)
    const startBuf = Buffer.alloc(8)
    const endBuf = Buffer.alloc(8)
    const dummyBuf = Buffer.alloc(8) // Reused across all iterations

    QueryPerformanceCounter(startBuf)

    for (let i = 0; i < 1000; i++) {
      QueryPerformanceCounter(dummyBuf)
    }

    QueryPerformanceCounter(endBuf)

    const start = Number(startBuf.readBigInt64LE(0))
    const end = Number(endBuf.readBigInt64LE(0))
    const elapsedNs = ((end - start) / freq) * 1e9
    const avgNs = elapsedNs / 1000

    const suspicious = avgNs > 300
    const ratio = freq > 0 ? avgNs / 50 : 0

    return {
      suspicious,
      ratio,
      detail: suspicious
        ? `QPC overhead: ${avgNs.toFixed(0)}ns avg (normal 20-80ns) — ${ratio.toFixed(1)}x slower`
        : `QPC overhead normal: ${avgNs.toFixed(0)}ns avg`,
    }
  } catch {
    return { suspicious: false, ratio: 0, detail: 'QPC timing unavailable' }
  }
}

// ═══════════════════════════════════════════════════
// 2. SYSTEM HYPERVISOR DETAIL (NtQuerySystemInformation)
// ═══════════════════════════════════════════════════

export interface HypervisorDetail {
  present: boolean
  vendorSignature: string
  detail: string
}

/**
 * Query SystemHypervisorDetailInformation via NtQuerySystemInformation.
 * Direct kernel query — the most authoritative hypervisor check.
 * Class 196 = SystemHypervisorDetailInformation (undocumented but stable).
 */
export function detectHypervisorByNtQuery(): HypervisorDetail {
  try {
    const buf = Buffer.alloc(HV_DETAIL_BUFFER_SIZE)
    const retLenBuf = Buffer.alloc(4)

    const status = NtQuerySystemInformation(
      SYSTEM_HYPERVISOR_DETAIL_INFORMATION_CLASS,
      buf,
      HV_DETAIL_BUFFER_SIZE,
      retLenBuf,
    )

    if (status !== 0) {
      if (status === 0xC0000002 || status === -1073741822) {
        return { present: false, vendorSignature: '', detail: 'No hypervisor (STATUS_NOT_IMPLEMENTED)' }
      }
      return { present: false, vendorSignature: '', detail: `NtQuerySystemInformation returned 0x${status.toString(16)}` }
    }

    const present = buf.readUInt8(0) !== 0

    let vendorStr = ''
    for (let i = 4; i < Math.min(16, HV_DETAIL_BUFFER_SIZE); i++) {
      const b = buf.readUInt8(i)
      if (b === 0) break
      if (b >= 0x20 && b <= 0x7E) {
        vendorStr += String.fromCharCode(b)
      }
    }

    const retLen = retLenBuf.readUInt32LE(0)

    return {
      present,
      vendorSignature: vendorStr,
      detail: present
        ? `Hypervisor present: "${vendorStr || 'unnamed'}" (${retLen} bytes returned)`
        : `Hypervisor not detected via NtQuerySystemInformation`,
    }
  } catch (err) {
    return { present: false, vendorSignature: '', detail: `Native query failed: ${(err as Error).message || 'unknown'}` }
  }
}

// ═══════════════════════════════════════════════════
// 3. SMBIOS FINGERPRINTING (via registry)
// ═══════════════════════════════════════════════════

const advapi32 = koffi.load('advapi32.dll')

// NOTE: koffi accepts BigInt values directly for void*/uintptr_t parameters.
// HKEY values like 0x80000002 are passed as BigInt, not as Buffer pointers.
const RegOpenKeyExA = advapi32.func(
  'long RegOpenKeyExA(uintptr_t hKey, const char* lpSubKey, uint32_t ulOptions, uint32_t samDesired, _Out_ void** phkResult)',
)
const RegQueryValueExA = advapi32.func(
  'long RegQueryValueExA(uintptr_t hKey, const char* lpValueName, void* lpReserved, _Out_ uint32_t* lpType, _Out_ void* lpData, _Out_ uint32_t* lpcbData)',
)
const RegCloseKey = advapi32.func('long RegCloseKey(uintptr_t hKey)')

const HKEY_LOCAL_MACHINE = 0x80000002n as unknown as bigint
const KEY_READ = 0x20019

const HV_SMBIOS_PATTERNS = ['KVM', 'QEMU', 'VMware', 'VirtualBox', 'Xen', 'Hyper-V', 'Parallels', 'Bochs', 'Oracle']

/** Read a registry string value via advapi32 FFI. Returns null on failure. */
function readRegistryString(subKey: string, valueName: string): string | null {
  try {
    const hKeyBuf = Buffer.alloc(8)

    // Pass HKEY_LOCAL_MACHINE as BigInt directly (koffi accepts BigInt for uintptr_t)
    const status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, hKeyBuf)
    if (status !== 0) return null

    const hKey = hKeyBuf.readBigUInt64LE(0)
    if (hKey === 0n) return null

    // Query required buffer size (lpData = null)
    const typeBuf = Buffer.alloc(4)
    const sizeBuf = Buffer.alloc(4)
    const queryStatus = RegQueryValueExA(hKey, valueName, null, typeBuf, null, sizeBuf)

    if (queryStatus !== 0 && queryStatus !== 0x7A) {
      RegCloseKey(hKey)
      return null
    }

    const dataSize = sizeBuf.readUInt32LE(0)
    if (dataSize === 0 || dataSize > 1024) {
      RegCloseKey(hKey)
      return null
    }

    // Read the value
    const dataBuf = Buffer.alloc(dataSize)
    const finalStatus = RegQueryValueExA(hKey, valueName, null, typeBuf, dataBuf, sizeBuf)

    RegCloseKey(hKey)

    if (finalStatus !== 0) return null

    const type = typeBuf.readUInt32LE(0)
    if (type === 1) {
      return dataBuf.toString('utf16le').replace(/\x00+$/, '')
    }

    return dataBuf.toString('utf-8').replace(/\x00+$/, '')
  } catch {
    return null
  }
}

/**
 * Check SMBIOS data via registry for known hypervisor signatures.
 */
export function detectHypervisorBySmbiosRegistry(): { detected: boolean; vendor: string; detail: string } {
  try {
    const mfr = readRegistryString(
      'HARDWARE\\DESCRIPTION\\System\\BIOS',
      'SystemManufacturer',
    )

    if (mfr) {
      for (const pattern of HV_SMBIOS_PATTERNS) {
        if (mfr.toLowerCase().includes(pattern.toLowerCase())) {
          return { detected: true, vendor: pattern, detail: `SMBIOS manufacturer: "${mfr}" matches ${pattern}` }
        }
      }
    }

    return { detected: false, vendor: '', detail: mfr ? `SMBIOS manufacturer: "${mfr}" (not a known hypervisor)` : 'SMBIOS not accessible' }
  } catch {
    return { detected: false, vendor: '', detail: 'Registry SMBIOS check failed' }
  }
}

// ═══════════════════════════════════════════════════
// 4. UNIFIED NATIVE SCAN
// ═══════════════════════════════════════════════════

/**
 * Run ALL native hypervisor detection techniques and return ScanResult[].
 * Falls back gracefully — if FFI fails (e.g., non-Windows platform),
 * returns empty results without crashing.
 *
 * Runtime: ~3-4ms (inline FFI, no process spawns).
 */
export function runNativeHypervisorScan(): ScanResult[] {
  const results: ScanResult[] = []
  const now = new Date().toISOString()

  try {
    // Technique 1: NtQuerySystemInformation (most authoritative)
    const hvDetail = detectHypervisorByNtQuery()
    if (hvDetail.present) {
      results.push({
        path: 'system:native-hv',
        fileName: `⚠ Hypervisor: ${hvDetail.vendorSignature || 'unnamed'} (kernel-level query)`,
        type: 'system',
        risk: 'medium',
        matches: [
          hvDetail.detail,
          hvDetail.vendorSignature ? `Vendor: "${hvDetail.vendorSignature}"` : '',
          'NtQuerySystemInformation(SystemHypervisorDetailInformation) confirms hypervisor',
        ].filter(Boolean),
        size: 0,
        modifiedAt: now,
      })
    }

    // Technique 2: QPC timing (RDTSC-equivalent VM-exit detection)
    const qpcTiming = detectHypervisorByQpcTiming()
    if (qpcTiming.suspicious) {
      results.push({
        path: 'system:native-hv-timing',
        fileName: `⚠ Hypervisor timing anomaly: ${qpcTiming.detail}`,
        type: 'system',
        risk: 'medium',
        matches: [
          qpcTiming.detail,
          `Timing ratio: ${qpcTiming.ratio.toFixed(1)}x normal`,
          'QPC call overhead indicates EPT vm-exit latency',
        ],
        size: 0,
        modifiedAt: now,
      })
    }

    // Technique 3: GetTickCount64 call overhead
    const tickTiming = detectHypervisorByTiming()
    if (tickTiming.suspicious) {
      results.push({
        path: 'system:native-hv-tick',
        fileName: `⚠ System call overhead anomaly: ${tickTiming.detail}`,
        type: 'system',
        risk: 'low',
        matches: [
          tickTiming.detail,
          'GetTickCount64 call overhead elevated — possible VM-exit overhead',
        ],
        size: 0,
        modifiedAt: now,
      })
    }

    // Technique 4: SMBIOS fingerprinting
    const smbios = detectHypervisorBySmbiosRegistry()
    if (smbios.detected) {
      results.push({
        path: 'system:native-hv-smbios',
        fileName: `⚠ SMBIOS hypervisor signature: ${smbios.vendor}`,
        type: 'system',
        risk: 'medium',
        matches: [
          smbios.detail,
          `Matches known hypervisor: ${smbios.vendor}`,
          'May indicate KVM/QEMU cheat VM with GPU passthrough',
        ],
        size: 0,
        modifiedAt: now,
      })
    }
  } catch (err) {
    console.error('[native-hv-detect] FFI error:', (err as Error).message || err)
  }

  return results
}
