/**
 * Predator RWX Scanner — Memory Region & Thread Analysis
 *
 * Детектит:
 *   1. RWX-регионы памяти (PAGE_EXECUTE_READWRITE = 0x40) в игровых процессах
 *      — internal-читы выделяют RWX-память под шеллкод/хуки/меню
 *   2. Thread Start Address аномалии — потоки, стартующие изнутри RWX-регионов
 *      — инжектированный код исполняется из heap/RWX → не из .exe/.dll
 */

import { execSync } from 'child_process'

// ── Types ──────────────────────────────────────

export interface RwxRegion {
  baseAddress: string
  regionSize: number
  regionSizeKb: number
  protect: string
  type: string
  isSuspicious: boolean
}

export interface ThreadAnomaly {
  threadId: number
  startAddress: string
  reason: string
}

export interface RwxScanResult {
  pid: number
  processName: string
  regions: RwxRegion[]
  threads: ThreadAnomaly[]
  riskScore: number
  details: string[]
}

// ── PowerShell C# VirtualQueryEx ───────────────

const CORE_PS = `
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class RwxScan {
  [StructLayout(LayoutKind.Sequential)]
  public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
  }

  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool VirtualQueryEx(
    IntPtr hProcess, IntPtr lpAddress,
    out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength
  );

  [DllImport("kernel32.dll")]
  public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

  [DllImport("kernel32.dll")]
  public static extern bool CloseHandle(IntPtr hObject);

  [DllImport("kernel32.dll")]
  public static extern int GetLastError();

  public static string Scan(uint pid) {
    IntPtr hProc = OpenProcess(0x0010 | 0x0020, false, (int)pid);
    if (hProc == IntPtr.Zero) return "ERR_OPEN:" + GetLastError();

    var results = new System.Collections.Generic.List<string>();
    IntPtr addr = IntPtr.Zero;

    while (true) {
      MEMORY_BASIC_INFORMATION mbi;
      if (!VirtualQueryEx(hProc, addr, out mbi, System.Runtime.InteropServices.Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)))) {
        int err = GetLastError();
        if (err == 87) break; // ERROR_INVALID_PARAMETER = end of user space
        // Transient error (e.g. guarded page) — skip ahead and continue
        addr = new IntPtr((long)addr + 0x10000);
        continue;
      }

      if ((long)mbi.RegionSize <= 0) {
        addr = new IntPtr((long)addr + 0x1000);
        continue;
      }

      // Filter: committed (0x1000) memory with RWX permissions
      if (mbi.State == 0x1000) {
        string protStr = "";
        switch (mbi.Protect & 0xFF) {
          case 0x10: protStr = "PAGE_EXECUTE"; break;
          case 0x20: protStr = "PAGE_EXECUTE_READ"; break;
          case 0x40: protStr = "PAGE_EXECUTE_READWRITE"; break;
          case 0x80: protStr = "PAGE_EXECUTE_WRITECOPY"; break;
          case 0x04: protStr = "PAGE_READWRITE"; break;
          default: protStr = "0x" + mbi.Protect.ToString("X8"); break;
        }

        string typeStr = "";
        switch (mbi.Type) {
          case 0x1000000: typeStr = "MEM_IMAGE"; break;
          case 0x40000: typeStr = "MEM_MAPPED"; break;
          case 0x20000: typeStr = "MEM_PRIVATE"; break;
          default: typeStr = "0x" + mbi.Type.ToString("X8"); break;
        }

        bool isRwx = (mbi.Protect & 0xFF) == 0x40;

        if (isRwx) {
          long sizeKb = (long)mbi.RegionSize / 1024;
          // Filter known .NET JIT regions — legitimate RWX for dynamic code
          bool isDotNet = (long)mbi.BaseAddress >= 0x7F0000000000L && (long)mbi.BaseAddress < 0x800000000000L;
          if (sizeKb > 4 && !isDotNet) {
            results.Add(string.Format("RWX|0x{0:X16}|{1}|{2}|{3}|{4}",
              (long)mbi.BaseAddress, mbi.RegionSize,
              protStr, typeStr, sizeKb));
          }
        }
      }

      long nextAddr = (long)addr + (long)mbi.RegionSize;
      if (nextAddr <= (long)addr) break;
      addr = new IntPtr(nextAddr);
    }

    CloseHandle(hProc);
    return string.Join(";", results.ToArray());
  }
}
"@
[RwxScan.Scan(${pid})]
`.trim()

// ── PowerShell Thread Enumeration ──────────────

const THREAD_PS = `
Get-Process -Id ${pid} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Threads |
  Select-Object Id, @{N='StartAddr';E={'0x' + $_.StartAddress.ToString('X16')}} |
  ConvertTo-Json -Compress
`.trim()

// ── Main scanning functions ────────────────────

/**
 * Scan a process memory for RWX regions using VirtualQueryEx via PowerShell C#.
 * Returns array of suspicious RWX regions.
 */
export function scanRwxRegions(pid: number): RwxRegion[] {
  const regions: RwxRegion[] = []

  try {
    const out = execSync(`powershell -Command "${CORE_PS.replace(/"/g, '\\"').replace(/\n/g, '; ')}"`, {
      encoding: 'utf-8',
      timeout: 15000, // 15 seconds per process
      windowsHide: true,
    })

    if (!out || out.trim().length < 5) return regions

    for (const line of out.trim().split(';')) {
      if (!line.startsWith('RWX|')) continue
      const parts = line.split('|')
      if (parts.length < 6) continue

      const baseAddress = parts[1]
      const regionSize = parseInt(parts[2], 10) || 0
      const protect = parts[3] || ''
      const type = parts[4] || ''
      const sizeKb = parseInt(parts[5], 10) || 0

      // MEM_IMAGE RWX = code section with write permission (extremely suspicious)
      const isImageRwx = type === 'MEM_IMAGE' && protect === 'PAGE_EXECUTE_READWRITE'
      // MEM_PRIVATE RWX = VirtualAlloc'd shellcode
      const isPrivateRwx = type === 'MEM_PRIVATE' && protect === 'PAGE_EXECUTE_READWRITE'
      // MEM_MAPPED RWX = mapped file with execute+write
      const isMappedRwx = type === 'MEM_MAPPED' && protect === 'PAGE_EXECUTE_READWRITE'

      const isSuspicious = isImageRwx || isPrivateRwx || isMappedRwx

      regions.push({
        baseAddress,
        regionSize,
        regionSizeKb: sizeKb,
        protect,
        type,
        isSuspicious,
      })
    }
  } catch { /* PowerShell failed */ }

  return regions
}

/**
 * Convert a hex address string to a numeric value for range comparison.
 */
function parseHexAddress(addr: string): bigint {
  try {
    const clean = addr.replace('0x', '').replace('0X', '')
    return BigInt('0x' + clean)
  } catch {
    return BigInt(0)
  }
}

/**
 * Scan thread start addresses — check if any thread starts INSIDE a found RWX region.
 * A thread living inside an RWX region is practically 100% injected code.
 */
export function scanThreadStartAddresses(pid: number, _processName: string, rwxRegions: RwxRegion[]): ThreadAnomaly[] {
  const anomalies: ThreadAnomaly[] = []

  // Build RWX address ranges for comparison
  const ranges: { start: bigint; end: bigint }[] = rwxRegions.map(r => ({
    start: parseHexAddress(r.baseAddress),
    end: parseHexAddress(r.baseAddress) + BigInt(r.regionSize),
  }))

  try {
    const out = execSync(`powershell -Command "${THREAD_PS}"`, {
      encoding: 'utf-8',
      timeout: 5000,
      windowsHide: true,
    })

    if (!out || out.trim().length < 5) return anomalies

    const parsed = JSON.parse(out)
    const threads = Array.isArray(parsed) ? parsed : [parsed]

    for (const thread of threads) {
      const tid = thread.Id
      const startAddr: string = thread.StartAddr || ''
      if (!startAddr) continue

      const addrInt = parseHexAddress(startAddr)

      // Check if this thread's start address falls into any RWX region
      let fallsInRwx = false
      for (const range of ranges) {
        if (addrInt >= range.start && addrInt < range.end) {
          fallsInRwx = true
          break
        }
      }

      if (fallsInRwx) {
        anomalies.push({
          threadId: tid,
          startAddress: startAddr,
          reason: `Thread starts inside RWX memory region (${startAddr}) — confirmed injected code execution`,
        })
      }
    }
  } catch { /* PowerShell failed */ }

  return anomalies
}

/**
 * Full RWX + Thread scan for a single process.
 * Returns combined results with risk assessment.
 */
export function scanRwxAndThreads(pid: number, processName: string): RwxScanResult {
  const result: RwxScanResult = {
    pid,
    processName,
    regions: [],
    threads: [],
    riskScore: 0,
    details: [],
  }

  // 1. Scan RWX memory regions
  const regions = scanRwxRegions(pid)
  const suspiciousRegions = regions.filter(r => r.isSuspicious)
  result.regions = suspiciousRegions

  if (suspiciousRegions.length > 0) {
    const totalRwxKb = suspiciousRegions.reduce((sum, r) => sum + r.regionSizeKb, 0)

    if (suspiciousRegions.length >= 3 || totalRwxKb > 1024) {
      result.riskScore += 100
      result.details.push(`CRITICAL: ${suspiciousRegions.length} RWX regions (${totalRwxKb} KB) — active code injection`)
    } else {
      result.riskScore += 70
      result.details.push(`HIGH: ${suspiciousRegions.length} RWX region(s) (${totalRwxKb} KB total) — possible shellcode`)
    }

    for (const reg of suspiciousRegions.slice(0, 3)) {
      result.details.push(`  RWX @ ${reg.baseAddress} — ${reg.regionSizeKb} KB (${reg.type}, ${reg.protect})`)
    }
  }

  // 2. Scan thread start addresses — check against found RWX regions
  const anomalies = scanThreadStartAddresses(pid, processName, suspiciousRegions)
  result.threads = anomalies

  if (anomalies.length > 0) {
    result.riskScore += 40
    result.details.push(`Confirmed: ${anomalies.length} thread(s) execute from within RWX memory`)

    for (const th of anomalies.slice(0, 3)) {
      result.details.push(`  Thread #${th.threadId} @ ${th.startAddress}`)
    }

    if (suspiciousRegions.length > 0 && anomalies.length > 0) {
      result.riskScore = Math.min(result.riskScore, 100)
      result.details.push('COMBO: RWX regions + threads executing from them = confirmed code injection')
    }
  }

  result.riskScore = Math.min(result.riskScore, 100)
  return result
}

/**
 * Convert RwxScanResult to a ScanResult-like object for scanner.ts integration.
 */
export interface RwxScanResultItem {
  path: string
  fileName: string
  type: 'process'
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
}

export function rwxResultToScanResult(scanResult: RwxScanResult): RwxScanResultItem | null {
  if (scanResult.riskScore < 30) return null

  return {
    path: `rwx:${scanResult.processName} (PID:${scanResult.pid})`,
    fileName: `🧠 Memory analysis: ${scanResult.processName}`,
    type: 'process',
    risk: scanResult.riskScore > 70 ? 'high' : 'medium',
    matches: scanResult.details.slice(0, 8),
    size: 0,
    modifiedAt: new Date().toISOString(),
  }
}
