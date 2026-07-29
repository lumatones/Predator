/**
 * Predator Disk vs Memory — Inline Hook Detection
 *
 * Сравнивает .text секцию DLL в памяти процесса с файлом на диске,
 * используя ReadProcessMemory (через PowerShell C# Add-Type).
 *
 * Читы делают inline hooks — патчат первые байты функций (jmp, call) в памяти.
 * На диске файл чистый, в памяти — модифицированный.
 *
 * Важно: корректно обрабатывает ASLR-релокации.
 * Если DLL имеет .reloc секцию и загружена не по предпочтительному адресу,
 * побайтовые различия в .text считаются легитимными (релокации), а не хуками.
 */

import fs from 'fs'
import { execSync } from 'child_process'
import { parsePsJson } from './types'

// ── Types ──────────────────────────────────────

export interface PeSection {
  name: string
  va: number   // Virtual Address (RVA)
  raw: number  // Raw offset in file
  size: number // VirtualSize in bytes
}

interface TextInfo {
  section: PeSection
  buf: Buffer
}

export interface PatchedBytes {
  offset: number
  diskBytes: string  // hex string of up to 16 bytes
  memBytes: string   // hex string of up to 16 bytes
}

export interface DllHookResult {
  moduleName: string
  modulePath: string
  textRva: number
  textSize: number
  diffBytes: number
  diffPercent: number
  isHooked: boolean
  skippedAslrReloc: boolean // true if differences were due to ASLR (not a hook)
  patches: PatchedBytes[]
  firstDiffOffset: number
  firstDiffDiskHex: string
  firstDiffMemHex: string
}

export interface DiskVsMemResult {
  pid: number
  processName: string
  scannedModules: number
  skippedAslr: number
  hookedModules: DllHookResult[]
  riskScore: number
  details: string[]
}

// ── PE Parser (zero dependencies) ──────────────

const MAX_HEADER_SIZE = 4096
const MAX_TEXT_SIZE = 5 * 1024 * 1024 // 5 MB
const MAX_DIFF_PATCHES_TO_REPORT = 5
const MAX_DIFF_BYTES_VISIBLE = 16

function readPeHeaders(filepath: string): Buffer | null {
  try {
    const stat = fs.statSync(filepath)
    if (stat.size < 64) return null
    const size = Math.min(stat.size, MAX_HEADER_SIZE)
    const buf = Buffer.alloc(size)
    const fd = fs.openSync(filepath, 'r')
    fs.readSync(fd, buf, 0, size, 0)
    fs.closeSync(fd)
    return buf
  } catch {
    return null
  }
}

function getPeOffset(buf: Buffer): number | null {
  if (buf[0] !== 0x4D || buf[1] !== 0x5A) return null
  const peOff = buf.readUInt32LE(0x3C)
  if (peOff + 24 > buf.length) return null
  if (buf[peOff] !== 0x50 || buf[peOff + 1] !== 0x45) return null
  return peOff
}

function parsePeSections(buf: Buffer, peOff: number): PeSection[] | null {
  const numSections = buf.readUInt16LE(peOff + 4 + 2)
  const optHeaderSize = buf.readUInt16LE(peOff + 4 + 16)
  const secOff = peOff + 4 + 20 + optHeaderSize

  const sections: PeSection[] = []
  for (let i = 0; i < numSections && i < 40; i++) {
    const o = secOff + i * 40
    if (o + 40 > buf.length) break
    let name = ''
    for (let j = 0; j < 8 && buf[o + j] !== 0; j++) name += String.fromCharCode(buf[o + j])
    sections.push({
      name,
      va: buf.readUInt32LE(o + 12),
      raw: buf.readUInt32LE(o + 20),
      size: buf.readUInt32LE(o + 16),
    })
  }
  return sections
}

/** Get the .text section from a PE file — returns null if not found or < 64 bytes */
function getTextSection(filepath: string): TextInfo | null {
  const headerBuf = readPeHeaders(filepath)
  if (!headerBuf) return null
  const peOff = getPeOffset(headerBuf)
  if (peOff === null) return null
  const sections = parsePeSections(headerBuf, peOff)
  if (!sections) return null
  const textSec = sections.find(s => s.name === '.text' || s.name === 'CODE')
  if (!textSec || textSec.size < 64) return null
  const textSize = Math.min(textSec.size, MAX_TEXT_SIZE)
  const textBuf = Buffer.alloc(textSize)
  try {
    const fd = fs.openSync(filepath, 'r')
    const bytesRead = fs.readSync(fd, textBuf, 0, textSize, textSec.raw)
    fs.closeSync(fd)
    return { section: textSec, buf: textBuf.subarray(0, bytesRead) }
  } catch {
    return null
  }
}

function hasRelocSection(filepath: string): boolean {
  const headerBuf = readPeHeaders(filepath)
  if (!headerBuf) return false
  const peOff = getPeOffset(headerBuf)
  if (peOff === null) return false
  const sections = parsePeSections(headerBuf, peOff)
  if (!sections) return false
  return sections.some(s => s.name === '.reloc' || s.name === '.RELOC')
}

function getImageBase(filepath: string): number | null {
  const headerBuf = readPeHeaders(filepath)
  if (!headerBuf) return null
  const peOff = getPeOffset(headerBuf)
  if (peOff === null) return null
  const optOff = peOff + 4 + 20
  const magic = headerBuf.readUInt16LE(optOff)
  if (magic === 0x10B) return headerBuf.readUInt32LE(optOff + 28)       // PE32
  if (magic === 0x20B) return Number(headerBuf.readBigUInt64LE(optOff + 24)) // PE32+
  return null
}

// ── System DLL filter ──────────────────────────

const SYSTEM_DIRS = [
  'c:\\windows\\system32\\',
  'c:\\windows\\syswow64\\',
  'c:\\windows\\system32\\drivers\\',
  'c:\\windows\\microsoft.net\\',
  'c:\\windows\\assembly\\',
  'c:\\windows\\winsxs\\',
]

function isSystemModule(filePath: string): boolean {
  const lower = filePath.toLowerCase()
  return SYSTEM_DIRS.some(dir => lower.startsWith(dir))
}

// ── PowerShell C# ReadProcessMemory ────────────

const RPM_PS_TEMPLATE = `
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class MemR {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr hObject);
}
"@

$h = [MemR]::OpenProcess(0x0010, $false, PID_PLACEHOLDER)
if ($h -eq 0) { Write-Host "ERROR_CANNOT_OPEN_PROCESS"; exit 1 }

$results = New-Object System.Collections.ArrayList
$modulesRaw = MODULES_JSON_PLACEHOLDER | ConvertFrom-Json
$hasError = $false

foreach ($mod in $modulesRaw) {
  $addr = [long]$mod.addr + [long]$mod.rva
  $size = [int]$mod.size
  $name = $mod.name
  $buf = New-Object byte[] $size
  $read = 0
  $ok = [MemR]::ReadProcessMemory($h, [IntPtr]$addr, $buf, $size, [ref]$read)
  if ($ok -and $read -gt 0) {
    $b64 = [Convert]::ToBase64String($buf, 0, $read)
    [void]$results.Add(@{name=$name; data=$b64; len=$read})
  } else {
    $hasError = $true
  }
}
[MemR]::CloseHandle($h)
$output = @{modules=$results; hasError=$hasError}
Write-Host ($output | ConvertTo-Json -Compress)
`

interface BatchEntry {
  name: string
  path: string
  baseAddr: number
  textRva: number
  textSize: number
  isRebased: boolean
}

/**
 * Read .text sections of multiple DLL modules from a running process
 * in a single PowerShell call. Returns a map of moduleName → Buffer.
 */
function batchReadProcessMemory(pid: number, entries: BatchEntry[]): Map<string, Buffer> {
  const result = new Map<string, Buffer>()
  if (entries.length === 0) return result

  const modulesJson = JSON.stringify(entries.map(m => ({
    name: m.name,
    addr: m.baseAddr,
    rva: m.textRva,
    size: m.textSize,
  })))

  const psScript = RPM_PS_TEMPLATE
    .replace('PID_PLACEHOLDER', String(pid))
    .replace('MODULES_JSON_PLACEHOLDER', modulesJson)

  try {
    const out = execSync(
      `powershell -Command "${psScript.replace(/"/g, '\\"').replace(/\n/g, '; ')}"`,
      {
        encoding: 'utf-8',
        timeout: 20000,
        windowsHide: true,
        maxBuffer: 50 * 1024 * 1024,
      }
    ).trim()

    if (out.startsWith('ERROR_')) return result

    const jsonStart = out.indexOf('{')
    const jsonEnd = out.lastIndexOf('}')
    if (jsonStart < 0 || jsonEnd < 0) return result

    const parsed = JSON.parse(out.slice(jsonStart, jsonEnd + 1))
    const rawModules: { name: string; data: string; len: number }[] = parsed.modules || []

    for (const raw of rawModules) {
      try {
        result.set(raw.name, Buffer.from(raw.data, 'base64'))
      } catch (err) { console.warn('[disk-vs-memory] failed:', (err as Error).message) }
    }
  } catch (err) { console.warn('[disk-vs-memory] failed:', (err as Error).message) }

  return result
}

// ── Main scanning function ─────────────────────

/**
 * Scan a process for hooked DLLs by comparing .text sections
 * in memory (via ReadProcessMemory) vs on disk.
 *
 * Handles ASLR: if a DLL has .reloc section and is loaded at a
 * non-preferred address, differences are attributed to relocations,
 * not hooks.
 */
export function scanDiskVsMemory(pid: number, processName: string): DiskVsMemResult {
  const result: DiskVsMemResult = {
    pid,
    processName,
    scannedModules: 0,
    skippedAslr: 0,
    hookedModules: [],
    riskScore: 0,
    details: [],
  }

  // 1. Get module list from process via PowerShell
  let modules: { name: string; path: string; baseAddr: number }[] = []
  try {
    const psCmd = `Get-Process -Id ${pid} -ErrorAction SilentlyContinue | ` +
      `Select-Object -ExpandProperty Modules | ` +
      `Select-Object ModuleName, FileName, @{N='BaseAddr';E={[long]$_.BaseAddress}} | ` +
      `ConvertTo-Json -Compress`

    const out = execSync(`powershell -Command "${psCmd}"`, {
      encoding: 'utf-8',
      timeout: 8000,
      windowsHide: true,
    }).trim()

    if (out && out.length > 5) {
      const rawModules = parsePsJson<{ ModuleName?: string; FileName?: string; BaseAddr?: number }>(out)
      modules = rawModules
        .filter((m) => m.ModuleName && m.FileName)
        .map((m) => ({
          name: m.ModuleName as string,
          path: m.FileName as string,
          baseAddr: typeof m.BaseAddr === 'number' ? m.BaseAddr : 0,
        }))
    }
  } catch {
    result.details.push('Could not enumerate process modules')
    return result
  }

  if (modules.length === 0) {
    result.details.push('No modules found in process')
    return result
  }

  // 2. Cache: parse .text section from disk for each non-system DLL
  //    Also check ASLR (has .reloc + loaded at different address)
  const textCache = new Map<string, TextInfo>()
  const batchEntries: BatchEntry[] = []

  for (const mod of modules) {
    const modPath = mod.path
    if (!modPath || isSystemModule(modPath)) continue
    if (modPath.toLowerCase().endsWith('.exe')) continue
    if (!fs.existsSync(modPath)) continue

    result.scannedModules++

    // Parse .text section from disk — cache it
    if (!textCache.has(modPath)) {
      const textInfo = getTextSection(modPath)
      if (!textInfo) continue
      textCache.set(modPath, textInfo)
    }

    const textInfo = textCache.get(modPath)!
    const hasReloc = hasRelocSection(modPath)
    const imageBase = getImageBase(modPath)
    const isRebased = hasReloc && imageBase !== null && mod.baseAddr !== imageBase

    if (isRebased) result.skippedAslr++

    batchEntries.push({
      name: mod.name,
      path: modPath,
      baseAddr: mod.baseAddr,
      textRva: textInfo.section.va,
      textSize: textInfo.buf.length,
      isRebased,
    })
  }

  if (batchEntries.length === 0) {
    result.details.push('No non-system modules to scan')
    return result
  }

  // 3. Batch-read all .text sections from process memory (single PowerShell call)
  const memTexts = batchReadProcessMemory(pid, batchEntries)

  // 4. Compare each batched module (skips system DLLs and .exes)
  for (const entry of batchEntries) {
    const memBuf = memTexts.get(entry.name)
    if (!memBuf) continue

    const textInfo = textCache.get(entry.path)
    if (!textInfo) continue

    const diskBuf = textInfo.buf
    const compareLen = Math.min(diskBuf.length, memBuf.length, MAX_TEXT_SIZE)
    if (compareLen < 64) continue

    // 5. Byte-by-byte comparison
    const diffOffsets: number[] = []
    for (let i = 0; i < compareLen; i++) {
      if (diskBuf[i] !== memBuf[i]) diffOffsets.push(i)
    }

    if (diffOffsets.length === 0) continue

    const diffPercent = Math.round((diffOffsets.length / compareLen) * 1000) / 10

    // 6. Build patch info for first N differences
    const patches: PatchedBytes[] = []
    for (let j = 0; j < Math.min(diffOffsets.length, MAX_DIFF_PATCHES_TO_REPORT); j++) {
      const off = diffOffsets[j]
      const viewLen = Math.min(MAX_DIFF_BYTES_VISIBLE, compareLen - off)
      const diskBytes = Buffer.alloc(viewLen)
      const memBytes = Buffer.alloc(viewLen)
      for (let k = 0; k < viewLen; k++) {
        diskBytes[k] = diskBuf[off + k]
        memBytes[k] = memBuf[off + k]
      }
      patches.push({
        offset: off,
        diskBytes: diskBytes.toString('hex').toUpperCase(),
        memBytes: memBytes.toString('hex').toUpperCase(),
      })
    }

    // 7. Determine if hooked (considering ASLR)
    let detail: string

    if (entry.isRebased) {
      // DLL was rebased — only flag if > 1% of .text differs (extreme case)
      if (diffPercent > 1.0 && diffOffsets.length > 100) {
        detail = `🔗 HOOKED (despite ASLR): ${entry.name} — ${diffPercent}% of .text (${diffOffsets.length} bytes)`
        result.riskScore += 60
      } else {
        continue // Legitimate ASLR differences, not a hook
      }
    } else {
      // No .reloc section (or loaded at preferred base) — any diff is suspicious
      if (diffPercent > 0.05) {
        if (diffPercent > 5.0) {
          detail = `🔗 CRITICAL: ${entry.name} — ${diffPercent}% of .text differs (${diffOffsets.length} bytes patched)`
          result.riskScore += 80
        } else if (diffPercent > 0.5) {
          detail = `🔗 HIGH: ${entry.name} — ${diffPercent}% of .text modified (${diffOffsets.length} bytes)`
          result.riskScore += 60
        } else {
          detail = `🔗 LOW: ${entry.name} — ${diffPercent}% of .text differs (${diffOffsets.length} bytes)`
          result.riskScore += 40
        }
      } else {
        continue // Tiny difference (< 0.05%) — noise
      }
    }

    const hookedModule: DllHookResult = {
      moduleName: entry.name,
      modulePath: entry.path,
      textRva: entry.textRva,
      textSize: compareLen,
      diffBytes: diffOffsets.length,
      diffPercent,
      isHooked: true,
      skippedAslrReloc: entry.isRebased,
      patches,
      firstDiffOffset: diffOffsets[0],
      firstDiffDiskHex: patches[0]?.diskBytes || '',
      firstDiffMemHex: patches[0]?.memBytes || '',
    }

    result.hookedModules.push(hookedModule)
    result.details.push(detail)

    if (patches.length > 0) {
      const p = patches[0]
      result.details.push(`  Patch @ +0x${p.offset.toString(16)}: disk=${p.diskBytes.slice(0, 24)}... mem=${p.memBytes.slice(0, 24)}...`)
    }
  }

  result.riskScore = Math.min(result.riskScore, 100)
  return result
}

// ── Conversion to ScanResult ───────────────────

export interface DvmScanResultItem {
  path: string
  fileName: string
  type: 'process'
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
}

export function dvmResultToScanResult(result: DiskVsMemResult): DvmScanResultItem | null {
  if (result.hookedModules.length === 0 || result.riskScore < 30) return null
  return {
    path: `dvm:${result.processName} (PID:${result.pid})`,
    fileName: `🔗 Hook analysis: ${result.processName}`,
    type: 'process',
    risk: result.riskScore > 70 ? 'high' : 'medium',
    matches: result.details.slice(0, 8),
    size: 0,
    modifiedAt: new Date().toISOString(),
  }
}
