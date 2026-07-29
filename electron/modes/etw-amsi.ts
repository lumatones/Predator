/**
 * Predator — AMSI / ETW Patch Detector
 *
 * Detects cheat patching of Windows security APIs in process memory:
 *   - AmsiScanBuffer  → return E_INVALIDARG / S_OK (scripts bypass scanning)
 *   - EtwEventWrite   → ret (suppress Windows event logging)
 *
 * Detection method:
 *   1. Check if amsi.dll loaded in suspicious process
 *   2. Dump process memory and scan for byte-level patch signatures
 *   3. Search for "AmsiScanBuffer", "EtwEventWrite" strings near RET instructions
 */

import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import os from 'os'
import { dumpProcessMemory } from '../memory-dump'

// ── Types ──────────────────────────────────────

export interface PatchResult {
  amsiPatched: boolean
  etwPatched: boolean
  details: string[]
  riskScore: number
}

// ── Byte patterns ──────────────────────────────

const AMSI_PATCH_X64: number[] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
const AMSI_PATCH_X64_V2: number[] = [0x31, 0xC0, 0xC3]
const ETW_PATCH_X64: number[] = [0x48, 0x33, 0xC0, 0xC3]
const ETW_PATCH_X86: number[] = [0x33, 0xC0, 0xC2, 0x14, 0x00]

interface PatternDef {
  name: string
  bytes: number[]
  description: string
  minOccurrences: number
}

const PATCH_PATTERNS: PatternDef[] = [
  { name: 'AMSI_Patch_x64', bytes: AMSI_PATCH_X64, description: 'AmsiScanBuffer patched (E_INVALIDARG)', minOccurrences: 1 },
  { name: 'AMSI_Patch_x64_v2', bytes: AMSI_PATCH_X64_V2, description: 'AmsiScanBuffer patched (xor eax, eax; ret)', minOccurrences: 3 },
  { name: 'ETW_Patch_x64', bytes: ETW_PATCH_X64, description: 'EtwEventWrite patched (xor rax, rax; ret)', minOccurrences: 1 },
  { name: 'ETW_Patch_x86', bytes: ETW_PATCH_X86, description: 'EtwEventWrite patched (x86)', minOccurrences: 1 },
]

// ── Helpers ────────────────────────────────────

function findPattern(buf: Buffer, pat: number[]): number[] {
  const offsets: number[] = []
  outer: for (let i = 0; i <= buf.length - pat.length; i++) {
    for (let j = 0; j < pat.length; j++) {
      if (buf[i + j] !== pat[j]) continue outer
    }
    offsets.push(i)
  }
  return offsets
}

function isAmsiLoaded(pid: number): boolean {
  try {
    const ps = `Get-Process -Id ${pid} | Select-Object -ExpandProperty Modules | Where-Object { $_.ModuleName -eq 'amsi.dll' } | Select-Object -First 1`
    const out = execSync(`powershell -Command "${ps}"`, { encoding: 'utf-8', timeout: 5000, windowsHide: true })
    return out.toLowerCase().includes('amsi.dll')
  } catch {
    return false
  }
}

// ── Public API ─────────────────────────────────

/** Scan a process for AMSI/ETW memory patches */
export function scanProcessForAmsiEtw(pid: number, processName: string, existingDumpPath?: string): PatchResult {
  const result: PatchResult = { amsiPatched: false, etwPatched: false, details: [], riskScore: 0 }

  const scriptHosts = ['powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'cmd.exe', 'mshta.exe']
  const isScriptHost = scriptHosts.some(h => processName.toLowerCase().includes(h.replace('.exe', '')))

  if (!isScriptHost && isAmsiLoaded(pid)) {
    result.details.push('amsi.dll loaded in non-script process — unusual')
    result.riskScore += 20
  }

  const shouldDelete = !existingDumpPath
  const dumpPath = existingDumpPath || path.join(os.tmpdir(), `predator_etw_${pid}_${Date.now()}.dmp`)
  if (!existingDumpPath) {
    const dumpResult = dumpProcessMemory(pid, processName)
    if (!dumpResult) return result
    try { fs.copyFileSync(dumpResult, dumpPath) } catch { return result }
  }

  try {
    const stat = fs.statSync(dumpPath)
    const readSize = Math.min(stat.size, 80 * 1024 * 1024)
    const fd = fs.openSync(dumpPath, 'r')
    const buf = Buffer.alloc(readSize)
    fs.readSync(fd, buf, 0, readSize, 0)
    fs.closeSync(fd)

    for (const pat of PATCH_PATTERNS) {
      const offsets = findPattern(buf, pat.bytes)
      if (offsets.length >= pat.minOccurrences) {
        result.details.push(`${pat.name}: ${offsets.length} occurrence(s) — ${pat.description}`)
        if (pat.name.startsWith('AMSI')) { result.amsiPatched = true; result.riskScore += 40 }
        if (pat.name.startsWith('ETW')) { result.etwPatched = true; result.riskScore += 35 }
      }
    }

    const strings = ['AmsiScanBuffer', 'AmsiInitialize', 'EtwEventWrite', 'EtwEventRegister']
    let cur = ''
    const foundStrings = new Set<string>()
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i]
      if (b >= 0x20 && b <= 0x7E) {
        cur += String.fromCharCode(b)
      } else {
        for (const s of strings) {
          if (cur.includes(s)) foundStrings.add(s)
        }
        cur = ''
      }
    }
    for (const s of foundStrings) {
      result.details.push(`String in memory: ${s}`)
      result.riskScore += 10
    }
  } catch (err) { console.warn('[etw-amsi] failed:', (err as Error).message) }
  finally {
    if (!existingDumpPath) {
      try { fs.unlinkSync(dumpPath) } catch (err) { console.warn('[etw-amsi] failed:', (err as Error).message) }
    }
  }

  return result
}

/** Quick check: scan an existing memory dump for AMSI/ETW patches */
export function analyzeDumpForAmsiEtw(dumpPath: string): PatchResult {
  const result: PatchResult = { amsiPatched: false, etwPatched: false, details: [], riskScore: 0 }
  if (!fs.existsSync(dumpPath)) return result

  try {
    const stat = fs.statSync(dumpPath)
    const readSize = Math.min(stat.size, 80 * 1024 * 1024)
    const fd = fs.openSync(dumpPath, 'r')
    const buf = Buffer.alloc(readSize)
    fs.readSync(fd, buf, 0, readSize, 0)
    fs.closeSync(fd)

    for (const pat of PATCH_PATTERNS) {
      const offsets = findPattern(buf, pat.bytes)
      if (offsets.length >= pat.minOccurrences) {
        result.details.push(`${pat.name}: ${offsets.length}x — ${pat.description}`)
        if (pat.name.startsWith('AMSI')) { result.amsiPatched = true; result.riskScore += 40 }
        if (pat.name.startsWith('ETW')) { result.etwPatched = true; result.riskScore += 35 }
      }
    }
  } catch (err) { console.warn('[etw-amsi] failed:', (err as Error).message) }

  return result
}
