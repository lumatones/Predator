/**
 * Predator ETW / AMSI Patch Detector
 * 
 * Читы патчат в памяти:
 *   - AmsiScanBuffer  → возврат E_INVALIDARG / S_OK (чтобы скрипты не сканировались)
 *   - EtwEventWrite   → ret (чтобы Windows не логировала активность)
 * 
 * Детект:
 *   1. Проверяем, загружена ли amsi.dll в подозрительном процессе
 *   2. Дампим процесс и ищем байтовые паттерны патчей
 *   3. Ищем строки "AmsiScanBuffer", "EtwEventWrite" рядом с RET
 */

import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import os from 'os'
import { dumpProcessMemory } from './memory-dump'

// ── Types ──────────────────────────────────────

export interface PatchResult {
  amsiPatched: boolean
  etwPatched: boolean
  details: string[]
  riskScore: number
}

// ── Byte patterns ──────────────────────────────

// AMSI patch: mov eax, 0x80070057 (E_INVALIDARG) ; ret
const AMSI_PATCH_X64: number[] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]

// AMSI patch v2: xor eax, eax ; ret  (3 bytes — короткий, проверяем осторожно)
const AMSI_PATCH_X64_V2: number[] = [0x31, 0xC0, 0xC3]

// ETW patch x64: xor rax, rax ; ret
const ETW_PATCH_X64: number[] = [0x48, 0x33, 0xC0, 0xC3]

// ETW patch x86: xor eax, eax ; ret 0x14
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

/** Проверяет, загружена ли amsi.dll в процессе (через PowerShell) */
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

/** Сканировать процесс на предмет AMSI/ETW патчей */
export function scanProcessForAmsiEtw(pid: number, processName: string, existingDumpPath?: string): PatchResult {
  const result: PatchResult = { amsiPatched: false, etwPatched: false, details: [], riskScore: 0 }

  // 1. Проверяем, загружена ли amsi.dll в процессе, где её быть не должно
  const scriptHosts = ['powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'cmd.exe', 'mshta.exe']
  const isScriptHost = scriptHosts.some(h => processName.toLowerCase().includes(h.replace('.exe', '')))

  if (!isScriptHost && isAmsiLoaded(pid)) {
    result.details.push('amsi.dll loaded in non-script process — unusual')
    result.riskScore += 20
  }

  // 2. Дампим (если нет готового дампа) и анализируем
  const shouldDelete = !existingDumpPath
  const dumpPath = existingDumpPath || path.join(os.tmpdir(), `predator_etw_${pid}_${Date.now()}.dmp`)
  if (!existingDumpPath) {
    const dumpResult = dumpProcessMemory(pid, processName)
    if (!dumpResult) return result
    // dumpProcessMemory returns a path; copy the file to our expected path
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
        if (pat.name.startsWith('AMSI')) {
          result.amsiPatched = true
          result.riskScore += 40
        }
        if (pat.name.startsWith('ETW')) {
          result.etwPatched = true
          result.riskScore += 35
        }
      }
    }

    // Дополнительно: ищем строки "AmsiScanBuffer", "EtwEventWrite" в памяти
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
  } catch { /* ignore */ }
  finally {
    // Only delete if we created the dump (caller owns it when existingDumpPath is provided)
    if (!existingDumpPath) {
      try { fs.unlinkSync(dumpPath) } catch { /* ignore */ }
    }
  }

  return result
}

/** Быстрая проверка: ищет паттерны в уже существующем дампе */
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
  } catch { /* ignore */ }

  return result
}
