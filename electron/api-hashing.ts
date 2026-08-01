/**
 * Predator API-Hashing Detector
 *
 * Читы скрывают импорты, вычисляя хеш имени API и находя его через PEB.
 * Детектим по:
 *   1. Пустой / крошечной Import Table (только kernel32/ntdll, но файл 2+ МБ)
 *   2. Байтовые паттерны в памяти: PEB access, ROR13, DJB2
 *   3. Строки LdrLoadDll, LdrGetProcedureAddress в дампе
 */

import fsp from 'fs/promises'
import { readFilePrefix, readFileRange } from './utils/file-io'
import { yieldToEventLoop } from './types'

// ── Types ──────────────────────────────────────

export interface PeImportInfo {
  dlls: string[]
  dllCount: number
  totalImports: number
  isPackedOrHashed: boolean
}

export interface ApiHashingResult {
  detected: boolean
  confidence: number // 0–100
  patterns: string[]
}

interface BytePattern {
  name: string
  bytes: number[]
  mask?: number[]
  description: string
  risk: number
}

function emptyResult(): ApiHashingResult {
  return { detected: false, confidence: 0, patterns: [] }
}

// ── PE Import Parser (zero deps) ───────────────

function rvaToFileOffset(rva: number, sections: { va: number; raw: number; size: number }[]): number {
  for (const sec of sections) {
    if (rva >= sec.va && rva < sec.va + sec.size) {
      return sec.raw + (rva - sec.va)
    }
  }
  return -1
}

function isValidFileRange(offset: number, size: number, fileSize: number): boolean {
  return Number.isSafeInteger(offset) && offset >= 0 &&
    Number.isSafeInteger(size) && size >= 0 && offset <= fileSize && size <= fileSize - offset
}

function readAscii(buffer: Buffer): string {
  let value = ''
  for (let i = 0; i < buffer.length && buffer[i] !== 0; i++) {
    value += String.fromCharCode(buffer[i])
  }
  return value
}

/** Parse the Import Table without blocking the Electron main process. */
export async function parsePeImports(
  filepath: string,
  signal?: AbortSignal,
): Promise<PeImportInfo | null> {
  try {
    const stat = await fsp.stat(filepath)
    if (stat.size < 64) return null

    const buf = await readFilePrefix(filepath, Math.min(4096, stat.size), signal)
    if (buf.length < 64 || buf[0] !== 0x4D || buf[1] !== 0x5A) return null

    const peOff = buf.readUInt32LE(0x3C)
    if (peOff + 24 > buf.length ||
        buf[peOff] !== 0x50 || buf[peOff + 1] !== 0x45 ||
        buf[peOff + 2] !== 0 || buf[peOff + 3] !== 0) return null

    const coffOff = peOff + 4
    const numSections = buf.readUInt16LE(coffOff + 2)
    const optHeaderSize = buf.readUInt16LE(coffOff + 16)
    const optOff = coffOff + 20
    if (optHeaderSize === 0 || optOff + optHeaderSize > buf.length) return null

    const magic = buf.readUInt16LE(optOff)
    const ddOff = magic === 0x20B ? optOff + 112 : optOff + 96
    if (ddOff + 16 > optOff + optHeaderSize || ddOff + 16 > buf.length) return null
    const importRva = buf.readUInt32LE(ddOff + 8)

    if (magic !== 0x10B && magic !== 0x20B) return null

    const secOff = optOff + optHeaderSize
    const sectionCount = Math.min(numSections, 30)
    const sectionTableSize = sectionCount * 40
    if (!isValidFileRange(secOff, sectionTableSize, stat.size)) return null

    const sectionTable = secOff + sectionTableSize <= buf.length
      ? buf.subarray(secOff, secOff + sectionTableSize)
      : await readFileRange(filepath, secOff, sectionTableSize, signal)
    if (sectionTable.length < sectionTableSize) return null

    const sections: { va: number; raw: number; size: number }[] = []
    for (let i = 0; i < sectionCount; i++) {
      const o = i * 40
      sections.push({
        va: sectionTable.readUInt32LE(o + 12),
        raw: sectionTable.readUInt32LE(o + 20),
        size: sectionTable.readUInt32LE(o + 8),
      })
    }

    if (importRva === 0) {
      return { dlls: [], dllCount: 0, totalImports: 0, isPackedOrHashed: stat.size > 512 * 1024 }
    }

    const importOff = rvaToFileOffset(importRva, sections)
    if (!isValidFileRange(importOff, 1, stat.size)) {
      return { dlls: [], dllCount: 0, totalImports: 0, isPackedOrHashed: true }
    }

    const idBuf = await readFileRange(filepath, importOff, Math.min(4096, stat.size - importOff), signal)
    const dlls: string[] = []
    let totalImports = 0

    for (let i = 0; i < 80; i++) {
      if (signal?.aborted) throw new Error('API hashing analysis aborted')
      const dOff = i * 20
      if (dOff + 20 > idBuf.length) break

      const nameRva = idBuf.readUInt32LE(dOff + 12)
      const origFirstThunk = idBuf.readUInt32LE(dOff)
      const firstThunk = idBuf.readUInt32LE(dOff + 16)
      if (nameRva === 0) break

      const nameOff = rvaToFileOffset(nameRva, sections)
      if (isValidFileRange(nameOff, 1, stat.size)) {
        const nBuf = await readFileRange(filepath, nameOff, Math.min(64, stat.size - nameOff), signal)
        const name = readAscii(nBuf)
        if (name) dlls.push(name.toLowerCase())
      }

      const thunkRva = origFirstThunk || firstThunk
      if (thunkRva === 0) continue
      const thunkOff = rvaToFileOffset(thunkRva, sections)
      if (!isValidFileRange(thunkOff, 4, stat.size)) continue

      const tBuf = await readFileRange(filepath, thunkOff, Math.min(512, stat.size - thunkOff), signal)
      for (let t = 0; t < 128 && t * 4 + 4 <= tBuf.length; t++) {
        const value = tBuf.readUInt32LE(t * 4)
        if (value === 0) break
        if ((value & 0x80000000) === 0) totalImports++
      }
    }

    const isPackedOrHashed = dlls.length < 3 && stat.size > 1024 * 1024
    return { dlls, dllCount: dlls.length, totalImports, isPackedOrHashed }
  } catch (err) {
    if (signal?.aborted) throw err
    return null
  }
}

// ── Byte-pattern scanner ───────────────────────

async function scanBufferPatterns(
  buf: Buffer,
  patterns: BytePattern[],
  signal?: AbortSignal,
): Promise<{ name: string; count: number; description: string; risk: number }[]> {
  const hits: { name: string; count: number; description: string; risk: number }[] = []
  for (const p of patterns) {
    const bytes = p.bytes
    const mask = p.mask || bytes.map(() => 0xFF)
    let count = 0
    outer: for (let i = 0; i <= buf.length - bytes.length; i++) {
      if ((i & 0xFFFFF) === 0) {
        if (signal?.aborted) throw new Error('API hashing analysis aborted')
        await yieldToEventLoop()
      }
      for (let j = 0; j < bytes.length; j++) {
        if ((buf[i + j] & mask[j]) !== (bytes[j] & mask[j])) continue outer
      }
      count++
    }
    if (count > 0) hits.push({ name: p.name, count, description: p.description, risk: p.risk })
  }
  return hits
}

const API_HASHING_PATTERNS: BytePattern[] = [
  { name: 'PEB_x64', bytes: [0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00], description: 'mov rax, gs:[0x60] — PEB access', risk: 25 },
  { name: 'PEB_x64_rcx', bytes: [0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00], description: 'mov rcx, gs:[0x60] — PEB access', risk: 25 },
  { name: 'PEB_x86', bytes: [0x64, 0xA1, 0x30, 0x00, 0x00, 0x00], description: 'mov eax, fs:[0x30] — PEB access', risk: 25 },
  { name: 'ROR13_ecx', bytes: [0xC1, 0xC9, 0x0D], description: 'ror ecx, 0x0D — API hash (Metasploit style)', risk: 35 },
  { name: 'ROR13_eax', bytes: [0xC1, 0xC8, 0x0D], description: 'ror eax, 0x0D — API hash', risk: 35 },
  { name: 'DJB2', bytes: [0x69, 0xC0, 0x83, 0x00, 0x00, 0x00], description: 'imul eax, 0x83 — DJB2 hash multiplier', risk: 20 },
]

const SUSPICIOUS_STRINGS = ['LdrLoadDll', 'LdrGetProcedureAddress', 'RtlInitUnicodeString', 'PEB_LDR_DATA', 'InLoadOrderModuleList']

// ── Public API ─────────────────────────────────

/** Static PE analysis: few imports may indicate API hashing or packing. */
export async function analyzeApiHashingStatic(
  filepath: string,
  signal?: AbortSignal,
): Promise<ApiHashingResult> {
  const info = await parsePeImports(filepath, signal)
  if (!info) return emptyResult()

  const patterns: string[] = []
  let score = 0

  if (info.isPackedOrHashed) {
    patterns.push(`Only ${info.dllCount} DLLs imported but file size is large`)
    score += 40
  }

  if (info.dllCount === 0 && info.totalImports === 0) {
    patterns.push('Import Table is completely empty — fully dynamic imports')
    score += 50
  }

  if (info.totalImports > 0 && info.totalImports < 15 && info.dllCount <= 2) {
    patterns.push(`Extremely few imports (${info.totalImports}) — likely API hashing`)
    score += 35
  }

  try {
    const stat = await fsp.stat(filepath)
    const buf = await readFilePrefix(filepath, Math.min(stat.size, 50 * 1024 * 1024), signal)
    const patHits = await scanBufferPatterns(buf, API_HASHING_PATTERNS, signal)
    for (const h of patHits) {
      patterns.push(`${h.name} (${h.count}x) — ${h.description}`)
      score += h.risk
    }
  } catch (err) {
    if (signal?.aborted) throw err
    console.warn('[api-hashing] failed:', (err as Error).message)
  }

  return { detected: score >= 40, confidence: Math.min(score, 100), patterns }
}

/** Analyze a memory dump: unpacked hash loops and loader strings are visible. */
export async function analyzeApiHashingInDump(
  filepath: string,
  signal?: AbortSignal,
): Promise<ApiHashingResult> {
  const patterns: string[] = []
  let score = 0

  try {
    const stat = await fsp.stat(filepath)
    if (!stat.isFile() || stat.size < 64) return emptyResult()

    const chunk = await readFilePrefix(filepath, Math.min(stat.size, 50 * 1024 * 1024), signal)
    const hits = await scanBufferPatterns(chunk, API_HASHING_PATTERNS, signal)
    for (const h of hits) {
      patterns.push(`${h.name} (${h.count}x) — ${h.description}`)
      score += h.risk
    }

    const ascii: string[] = []
    let cur = ''
    for (let i = 0; i < chunk.length; i++) {
      if ((i & 0xFFFF) === 0 && signal?.aborted) throw new Error('API hashing analysis aborted')
      const b = chunk[i]
      if (b >= 0x20 && b <= 0x7E) {
        cur += String.fromCharCode(b)
      } else {
        if (cur.length >= 6) ascii.push(cur)
        cur = ''
      }
    }

    if (cur.length >= 6) ascii.push(cur)

    const set = new Set(ascii)
    for (const kw of SUSPICIOUS_STRINGS) {
      if (set.has(kw)) {
        patterns.push(`String: ${kw}`)
        score += 15
      }
    }
  } catch (err) {
    if (signal?.aborted) throw err
    console.warn('[api-hashing] failed:', (err as Error).message)
  }

  return { detected: score >= 40, confidence: Math.min(score, 100), patterns }
}
