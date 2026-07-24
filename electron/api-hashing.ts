/**
 * Predator API-Hashing Detector
 * 
 * Читы скрывают импорты, вычисляя хеш имени API и находя его через PEB.
 * Детектим по:
 *   1. Пустой / крошечной Import Table (только kernel32/ntdll, но файл 2+ МБ)
 *   2. Байтовые паттерны в памяти: PEB access, ROR13, DJB2
 *   3. Строки LdrLoadDll, LdrGetProcedureAddress в дампе
 */

import fs from 'fs'

// ── Types ──────────────────────────────────────

interface PeImportInfo {
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

// ── PE Import Parser (zero deps) ───────────────

function rvaToFileOffset(rva: number, sections: { va: number; raw: number; size: number }[]): number {
  for (const sec of sections) {
    if (rva >= sec.va && rva < sec.va + sec.size) {
      return sec.raw + (rva - sec.va)
    }
  }
  return -1
}

/** Парсит Import Table: считает DLL и примерное количество импортов */
export function parsePeImports(filepath: string): PeImportInfo | null {
  try {
    const stat = fs.statSync(filepath)
    if (stat.size < 64) return null

    const buf = Buffer.alloc(1024)
    const fd = fs.openSync(filepath, 'r')
    fs.readSync(fd, buf, 0, 1024, 0)
    fs.closeSync(fd)

    if (buf[0] !== 0x4D || buf[1] !== 0x5A) return null

    const peOff = buf.readUInt32LE(0x3C)
    if (peOff + 24 > 1024) return null
    if (buf[peOff] !== 0x50 || buf[peOff + 1] !== 0x45) return null

    const coffOff = peOff + 4
    const numSections = buf.readUInt16LE(coffOff + 2)
    const optHeaderSize = buf.readUInt16LE(coffOff + 16)

    const optOff = coffOff + 20
    const magic = buf.readUInt16LE(optOff)

    // DataDirectory[1] = Import Directory
    const ddOff = magic === 0x20B ? optOff + 112 : optOff + 96
    const importRva = buf.readUInt32LE(ddOff + 8)

    // Sections
    const secOff = optOff + optHeaderSize
    const sections: { va: number; raw: number; size: number }[] = []
    for (let i = 0; i < numSections && i < 30; i++) {
      const o = secOff + i * 40
      if (o + 40 > 1024) break
      sections.push({
        va: buf.readUInt32LE(o + 12),
        raw: buf.readUInt32LE(o + 20),
        size: buf.readUInt32LE(o + 8),
      })
    }

    if (importRva === 0) {
      return { dlls: [], dllCount: 0, totalImports: 0, isPackedOrHashed: stat.size > 512 * 1024 }
    }

    const importOff = rvaToFileOffset(importRva, sections)
    if (importOff < 0 || importOff >= stat.size) {
      return { dlls: [], dllCount: 0, totalImports: 0, isPackedOrHashed: true }
    }

    // Read up to 4KB of import directory
    const idBuf = Buffer.alloc(4096)
    const fd2 = fs.openSync(filepath, 'r')
    fs.readSync(fd2, idBuf, 0, 4096, importOff)
    fs.closeSync(fd2)

    const dlls: string[] = []
    let totalImports = 0

    for (let i = 0; i < 80; i++) {
      const dOff = i * 20
      const nameRva = idBuf.readUInt32LE(dOff + 12)
      const origFirstThunk = idBuf.readUInt32LE(dOff)
      const firstThunk = idBuf.readUInt32LE(dOff + 16)
      if (nameRva === 0) break

      const nameOff = rvaToFileOffset(nameRva, sections)
      if (nameOff >= 0 && nameOff < stat.size - 64) {
        const nBuf = Buffer.alloc(64)
        const fd3 = fs.openSync(filepath, 'r')
        fs.readSync(fd3, nBuf, 0, 64, nameOff)
        fs.closeSync(fd3)
        let name = ''
        for (let j = 0; j < 64 && nBuf[j] !== 0; j++) name += String.fromCharCode(nBuf[j])
        if (name) dlls.push(name.toLowerCase())
      }

      // Count thunks
      const thunkRva = origFirstThunk || firstThunk
      if (thunkRva) {
        const thunkOff = rvaToFileOffset(thunkRva, sections)
        if (thunkOff >= 0 && thunkOff < stat.size - 512) {
          const tBuf = Buffer.alloc(512)
          const fd4 = fs.openSync(filepath, 'r')
          fs.readSync(fd4, tBuf, 0, 512, thunkOff)
          fs.closeSync(fd4)
          for (let t = 0; t < 128; t++) {
            const v = tBuf.readUInt32LE(t * 4)
            if (v === 0) break
            if ((v & 0x80000000) === 0) totalImports++
          }
        }
      }
    }

    const isPackedOrHashed = dlls.length < 3 && stat.size > 1024 * 1024
    return { dlls, dllCount: dlls.length, totalImports, isPackedOrHashed }
  } catch {
    return null
  }
}

// ── Byte-pattern scanner ───────────────────────

function scanBufferPatterns(buf: Buffer, patterns: BytePattern[]) {
  const hits: { name: string; count: number; description: string; risk: number }[] = []
  for (const p of patterns) {
    const bytes = p.bytes
    const mask = p.mask || bytes.map(() => 0xFF)
    let count = 0
    outer: for (let i = 0; i <= buf.length - bytes.length; i++) {
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

/** Статический анализ PE: мало импортов = API hashing / packing */
export function analyzeApiHashingStatic(filepath: string): ApiHashingResult {
  const info = parsePeImports(filepath)
  if (!info) return { detected: false, confidence: 0, patterns: [] }

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

  // Also scan file content for patterns
  try {
    const buf = fs.readFileSync(filepath)
    const patHits = scanBufferPatterns(buf, API_HASHING_PATTERNS)
    for (const h of patHits) {
      patterns.push(`${h.name} (${h.count}x) — ${h.description}`)
      score += h.risk
    }
  } catch { /* ignore */ }

  return { detected: score >= 40, confidence: Math.min(score, 100), patterns }
}

/** Анализ дампа памяти: чит уже распакован, хеш-циклы видны */
export function analyzeApiHashingInDump(filepath: string): ApiHashingResult {
  const patterns: string[] = []
  let score = 0

  try {
    const stat = fs.statSync(filepath)
    if (!stat.isFile() || stat.size < 64) return { detected: false, confidence: 0, patterns: [] }

    const fd = fs.openSync(filepath, 'r')
    const chunkSize = Math.min(stat.size, 50 * 1024 * 1024)
    const chunk = Buffer.alloc(chunkSize)
    fs.readSync(fd, chunk, 0, chunkSize, 0)
    fs.closeSync(fd)

    const hits = scanBufferPatterns(chunk, API_HASHING_PATTERNS)
    for (const h of hits) {
      patterns.push(`${h.name} (${h.count}x) — ${h.description}`)
      score += h.risk
    }

    // String search in dump
    const ascii: string[] = []
    let cur = ''
    for (let i = 0; i < chunk.length; i++) {
      const b = chunk[i]
      if (b >= 0x20 && b <= 0x7E) {
        cur += String.fromCharCode(b)
      } else {
        if (cur.length >= 6) ascii.push(cur)
        cur = ''
      }
    }

    const set = new Set(ascii)
    for (const kw of SUSPICIOUS_STRINGS) {
      if (set.has(kw)) {
        patterns.push(`String: ${kw}`)
        score += 15
      }
    }
  } catch { /* ignore */ }

  return { detected: score >= 40, confidence: Math.min(score, 100), patterns }
}
