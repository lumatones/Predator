import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'

import {
  parsePeImports,
  analyzeApiHashingStatic,
  analyzeApiHashingInDump,
} from '../api-hashing'

const TMP_DIR = path.join(os.tmpdir(), `predator-api-hashing-${Date.now()}`)
const LARGE_PE_PATH = path.join(TMP_DIR, 'large-empty-imports.exe')
const MALFORMED_PATH = path.join(TMP_DIR, 'malformed.bin')
const DUMP_PATH = path.join(TMP_DIR, 'memory.dmp')

function createLargeEmptyImportPe(): Buffer {
  const buffer = Buffer.alloc(4096)
  buffer[0] = 0x4D
  buffer[1] = 0x5A
  buffer.writeUInt32LE(0x80, 0x3C)

  buffer.writeUInt32LE(0x00004550, 0x80)
  const coff = 0x84
  buffer.writeUInt16LE(0x014C, coff)
  buffer.writeUInt16LE(1, coff + 2)
  buffer.writeUInt16LE(0xF8, coff + 16)

  const optional = coff + 20
  buffer.writeUInt16LE(0x010B, optional)
  // Import RVA is zero: the import table is empty.
  return buffer
}

describe('async API hashing analysis', () => {
  beforeAll(() => {
    fs.mkdirSync(TMP_DIR, { recursive: true })

    const largePe = createLargeEmptyImportPe()
    const fd = fs.openSync(LARGE_PE_PATH, 'w')
    fs.writeSync(fd, largePe)
    fs.ftruncateSync(fd, 600 * 1024)
    fs.closeSync(fd)

    fs.writeFileSync(MALFORMED_PATH, Buffer.from('not a PE or dump'))
    fs.writeFileSync(DUMP_PATH, Buffer.concat([
      Buffer.from([0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00]),
      Buffer.from([0xC1, 0xC9, 0x0D]),
      Buffer.from('LdrLoadDll\0', 'ascii'),
      Buffer.alloc(64),
    ]))
  })

  afterAll(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true })
  })

  it('parses an empty Import Table asynchronously', async () => {
    await expect(parsePeImports(LARGE_PE_PATH)).resolves.toMatchObject({
      dlls: [],
      dllCount: 0,
      totalImports: 0,
      isPackedOrHashed: true,
    })
  })

  it('preserves static API hashing thresholds for empty imports', async () => {
    const result = await analyzeApiHashingStatic(LARGE_PE_PATH)
    expect(result.detected).toBe(true)
    expect(result.confidence).toBe(90)
    expect(result.patterns).toEqual(expect.arrayContaining([
      expect.stringContaining('Import Table is completely empty'),
      expect.stringContaining('file size is large'),
    ]))
  })

  it('detects byte patterns and loader strings in a memory dump', async () => {
    const result = await analyzeApiHashingInDump(DUMP_PATH)
    expect(result.detected).toBe(true)
    expect(result.confidence).toBeGreaterThanOrEqual(40)
    expect(result.patterns).toEqual(expect.arrayContaining([
      expect.stringContaining('PEB_x64'),
      expect.stringContaining('ROR13_ecx'),
      expect.stringContaining('String: LdrLoadDll'),
    ]))
  })

  it('returns an empty result for malformed or undersized inputs', async () => {
    await expect(parsePeImports(MALFORMED_PATH)).resolves.toBeNull()
    await expect(analyzeApiHashingInDump(MALFORMED_PATH)).resolves.toEqual({
      detected: false,
      confidence: 0,
      patterns: [],
    })
  })

  it('propagates cancellation before starting file analysis', async () => {
    const controller = new AbortController()
    controller.abort()

    await expect(parsePeImports(LARGE_PE_PATH, controller.signal)).rejects.toThrow('aborted')
    await expect(analyzeApiHashingStatic(LARGE_PE_PATH, controller.signal)).rejects.toThrow('aborted')
    await expect(analyzeApiHashingInDump(DUMP_PATH, controller.signal)).rejects.toThrow('aborted')
  })
})
