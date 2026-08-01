import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'

import { analyzePeHeaders, analyzeSectionEntropy } from '../cheat-rules'

const TMP_DIR = path.join(os.tmpdir(), `predator-pe-test-${Date.now()}`)
const PE_PATH = path.join(TMP_DIR, 'sample.exe')
const MALFORMED_PATH = path.join(TMP_DIR, 'malformed.exe')

function createMinimalPe(): Buffer {
  const buffer = Buffer.alloc(0x400)

  // DOS header and e_lfanew.
  buffer[0] = 0x4D
  buffer[1] = 0x5A
  buffer.writeUInt32LE(0x80, 0x3C)

  // PE signature.
  buffer.writeUInt32LE(0x00004550, 0x80)

  // COFF header: one section, executable image.
  const coff = 0x84
  buffer.writeUInt16LE(0x014C, coff)
  buffer.writeUInt16LE(1, coff + 2)
  buffer.writeUInt16LE(0x0102, coff + 18)

  // PE32 optional header with a console subsystem and entry point in .text.
  const optional = coff + 20
  buffer.writeUInt16LE(0xF8, coff + 16)
  buffer.writeUInt16LE(0x010B, optional)
  buffer.writeUInt32LE(0x1000, optional + 16)
  buffer.writeUInt16LE(3, optional + 68)

  // One .text section.
  const section = optional + 0xF8
  buffer.write('.text', section, 'ascii')
  buffer.writeUInt32LE(0x1000, section + 8)
  buffer.writeUInt32LE(0x1000, section + 12)
  buffer.writeUInt32LE(0x200, section + 16)
  buffer.writeUInt32LE(0x200, section + 20)

  return buffer
}

describe('async PE analysis', () => {
  beforeAll(() => {
    fs.mkdirSync(TMP_DIR, { recursive: true })
    fs.writeFileSync(PE_PATH, createMinimalPe())
    fs.writeFileSync(MALFORMED_PATH, Buffer.concat([
      Buffer.from('MZ', 'ascii'),
      Buffer.alloc(0x3A),
      Buffer.from([0x80, 0, 0, 0]),
      Buffer.alloc(0x40),
    ]))
  })

  afterAll(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true })
  })

  it('parses a valid PE header without changing the result contract', async () => {
    await expect(analyzePeHeaders(PE_PATH)).resolves.toMatchObject({
      isValidPe: true,
      sectionCount: 1,
      suspiciousSections: [],
      isSuspicious: false,
      subsystem: 'WINDOWS_CUI',
      relocsStripped: false,
      entryPointInSuspiciousSection: false,
      peSuspicionScore: 0,
    })
  })

  it('returns an invalid PE result for a truncated PE signature', async () => {
    await expect(analyzePeHeaders(MALFORMED_PATH)).resolves.toMatchObject({
      isValidPe: false,
      sectionCount: 0,
      suspiciousSections: [],
    })
  })

  it('analyzes section entropy asynchronously and preserves section metadata', async () => {
    const sections = await analyzeSectionEntropy(PE_PATH)
    expect(sections).toHaveLength(1)
    expect(sections[0]).toMatchObject({
      name: '.text',
      rawOffset: 0x200,
      rawSize: 0x200,
      virtualSize: 0x1000,
      entropy: 0,
      isSuspicious: true,
    })
  })

  it('stops before opening a file when already aborted', async () => {
    const controller = new AbortController()
    controller.abort()

    await expect(analyzePeHeaders(PE_PATH, controller.signal)).rejects.toThrow('aborted')
    await expect(analyzeSectionEntropy(PE_PATH, controller.signal)).rejects.toThrow('aborted')
  })

  it('returns null or an empty list for a non-PE file', async () => {
    const textPath = path.join(TMP_DIR, 'text.bin')
    fs.writeFileSync(textPath, Buffer.from('not a PE file'))

    await expect(analyzePeHeaders(textPath)).resolves.toBeNull()
    await expect(analyzeSectionEntropy(textPath)).resolves.toEqual([])
  })
})
