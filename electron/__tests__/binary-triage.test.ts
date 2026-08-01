import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import fs from 'fs'
import os from 'os'
import path from 'path'

const { signatureStatus, ipcHandle, showOpenDialog } = vi.hoisted(() => ({
  signatureStatus: vi.fn(),
  ipcHandle: vi.fn(),
  showOpenDialog: vi.fn(),
}))

vi.mock('../heuristic/signature-batch', () => ({
  checkDigitalSignatureStatus: signatureStatus,
}))

vi.mock('electron', () => ({
  ipcMain: { handle: ipcHandle },
  dialog: { showOpenDialog },
}))

import { analyzeBinaryTriage, registerBinaryTriageHandler } from '../binary-triage'

const TMP_DIR = path.join(os.tmpdir(), `predator-binary-triage-${Date.now()}`)

function createMinimalPe(): Buffer {
  const buffer = Buffer.alloc(0x800)
  buffer[0] = 0x4d
  buffer[1] = 0x5a
  buffer.writeUInt32LE(0x80, 0x3c)
  buffer.writeUInt32LE(0x00004550, 0x80)

  const coff = 0x84
  buffer.writeUInt16LE(0x014c, coff)
  buffer.writeUInt16LE(1, coff + 2)
  buffer.writeUInt16LE(0x00e0, coff + 16)
  buffer.writeUInt16LE(0x0102, coff + 18)

  const optional = coff + 20
  buffer.writeUInt16LE(0x010b, optional)
  buffer.writeUInt32LE(0x1000, optional + 16)
  buffer.writeUInt32LE(0x400000, optional + 28)
  buffer.writeUInt32LE(0x200, optional + 32)
  buffer.writeUInt32LE(0x200, optional + 36)
  buffer.writeUInt32LE(0x2000, optional + 56)
  buffer.writeUInt32LE(0x200, optional + 60)
  buffer.writeUInt16LE(3, optional + 68)
  buffer.writeUInt32LE(16, optional + 92)

  const section = optional + 0xe0
  buffer.write('.packed', section, 'ascii')
  buffer.writeUInt32LE(0x1000, section + 8)
  buffer.writeUInt32LE(0x1000, section + 12)
  buffer.writeUInt32LE(0x600, section + 16)
  buffer.writeUInt32LE(0x200, section + 20)
  buffer.writeUInt32LE(0x60000020, section + 36)
  buffer.fill(0xa5, 0x200, 0x800)
  return buffer
}

describe('binary triage', () => {
  beforeEach(() => {
    fs.mkdirSync(TMP_DIR, { recursive: true })
    signatureStatus.mockReset()
    signatureStatus.mockResolvedValue('unsigned')
    ipcHandle.mockReset()
    showOpenDialog.mockReset()
  })

  afterEach(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true })
  })

  it('returns a static-only report with PE sections and unsigned status', async () => {
    const filePath = path.join(TMP_DIR, 'sample.exe')
    fs.writeFileSync(filePath, createMinimalPe())

    const report = await analyzeBinaryTriage(filePath)

    expect(report.staticOnly).toBe(true)
    expect(report.file.signatureStatus).toBe('unsigned')
    expect(report.file.signed).toBe(false)
    expect(report.pe.valid).toBe(true)
    expect(report.pe.architecture).toBe('x86')
    expect(report.pe.entryPointSection).toBe('.packed')
    expect(report.pe.sections[0]).toMatchObject({ name: '.packed', rawBacked: true, executable: true })
    expect(report.indicators.some(indicator => indicator.id === 'unsigned')).toBe(true)
    expect(report.indicators.some(indicator => indicator.id === 'section-names')).toBe(true)
    expect(report.indicators.some(indicator => indicator.id === 'high-entropy')).toBe(false)
    expect(report.limitations.some(item => item.includes('Static-only'))).toBe(true)
  })

  it('preserves unknown signature state instead of calling it unsigned', async () => {
    signatureStatus.mockResolvedValue('unknown')
    const filePath = path.join(TMP_DIR, 'unknown.exe')
    fs.writeFileSync(filePath, createMinimalPe())

    const report = await analyzeBinaryTriage(filePath)

    expect(report.file.signatureStatus).toBe('unknown')
    expect(report.indicators.some(indicator => indicator.id === 'signature-unknown')).toBe(true)
    expect(report.indicators.some(indicator => indicator.id === 'unsigned')).toBe(false)
  })

  it('rejects unsupported extensions before reading the file', async () => {
    const filePath = path.join(TMP_DIR, 'sample.txt')
    fs.writeFileSync(filePath, 'not an executable')

    await expect(analyzeBinaryTriage(filePath)).rejects.toThrow('Unsupported binary extension')
    expect(signatureStatus).not.toHaveBeenCalled()
  })

  it('reports valid signature status with signed=true', async () => {
    signatureStatus.mockResolvedValue('valid')
    const filePath = path.join(TMP_DIR, 'signed.exe')
    fs.writeFileSync(filePath, createMinimalPe())

    const report = await analyzeBinaryTriage(filePath)

    expect(report.file.signatureStatus).toBe('valid')
    expect(report.file.signed).toBe(true)
    expect(report.indicators.some(indicator => indicator.id === 'unsigned')).toBe(false)
    expect(report.indicators.some(indicator => indicator.id === 'signature-unknown')).toBe(false)
  })

  it('registers a native file-picker IPC handler', () => {
    registerBinaryTriageHandler()
    expect(ipcHandle).toHaveBeenCalledWith('triage-binary', expect.any(Function))
  })
})
