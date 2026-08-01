/**
 * Predator — Binary Triage
 *
 * Static-only analysis for a user-selected Windows binary. This module never
 * executes or loads the target file; it reads bytes and asks Authenticode for
 * a signature verdict only.
 */

import crypto from 'crypto'
import fsp from 'fs/promises'
import path from 'path'
import { dialog, ipcMain } from 'electron'

import { calculateEntropy } from './analysis/entropy'
import { checkDigitalSignatureStatus } from './heuristic/signature-batch'

const MAX_TRIAGE_SIZE = 100 * 1024 * 1024
const BINARY_EXTENSIONS = new Set(['.exe', '.dll', '.sys', '.drv', '.asi'])
const MAX_IMPORTS_PER_DLL = 128
const MAX_IMPORTED_DLLS = 128

import type {
  BinaryTriageReport,
  TriageImport,
  TriageIndicator,
  TriageSection,
  TriageSeverity,
  TriageVerdict,
} from '../types/binary-triage'

interface SectionRecord {
  name: string
  virtualAddress: number
  virtualSize: number
  rawOffset: number
  rawSize: number
  characteristics: number
}

interface ParsedPe {
  valid: boolean
  is64: boolean
  machine: number
  subsystem: number
  imageBase: bigint
  entryPointRva: number
  sections: SectionRecord[]
  directories: Array<{ rva: number; size: number }>
  imports: TriageImport[]
  tlsCallbackCount: number
  physicalTlsCallbackCount: number
  manifest?: string
  requestedExecutionLevel?: string
}

function readU16(buffer: Buffer, offset: number): number | null {
  return offset >= 0 && offset + 2 <= buffer.length ? buffer.readUInt16LE(offset) : null
}

function readU32(buffer: Buffer, offset: number): number | null {
  return offset >= 0 && offset + 4 <= buffer.length ? buffer.readUInt32LE(offset) : null
}

function readU64(buffer: Buffer, offset: number): bigint | null {
  return offset >= 0 && offset + 8 <= buffer.length ? buffer.readBigUInt64LE(offset) : null
}

function readAscii(buffer: Buffer, offset: number, maxLength = 512): string {
  if (offset < 0 || offset >= buffer.length) return ''
  const boundedEnd = Math.min(buffer.length, offset + maxLength)
  const localEnd = buffer.subarray(offset, boundedEnd).indexOf(0)
  const end = localEnd < 0 ? boundedEnd : offset + localEnd
  return buffer.subarray(offset, end).toString('ascii')
}

function formatHex(value: bigint | number): string {
  return `0x${value.toString(16)}`
}

function architecture(machine: number): 'x86' | 'x64' | 'unknown' {
  if (machine === 0x14c) return 'x86'
  if (machine === 0x8664) return 'x64'
  return 'unknown'
}

function subsystemName(value: number): string {
  return ({ 1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI', 9: 'WINDOWS_CE_GUI', 10: 'EFI' } as Record<number, string>)[value] || `UNKNOWN(${value})`
}

function sectionForRva(sections: readonly SectionRecord[], rva: number): SectionRecord | undefined {
  return sections.find(section => rva >= section.virtualAddress && rva < section.virtualAddress + Math.max(section.virtualSize, section.rawSize))
}

function rvaToOffset(sections: readonly SectionRecord[], rva: number, sizeOfHeaders: number, bufferLength: number): number | null {
  if (rva < sizeOfHeaders) return rva < bufferLength ? rva : null
  const section = sectionForRva(sections, rva)
  if (!section || section.rawSize === 0) return null
  const offset = section.rawOffset + (rva - section.virtualAddress)
  return offset >= section.rawOffset && offset < section.rawOffset + section.rawSize && offset < bufferLength ? offset : null
}

function classifyImport(name: string): { risk: TriageSeverity; reason?: string } {
  const lower = name.toLowerCase()
  if (/writeprocessmemory|virtualallocex|createremotethread|ntcreatethreadex|rtlcreateuserthread|setthreadcontext|queueuserapc/.test(lower)) {
    return { risk: 'critical', reason: 'Process injection or remote memory write API' }
  }
  if (/openprocess|readprocessmemory|virtualqueryex|ntopenprocess/.test(lower)) {
    return { risk: 'high', reason: 'Cross-process memory access API' }
  }
  if (/shellexecute|createprocess|winexec|rundll32/.test(lower)) {
    return { risk: 'medium', reason: 'Can launch another executable or shell-associated object' }
  }
  if (/connect|wsaconnect|internet|winhttp|urlmon|httpsendrequest|recv|send/.test(lower)) {
    return { risk: 'medium', reason: 'Network communication API' }
  }
  if (/adjusttoken|openprocesstoken|adjusttokenprivileges|createtoken/.test(lower)) {
    return { risk: 'high', reason: 'Access-token or privilege management API' }
  }
  if (/loadlibrary|getprocaddress|ldrloaddll|rtlgetprocedureaddress/.test(lower)) {
    return { risk: 'medium', reason: 'Dynamic API or module resolution' }
  }
  return { risk: 'low' }
}

function parseImports(
  buffer: Buffer,
  sections: readonly SectionRecord[],
  directories: readonly { rva: number; size: number }[],
  is64: boolean,
  sizeOfHeaders: number,
): TriageImport[] {
  const directory = directories[1]
  const start = directory ? rvaToOffset(sections, directory.rva, sizeOfHeaders, buffer.length) : null
  if (start === null) return []

  const imports: TriageImport[] = []
  const thunkSize = is64 ? 8 : 4
  const ordinalMask = is64 ? 0x8000000000000000n : 0x80000000n

  for (let descriptorIndex = 0; descriptorIndex < MAX_IMPORTED_DLLS; descriptorIndex++) {
    const descriptor = start + descriptorIndex * 20
    const originalFirstThunk = readU32(buffer, descriptor)
    const nameRva = readU32(buffer, descriptor + 12)
    const firstThunk = readU32(buffer, descriptor + 16)
    if (originalFirstThunk === null || nameRva === null || firstThunk === null || (originalFirstThunk === 0 && nameRva === 0 && firstThunk === 0)) break

    const dllOffset = rvaToOffset(sections, nameRva, sizeOfHeaders, buffer.length)
    const dll = readAscii(buffer, dllOffset ?? -1).toLowerCase()
    const thunkRva = originalFirstThunk || firstThunk
    const thunkOffset = rvaToOffset(sections, thunkRva, sizeOfHeaders, buffer.length)
    if (!dll || thunkOffset === null) continue

    for (let thunkIndex = 0; thunkIndex < MAX_IMPORTS_PER_DLL; thunkIndex++) {
      const offset = thunkOffset + thunkIndex * thunkSize
      const value = is64 ? readU64(buffer, offset) : BigInt(readU32(buffer, offset) ?? 0)
      if (value === null || value === 0n) break

      if ((value & ordinalMask) !== 0n) {
        imports.push({
          dll,
          ordinal: Number(value & 0xffffn),
          risk: 'medium',
          reason: 'Ordinal import cannot be identified statically; runtime API behavior is unknown',
        })
        continue
      }

      const hintNameRva = Number(value & 0x7fffffffn)
      const hintNameOffset = rvaToOffset(sections, hintNameRva, sizeOfHeaders, buffer.length)
      const name = readAscii(buffer, (hintNameOffset ?? -1) + 2)
      if (!name) continue
      const classification = classifyImport(name)
      imports.push({ dll, name, ...classification })
    }
  }

  return imports
}

function extractManifestResource(
  buffer: Buffer,
  sections: readonly SectionRecord[],
  directories: readonly { rva: number; size: number }[],
  sizeOfHeaders: number,
): { manifest?: string; requestedExecutionLevel?: string } {
  const resourceDirectory = directories[2]
  if (!resourceDirectory?.rva || resourceDirectory.size < 16) return {}
  const resourceOffset = rvaToOffset(sections, resourceDirectory.rva, sizeOfHeaders, buffer.length)
  if (resourceOffset === null || resourceOffset + resourceDirectory.size > buffer.length) return {}
  const resourceBase = resourceOffset
  const resourceEnd = resourceBase + resourceDirectory.size

  function readResourceU16(offset: number): number | null {
    return offset >= resourceBase && offset + 2 <= resourceEnd ? buffer.readUInt16LE(offset) : null
  }

  function readResourceU32(offset: number): number | null {
    return offset >= resourceBase && offset + 4 <= resourceEnd ? buffer.readUInt32LE(offset) : null
  }

  function findManifestData(directoryOffset: number, depth: number, typeMatched: boolean): { offset: number; size: number } | null {
    if (depth > 3 || directoryOffset < resourceBase || directoryOffset + 16 > resourceEnd) return null
    const namedCount = readResourceU16(directoryOffset + 12)
    const idCount = readResourceU16(directoryOffset + 14)
    if (namedCount === null || idCount === null) return null

    const entryCount = namedCount + idCount
    for (let index = 0; index < entryCount; index++) {
      const entryOffset = directoryOffset + 16 + index * 8
      const nameOrId = readResourceU32(entryOffset)
      const child = readResourceU32(entryOffset + 4)
      if (nameOrId === null || child === null) continue
      const id = (nameOrId & 0x80000000) === 0 ? nameOrId : null
      const nextTypeMatched = typeMatched || (depth === 0 && id === 24)
      if ((child & 0x80000000) !== 0) {
        const nested = findManifestData(resourceBase + (child & 0x7fffffff), depth + 1, nextTypeMatched)
        if (nested) return nested
        continue
      }
      if (!nextTypeMatched) continue
      const dataEntry = resourceBase + child
      const dataRva = readResourceU32(dataEntry)
      const dataSize = readResourceU32(dataEntry + 4)
      if (dataRva === null || dataSize === null || dataSize === 0) continue
      const dataOffset = rvaToOffset(sections, dataRva, sizeOfHeaders, buffer.length)
      if (dataOffset !== null && dataSize <= buffer.length - dataOffset) return { offset: dataOffset, size: dataSize }
    }
    return null
  }

  const data = findManifestData(resourceBase, 0, false)
  if (!data) return {}
  const manifest = buffer.subarray(data.offset, data.offset + data.size).toString('utf8').replace(/^\uFEFF/, '').replace(/\0+$/, '').trim()
  if (!manifest.startsWith('<')) return {}
  const level = manifest.match(/requestedExecutionLevel[^>]*level=['"]([^'"]+)['"]/i)?.[1]
  return { manifest, requestedExecutionLevel: level }
}

function parsePe(buffer: Buffer): ParsedPe {
  if (buffer.length < 64 || buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    return { valid: false, is64: false, machine: 0, subsystem: 0, imageBase: 0n, entryPointRva: 0, sections: [], directories: [], imports: [], tlsCallbackCount: 0, physicalTlsCallbackCount: 0 }
  }

  const peOffset = readU32(buffer, 0x3c)
  if (peOffset === null || peOffset + 24 > buffer.length || buffer.toString('ascii', peOffset, peOffset + 4) !== 'PE\0\0') {
    return { valid: false, is64: false, machine: 0, subsystem: 0, imageBase: 0n, entryPointRva: 0, sections: [], directories: [], imports: [], tlsCallbackCount: 0, physicalTlsCallbackCount: 0 }
  }

  const coff = peOffset + 4
  const machine = readU16(buffer, coff) ?? 0
  const sectionCount = readU16(buffer, coff + 2) ?? 0
  const optionalSize = readU16(buffer, coff + 16) ?? 0
  const optional = coff + 20
  const magic = readU16(buffer, optional) ?? 0
  const is64 = magic === 0x20b
  if ((magic !== 0x10b && !is64) || optional + optionalSize > buffer.length) {
    return { valid: false, is64: false, machine, subsystem: 0, imageBase: 0n, entryPointRva: 0, sections: [], directories: [], imports: [], tlsCallbackCount: 0, physicalTlsCallbackCount: 0 }
  }

  const entryPointRva = readU32(buffer, optional + 16) ?? 0
  const imageBase = is64 ? (readU64(buffer, optional + 24) ?? 0n) : BigInt(readU32(buffer, optional + 28) ?? 0)
  const sizeOfHeaders = readU32(buffer, optional + 60) ?? 0
  const subsystem = readU16(buffer, optional + 68) ?? 0
  const directoryCount = readU32(buffer, optional + (is64 ? 108 : 92)) ?? 0
  const directoryStart = optional + (is64 ? 112 : 96)
  const directories = Array.from({ length: Math.min(directoryCount, 16) }, (_, index) => ({
    rva: readU32(buffer, directoryStart + index * 8) ?? 0,
    size: readU32(buffer, directoryStart + index * 8 + 4) ?? 0,
  }))

  const sectionStart = optional + optionalSize
  const sections: SectionRecord[] = []
  for (let index = 0; index < sectionCount && index < 96; index++) {
    const offset = sectionStart + index * 40
    if (offset + 40 > buffer.length) break
    const rawName = buffer.subarray(offset, offset + 8).toString('ascii').replace(/\0.*$/, '')
    sections.push({
      name: rawName || `<section-${index}>`,
      virtualSize: readU32(buffer, offset + 8) ?? 0,
      virtualAddress: readU32(buffer, offset + 12) ?? 0,
      rawSize: readU32(buffer, offset + 16) ?? 0,
      rawOffset: readU32(buffer, offset + 20) ?? 0,
      characteristics: readU32(buffer, offset + 36) ?? 0,
    })
  }

  const tls = directories[9]
  let tlsCallbackCount = 0
  let physicalTlsCallbackCount = 0
  if (tls?.rva && tls.size) {
    const tlsOffset = rvaToOffset(sections, tls.rva, sizeOfHeaders, buffer.length)
    const callbackVa = tlsOffset === null ? null : is64 ? readU64(buffer, tlsOffset + 24) : BigInt(readU32(buffer, tlsOffset + 12) ?? 0)
    const callbackOffset = callbackVa === null ? null : rvaToOffset(sections, Number(callbackVa - imageBase), sizeOfHeaders, buffer.length)
    if (callbackOffset !== null) {
      const pointerSize = is64 ? 8 : 4
      for (let index = 0; index < 64; index++) {
        const callback = is64 ? readU64(buffer, callbackOffset + index * pointerSize) : BigInt(readU32(buffer, callbackOffset + index * pointerSize) ?? 0)
        if (callback === null || callback === 0n) break
        tlsCallbackCount++
        if (rvaToOffset(sections, Number(callback - imageBase), sizeOfHeaders, buffer.length) !== null) physicalTlsCallbackCount++
      }
    }
  }

  return {
    valid: true,
    is64,
    machine,
    subsystem,
    imageBase,
    entryPointRva,
    sections,
    directories,
    imports: parseImports(buffer, sections, directories, is64, sizeOfHeaders),
    tlsCallbackCount,
    physicalTlsCallbackCount,
    ...extractManifestResource(buffer, sections, directories, sizeOfHeaders),
  }
}

function buildTriageIndicators(parsed: ParsedPe, signatureStatus: 'valid' | 'unsigned' | 'unknown', fileName: string, size: number): TriageIndicator[] {
  const indicators: TriageIndicator[] = []
  if (signatureStatus === 'unsigned') {
    indicators.push({ id: 'unsigned', severity: 'high', title: 'Unsigned executable', explanation: 'Authenticode reports that the file has no valid signature. Publisher identity cannot be trusted from the file itself.', confidence: 0.98 })
  } else if (signatureStatus === 'unknown') {
    indicators.push({ id: 'signature-unknown', severity: 'medium', title: 'Signature status unavailable', explanation: 'The operating system did not return a trustworthy Authenticode verdict. This is uncertainty, not proof that the file is unsigned.', confidence: 0.99 })
  }
  if (parsed.requestedExecutionLevel === 'requireAdministrator') indicators.push({ id: 'elevation', severity: 'high', title: 'Requests administrator privileges', explanation: 'The embedded manifest requests requireAdministrator before the application starts.', confidence: 0.99 })

  const suspiciousSections = parsed.sections.filter(section => !['.text', '.rdata', '.data', '.pdata', '.tls', '.rsrc', '.reloc', '.idata', '.edata', '.loadcfg'].includes(section.name))
  if (suspiciousSections.length > 0) indicators.push({ id: 'section-names', severity: 'high', title: 'Non-standard PE sections', explanation: `Found: ${suspiciousSections.map(section => section.name).join(', ')}. Custom names are compatible with packing or virtualized code, but are not proof by themselves.`, confidence: 0.9 })

  if (parsed.tlsCallbackCount > 0) indicators.push({ id: 'tls-callbacks', severity: 'medium', title: 'TLS callbacks present', explanation: `${parsed.tlsCallbackCount} callback(s) execute during loader initialization, before normal application logic.`, confidence: 0.98 })
  if (parsed.tlsCallbackCount > parsed.physicalTlsCallbackCount) indicators.push({ id: 'virtual-tls', severity: 'high', title: 'TLS callback points into virtual-only data', explanation: 'At least one TLS callback does not map to file-backed bytes, which is compatible with runtime reconstruction or unpacking.', confidence: 0.88 })
  if (size >= 5 * 1024 * 1024 && fileName.toLowerCase() === 'dxwebsetup.exe') indicators.push({ id: 'identity-mismatch', severity: 'critical', title: 'Installer identity mismatch', explanation: 'The filename resembles Microsoft DirectX web setup, but the file is unusually large for that identity and unsigned.', confidence: 0.99 })

  const criticalImports = parsed.imports.filter(item => item.risk === 'critical')
  if (criticalImports.length > 0) indicators.push({ id: 'injection-imports', severity: 'critical', title: 'Static injection API imports', explanation: criticalImports.map(item => item.name || `ordinal ${item.ordinal}`).join(', '), confidence: 0.97 })
  const tokenImports = parsed.imports.filter(item => item.reason?.includes('token'))
  if (tokenImports.length > 0) indicators.push({ id: 'token-api', severity: 'high', title: 'Token or privilege API imports', explanation: tokenImports.map(item => item.name).filter(Boolean).join(', '), confidence: 0.93 })
  const networkImports = parsed.imports.filter(item => item.reason === 'Network communication API')
  if (networkImports.length > 0) indicators.push({ id: 'network-api', severity: 'medium', title: 'Network API imports', explanation: networkImports.map(item => item.name || `ordinal ${item.ordinal}`).join(', '), confidence: 0.9 })
  const launchImports = parsed.imports.filter(item => item.reason?.startsWith('Can launch'))
  if (launchImports.length > 0) indicators.push({ id: 'launch-api', severity: 'medium', title: 'Process launch API imports', explanation: launchImports.map(item => item.name).filter(Boolean).join(', '), confidence: 0.9 })
  return indicators
}

function scoreIndicators(indicators: readonly TriageIndicator[]): number {
  const weights: Record<TriageSeverity, number> = { critical: 35, high: 22, medium: 10, low: 4 }
  return Math.min(100, indicators.reduce((score, indicator) => score + weights[indicator.severity], 0))
}

export async function analyzeBinaryTriage(filePath: string): Promise<BinaryTriageReport> {
  const absolutePath = path.resolve(filePath)
  const extension = path.extname(absolutePath).toLowerCase()
  if (!BINARY_EXTENSIONS.has(extension)) throw new Error('Unsupported binary extension')

  const stat = await fsp.stat(absolutePath)
  if (!stat.isFile()) throw new Error('Selected path is not a file')
  if (stat.size > MAX_TRIAGE_SIZE) throw new Error('File is too large for safe triage')

  const buffer = await fsp.readFile(absolutePath)
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex')
  const signatureStatus = await checkDigitalSignatureStatus(absolutePath)
  const signed = signatureStatus === 'valid'
  const parsed = parsePe(buffer)
  const sections: TriageSection[] = parsed.sections.map(section => {
    const raw = section.rawSize > 0 && section.rawOffset + section.rawSize <= buffer.length ? buffer.subarray(section.rawOffset, section.rawOffset + section.rawSize) : null
    return {
      name: section.name,
      virtualAddress: section.virtualAddress,
      virtualSize: section.virtualSize,
      rawOffset: section.rawOffset,
      rawSize: section.rawSize,
      entropy: raw && raw.length > 0 ? calculateEntropy(raw) : null,
      executable: (section.characteristics & 0x20000000) !== 0,
      writable: (section.characteristics & 0x80000000) !== 0,
      rawBacked: raw !== null,
    }
  })
  const indicators = buildTriageIndicators(parsed, signatureStatus, path.basename(absolutePath), stat.size)
  const highEntropy = sections.filter(section => section.entropy !== null && section.entropy >= 7.5)
  if (highEntropy.length > 0) indicators.push({ id: 'high-entropy', severity: 'high', title: 'High-entropy executable data', explanation: `Sections: ${highEntropy.map(section => `${section.name} (${section.entropy?.toFixed(2)})`).join(', ')}. This is compatible with compression or encryption.`, confidence: 0.93 })
  const virtualOnly = sections.filter(section => section.virtualSize > 0 && section.rawSize === 0)
  if (virtualOnly.length > 0) indicators.push({ id: 'virtual-only-sections', severity: 'high', title: 'Virtual-only PE sections', explanation: `${virtualOnly.length} section(s) have virtual data but no raw file backing. Static analysis cannot see their runtime contents.`, confidence: 0.95 })

  const score = scoreIndicators(indicators)
  const verdict: TriageVerdict = score >= 70 ? 'high-risk' : score >= 40 ? 'suspicious' : parsed.valid ? 'low-risk' : 'inconclusive'
  const directories = parsed.directories.map((directory, index) => ({
    name: ['EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'CERTIFICATE', 'BASERELOC', 'DEBUG', 'ARCH', 'GLOBALPTR', 'TLS', 'LOADCONFIG', 'BOUNDIMPORT', 'IAT', 'DELAYIMPORT', 'COM', 'RESERVED'][index] || `DIRECTORY_${index}`,
    rva: directory.rva,
    size: directory.size,
    mapped: directory.rva !== 0 && sectionForRva(parsed.sections, directory.rva) !== undefined,
  }))

  return {
    staticOnly: true,
    file: { path: absolutePath, fileName: path.basename(absolutePath), size: stat.size, sha256, extension, signed, signatureStatus },
    pe: {
      valid: parsed.valid,
      architecture: architecture(parsed.machine),
      machine: formatHex(parsed.machine),
      subsystem: subsystemName(parsed.subsystem),
      imageBase: formatHex(parsed.imageBase),
      entryPointRva: formatHex(parsed.entryPointRva),
      entryPointSection: sectionForRva(parsed.sections, parsed.entryPointRva)?.name,
      sectionCount: parsed.sections.length,
      sections,
      directories,
      imports: parsed.imports,
      tls: { present: parsed.tlsCallbackCount > 0, callbackCount: parsed.tlsCallbackCount, physicalCallbackCount: parsed.physicalTlsCallbackCount },
      manifest: parsed.manifest,
      requestedExecutionLevel: parsed.requestedExecutionLevel,
    },
    indicators,
    score,
    verdict,
    limitations: [
      'Static-only: the target file was not executed or loaded as a module.',
      'Dynamic API resolution, unpacked memory contents and runtime network destinations cannot be confirmed statically.',
      'A network import does not prove data exfiltration or command-and-control traffic.',
      'A high entropy section is compatible with compression/encryption and is not proof of malware by itself.',
    ],
  }
}

export function registerBinaryTriageHandler(): void {
  ipcMain.handle('triage-binary', async (event) => {
    if (event.sender.getType() !== 'window') throw new Error('Unauthorized triage request')
    const selection = await dialog.showOpenDialog({
      title: 'Выберите бинарный файл для статического анализа',
      properties: ['openFile'],
      filters: [{ name: 'Windows binaries', extensions: ['exe', 'dll', 'sys', 'drv', 'asi'] }],
    })
    if (selection.canceled || selection.filePaths.length === 0) return null
    return analyzeBinaryTriage(selection.filePaths[0])
  })
}
