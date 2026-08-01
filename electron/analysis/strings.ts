/**
 * Predator — Binary String Extractor
 * Extracted from heuristic.ts
 *
 * Extract ASCII + Unicode strings from a binary file without blocking the
 * Electron main process.
 */

import fsp from 'fs/promises'
import { readFilePrefix } from '../utils/file-io'

export async function scanStrings(
  filepath: string,
  maxSize = 512 * 1024,
  signal?: AbortSignal,
): Promise<string[]> {
  const strings: string[] = []
  try {
    const stat = await fsp.stat(filepath)
    if (stat.size > maxSize) return strings

    const data = await readFilePrefix(filepath, Math.min(stat.size, maxSize), signal)

    let ascii = ''
    for (const b of data) {
      if (signal?.aborted) return strings
      if (b >= 0x20 && b <= 0x7e) {
        ascii += String.fromCharCode(b)
      } else {
        if (ascii.length >= 4) strings.push(ascii)
        ascii = ''
      }
    }
    if (ascii.length >= 4) strings.push(ascii)

    let uniBuf: number[] = []
    for (let i = 0; i < data.length - 1; i += 2) {
      if (signal?.aborted) return strings
      if (data[i] >= 0x20 && data[i] <= 0x7e && data[i + 1] === 0x00) {
        uniBuf.push(data[i])
      } else {
        if (uniBuf.length >= 4) strings.push(String.fromCharCode(...uniBuf))
        uniBuf = []
      }
    }
    if (uniBuf.length >= 4) strings.push(String.fromCharCode(...uniBuf))
  } catch (err) {
    if (!signal?.aborted) console.warn('[strings] failed:', (err as Error).message)
  }
  return strings
}
