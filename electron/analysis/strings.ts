/**
 * Predator — Binary String Extractor
 * Extracted from heuristic.ts
 *
 * Extract ASCII + Unicode strings from a binary file.
 */

import fs from 'fs'

export function scanStrings(filepath: string, maxSize = 512 * 1024): string[] {
  const strings: string[] = []
  try {
    const stat = fs.statSync(filepath)
    if (stat.size > maxSize) return strings

    const fd = fs.openSync(filepath, 'r')
    const data = Buffer.alloc(Math.min(stat.size, maxSize))
    fs.readSync(fd, data, 0, data.length, 0)
    fs.closeSync(fd)

    let ascii = ''
    for (const b of data) {
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
      if (data[i] >= 0x20 && data[i] <= 0x7e && data[i + 1] === 0x00) {
        uniBuf.push(data[i])
      } else {
        if (uniBuf.length >= 4) strings.push(String.fromCharCode(...uniBuf))
        uniBuf = []
      }
    }
    if (uniBuf.length >= 4) strings.push(String.fromCharCode(...uniBuf))
  } catch (err) { console.warn('[strings] failed:', (err as Error).message) }
  return strings
}
