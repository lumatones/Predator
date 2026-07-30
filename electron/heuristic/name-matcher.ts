/**
 * Predator — Name-Based Cheat Matching
 *
 * Extracted from heuristic.ts. Pure functions that match process/file names
 * against known cheat signatures. No file I/O, no side effects.
 *
 * Dependencies:
 *   - PROC_BASES, FILE_NAMES, LUA_NAMES, FOLDER_NAMES (from ./cheat-names)
 *   - ctx.cheatNameCache (from ../types)
 */

import path from 'path'
import { ctx } from '../types'
import { PROC_BASES, FILE_NAMES, LUA_NAMES, FOLDER_NAMES } from './cheat-names'

// ═══════════════════════════════════════════════════
// DOUBLE EXTENSION DETECTION (from Kudu malware scanner)
// ═══════════════════════════════════════════════════

/** Executable extensions that can run code when double-clicked */
const EXECUTABLE_EXTS = new Set([
  '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
  '.vbs', '.vbe', '.js', '.jse', '.wsh', '.wsf', '.ps1',
])

/** Bait extensions — looks like a document/media file */
const BAIT_EXTS = new Set([
  // Documents
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.txt', '.rtf', '.csv', '.odt', '.ods',
  // Media
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico',
  '.mp3', '.mp4', '.avi', '.mov', '.wav', '.flac', '.mkv',
  // Archives
  '.zip', '.rar', '.7z', '.tar', '.gz',
  // Web
  '.html', '.htm', '.xml', '.json',
])

/**
 * Detects files with double extensions like "invoice.pdf.exe" or "photo.jpg.scr".
 * This is a common malware/cheat distribution tactic — the user sees ".pdf"
 * but the file actually executes.
 *
 * Ported from Kudu's malware scanner (AdventDevInc/kudu).
 */
export function hasDoubleExtension(fileName: string): { isSuspicious: boolean; bait: string; real: string } {
  const ext = path.extname(fileName).toLowerCase()
  if (!ext) return { isSuspicious: false, bait: '', real: '' }

  // Remove last extension and check if there's another
  const nameWithoutExt = fileName.slice(0, -ext.length)
  const secondExt = path.extname(nameWithoutExt).toLowerCase()
  if (!secondExt) return { isSuspicious: false, bait: '', real: '' }

  const isExecutable = EXECUTABLE_EXTS.has(ext)
  const isBait = BAIT_EXTS.has(secondExt)

  if (isExecutable && isBait) {
    return { isSuspicious: true, bait: secondExt, real: ext }
  }

  return { isSuspicious: false, bait: '', real: '' }
}

// ═══════════════════════════════════════════════════
// CHEAT NAME MATCHING
// ═══════════════════════════════════════════════════

export function matchKnownCheat(name: string): string[] {
  const lower = name.toLowerCase()
  const cached = ctx.cheatNameCache.get(lower)
  if (cached !== undefined) return cached

  const matches: string[] = []
  for (const base of PROC_BASES) {
    if (lower.includes(base)) matches.push(`process:${base}`)
  }
  for (const file of FILE_NAMES) {
    if (lower.includes(file)) matches.push(`file:${file}`)
  }
  for (const lua of LUA_NAMES) {
    if (lower.includes(lua)) matches.push(`lua:${lua}`)
  }
  for (const folder of FOLDER_NAMES) {
    if (lower.includes(folder)) matches.push(`folder:${folder}`)
  }
  ctx.cheatNameCache.set(lower, matches)
  return matches
}

// ═══════════════════════════════════════════════════
// RISK SCORING
// ═══════════════════════════════════════════════════

export function riskScoreToLevel(score: number): 'high' | 'medium' | 'low' {
  if (score > 80) return 'high'
  if (score > 50) return 'medium'
  return 'low'
}

export function getFileRiskLevel(fileName: string, matches: string[]): 'high' | 'medium' | 'low' {
  const ext = path.extname(fileName).toLowerCase()
  const highRiskExts = ['.exe', '.dll', '.sys', '.drv', '.bat', '.ps1', '.vbs', '.ahk']
  const mediumRiskExts = ['.js', '.lua', '.py', '.cs', '.asi', '.luac']

  const hasHighKeyword = matches.some(k =>
    ['dll inject', 'memory hack', 'injector', 'aimbot', 'wallhack',
     'triggerbot', 'dma', 'fpga', 'pcileech', 'fuser'].includes(k),
  )

  if ((highRiskExts.includes(ext) && hasHighKeyword) || matches.length >= 3) return 'high'
  if (highRiskExts.includes(ext) || mediumRiskExts.includes(ext) || matches.length >= 2) return 'medium'
  return 'low'
}
