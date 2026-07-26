/**
 * Predator — File Scan Mode
 *
 * Scans files and directories for suspicious content
 * using heuristic analysis, known signatures, and hash matching.
 */

import path from 'path'
import fs from 'fs'
import fsp from 'fs/promises'
import type { BrowserWindow } from 'electron'

import { KNOWN_BINARY_SIGNATURES, getScanPaths, TARGET_EXTENSIONS } from '../cheats-db'
import { heuristicFileScan, SUSPICIOUS_PATTERNS, ALL_CHEAT_KEYWORDS, matchKnownCheat, getFileRiskLevel, checkFileHash } from '../heuristic'
import { sendProgress, yieldToEventLoop, processBatch, SCAN_CONCURRENCY, clearFindingDedup, type ScanResult } from '../types'

// ── Async directory walker ──
export async function* walkDirAsync(dirPath: string): AsyncGenerator<string> {
  try {
    const entries = await fsp.readdir(dirPath, { withFileTypes: true })
    // Check if this is a suspicious location (Downloads, Desktop, Temp)
    const dirLower = dirPath.toLowerCase()
    const isSuspiciousDir = dirLower.includes('downloads') || dirLower.includes('download') ||
      dirLower.includes('desktop') || dirLower.includes('temp') || dirLower.includes('загрузки')
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name)
      if (entry.isDirectory()) {
        if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'Temp') {
          await yieldToEventLoop()
          yield* walkDirAsync(fullPath)
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        // In suspicious dirs, yield ALL files regardless of extension
        if (isSuspiciousDir || TARGET_EXTENSIONS.has(ext)) yield fullPath
      }
    }
  } catch (_e) {
    // Log skipped dirs in dev mode for debugging
    if (process.env.NODE_ENV === 'development') {
      console.warn(`[Predator] walkDirAsync: cannot read ${dirPath}`)
    }
  }
}

export async function scanFile(filePath: string): Promise<ScanResult | null> {
  try {
    const stat = await fsp.stat(filePath)
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) return null

    const fileName = path.basename(filePath)
    const matches: string[] = []

    const sigMatches = matchKnownCheat(fileName)
    matches.push(...sigMatches)

    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(fileName)) matches.push(`pattern:${pattern.source.replace(/\\/g, '')}`)
    }

    const hashCheck = await checkFileHash(filePath)
    if (hashCheck.matched) {
      matches.push(`hash:${hashCheck.hash.slice(0, 16)}...`)
      matches.push(`sha256:${hashCheck.hash}`)
    }

    const ext = path.extname(filePath).toLowerCase()
    const textExts = new Set(['.json', '.xml', '.cfg', '.ini', '.js', '.lua', '.cs', '.bat', '.ps1', '.vbs', '.ahk', '.luac'])
    if (textExts.has(ext) && stat.size < 512 * 1024) {
      try {
        const content = (await fsp.readFile(filePath, 'utf-8')).toLowerCase()
        for (const keyword of ALL_CHEAT_KEYWORDS) {
          if (content.includes(keyword)) matches.push(`content:${keyword}`)
        }
      } catch (_e) { /* binary */ }
    }

    const binaryExts = new Set(['.exe', '.dll', '.sys', '.drv', '.asi', '.luac'])
    if (binaryExts.has(ext) && stat.size >= 1024 && stat.size < 50 * 1024 * 1024) {
      try {
        const buffer = await fsp.readFile(filePath)
        for (const sig of KNOWN_BINARY_SIGNATURES) {
          if (buffer.includes(sig)) matches.push(`binary-sig:${sig.toString('utf-8').slice(0, 30)}`)
        }
      } catch (_e) { /* skip */ }
    }

    if (matches.length === 0) return null
    return {
      path: filePath, fileName: path.basename(filePath), type: 'file',
      risk: getFileRiskLevel(path.basename(filePath), matches),
      matches, size: stat.size, modifiedAt: stat.mtime.toISOString(),
    }
  } catch (_e) { return null }
}

// ── Walk cache for getDeepWalkEntries ──
const _walkCache = new Map<string, string[]>()

function getDeepWalkEntries(dirPath: string, maxDepth = 2): string[] {
  const key = `${dirPath}:${maxDepth}`
  const cached = _walkCache.get(key)
  if (cached !== undefined) return cached

  const entries: string[] = []
  function walk(d: string, depth: number) {
    if (depth > maxDepth) return
    try {
      const dirEntries = fs.readdirSync(d, { withFileTypes: true })
      for (const entry of dirEntries) {
        const fullPath = path.join(d, entry.name)
        entries.push(fullPath)
        if (entry.isDirectory() && !entry.name.startsWith('.')) {
          walk(fullPath, depth + 1)
        }
      }
    } catch (_e) { /* skip */ }
  }
  walk(dirPath, 0)

  _walkCache.set(key, entries)
  return entries
}

/**
 * Scan directories for files matching cheat-specific keywords
 */
export function scanForCheatFiles(cheatName: string, keywords: string[]): ScanResult[] {
  const results: ScanResult[] = []
  const searchDirs = getScanPaths().slice(0, 8)

  const allEntries: string[] = []
  for (const dir of searchDirs) {
    if (!fs.existsSync(dir)) continue
    try {
      allEntries.push(...getDeepWalkEntries(dir, 2))
    } catch (_e) { /* skip */ }
  }

  for (const entryPath of allEntries) {
    const lower = path.basename(entryPath).toLowerCase()
    const matches: string[] = []
    for (const keyword of keywords) {
      if (lower.includes(keyword)) matches.push(`cheat:${cheatName.toLowerCase()} → ${keyword}`)
    }
    const sigMatches = matchKnownCheat(lower)
    matches.push(...sigMatches)

    if (matches.length > 0) {
      try {
        const stat = fs.statSync(entryPath)
        results.push({
          path: entryPath,
          fileName: stat.isDirectory() ? path.basename(entryPath) + '/' : path.basename(entryPath),
          type: 'file',
          risk: matches.length >= 2 ? 'high' : 'medium',
          matches, size: stat.size, modifiedAt: stat.mtime.toISOString(),
        })
      } catch (_e) { /* skip */ }
    }
  }

  return results
}

export async function runFileScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  clearFindingDedup()

  const results: ScanResult[] = []
  let filesScanned = 0
  const scanDirs = getScanPaths()

  for (let i = 0; i < scanDirs.length; i++) {
    const dir = scanDirs[i]
    try {
      await fsp.access(dir)
    } catch (_e) {
      await sendProgress(win, { phase: 'scanning', currentDir: `${dir} (skipped)`, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
      continue
    }

    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })

    const fileBatch: string[] = []
    for await (const filePath of walkDirAsync(dir)) {
      fileBatch.push(filePath)
    }

    if (fileBatch.length > 0) {
      const batchResults = await processBatch(fileBatch, async (filePath) => {
        filesScanned++
        const r = await scanFile(filePath)
        return r
      }, SCAN_CONCURRENCY)

      for (const r of batchResults) {
        if (r) results.push(r)
      }

      await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
    }

    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
  }

  return { results, filesScanned }
}
