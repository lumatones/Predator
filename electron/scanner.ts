import { ipcMain, BrowserWindow } from 'electron'
import fs from 'fs'
import path from 'path'
import os from 'os'

// ── Config ─────────────────────────────────────

const TARGET_EXTENSIONS = new Set([
  '.js', '.exe', '.dll', '.bat', '.ps1', '.vbs', '.ahk',
  '.lua', '.py', '.cs', '.cpp', '.c', '.h', '.cfg', '.ini',
  '.txt', '.log', '.json', '.xml',
])

const SUSPICIOUS_KEYWORDS = [
  'nightfall', 'cheat', 'hack', 'mod menu', 'inject', 'injector',
  'bypass', 'predator', 'hook', 'dll inject', 'memory hack',
  'trainer', 'crack', 'exploit', 'modloader', 'script hook',
  'unknowncheats', 'guided hacking', 'mpgh', 'aimbot', 'wallhack',
  'esp hack', 'triggerbot', 'silent aim', 'crosshair',
]

const SUSPICIOUS_PATTERNS = [
  /[Nn]ightfall/i,
  /[Cc]heats?\s*(?:folder|dir|menu)/i,
  /[Mm]od\s*[Mm]enu/i,
  /[Ii]nject/i,
  /[Bb]ypass/i,
  /[Hh]ook\d*\.dll/i,
  /[Ss]cript\s*[Hh]ook/i,
  /[Aa]imbot/i,
  /[Ww]allhack/i,
]

const SCAN_DIRS = [
  path.join(os.homedir(), 'Downloads'),
  path.join(os.homedir(), 'Desktop'),
  path.join(os.homedir(), 'Documents'),
  path.join(os.homedir(), 'AppData', 'Local'),
  path.join(os.homedir(), 'AppData', 'Roaming'),
]

// Browser history search directories (Chromium-based)
const BROWSER_DIRS = [
  path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'History'),
  path.join(os.homedir(), 'AppData', 'Local', 'Yandex', 'YandexBrowser', 'User Data', 'Default', 'History'),
  path.join(os.homedir(), 'AppData', 'Roaming', 'Opera Software', 'Opera Stable', 'History'),
]

// ── Types ──────────────────────────────────────

export interface ScanResult {
  path: string
  fileName: string
  type: 'file' | 'browser'
  risk: 'high' | 'medium' | 'low'
  matches: string[]
  size: number
  modifiedAt: string
}

export interface ScanProgress {
  phase: 'scanning' | 'analyzing' | 'done'
  currentDir: string
  filesFound: number
  filesScanned: number
  totalDirs: number
  dirsDone: number
}

export interface ScanResponse {
  results: ScanResult[]
  summary: {
    totalScanned: number
    suspiciousFiles: number
    highRiskCount: number
    scanTimeMs: number
  }
}

// ── Scanning logic ─────────────────────────────

function getFileRiskLevel(fileName: string, matches: string[]): 'high' | 'medium' | 'low' {
  const ext = path.extname(fileName).toLowerCase()
  const highRiskExts = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.ahk']
  const mediumRiskExts = ['.js', '.lua', '.py', '.cs', '.vbs']

  const hasHighKeyword = matches.some(k =>
    ['dll inject', 'memory hack', 'injector', 'aimbot', 'wallhack', 'triggerbot'].includes(k)
  )

  if ((highRiskExts.includes(ext) && hasHighKeyword) || matches.length >= 3) return 'high'
  if (highRiskExts.includes(ext) || mediumRiskExts.includes(ext) || matches.length >= 2) return 'medium'
  return 'low'
}

async function scanFile(filePath: string): Promise<ScanResult | null> {
  try {
    const stat = fs.statSync(filePath)
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) return null // Skip files > 5MB

    const fileName = path.basename(filePath).toLowerCase()
    const matches: string[] = []

    // Check filename for suspicious keywords
    for (const keyword of SUSPICIOUS_KEYWORDS) {
      if (fileName.includes(keyword.toLowerCase())) {
        matches.push(`filename:${keyword}`)
      }
    }

    // Check filename against patterns
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(path.basename(filePath))) {
        matches.push(`pattern:${pattern.source}`)
      }
    }

    // Read file content (text files only)
    const ext = path.extname(filePath).toLowerCase()
    const textExts = new Set(['.txt', '.log', '.json', '.xml', '.cfg', '.ini', '.js', '.lua', '.py', '.cs', '.bat', '.ps1', '.vbs', '.ahk'])
    if (textExts.has(ext) && stat.size < 512 * 1024) {
      try {
        const content = fs.readFileSync(filePath, 'utf-8').toLowerCase()
        for (const keyword of SUSPICIOUS_KEYWORDS) {
          if (content.includes(keyword)) {
            matches.push(`content:${keyword}`)
          }
        }
      } catch {
        // Binary or unreadable file — skip content scan
      }
    }

    if (matches.length === 0) return null

    return {
      path: filePath,
      fileName: path.basename(filePath),
      type: 'file',
      risk: getFileRiskLevel(path.basename(filePath), matches),
      matches,
      size: stat.size,
      modifiedAt: stat.mtime.toISOString(),
    }
  } catch {
    return null
  }
}

function* walkDir(dirPath: string): Generator<string> {
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name)
      if (entry.isDirectory()) {
        // Skip hidden/system directories
        if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'Temp') {
          yield* walkDir(fullPath)
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        if (TARGET_EXTENSIONS.has(ext)) {
          yield fullPath
        }
      }
    }
  } catch {
    // Permission denied or other error — skip directory
  }
}

async function scanBrowserHistory(): Promise<ScanResult[]> {
  const results: ScanResult[] = []

  for (const historyPath of BROWSER_DIRS) {
    try {
      if (!fs.existsSync(historyPath)) continue

      const stat = fs.statSync(historyPath)
      if (stat.size > 10 * 1024 * 1024) continue // Skip huge history files

      // Read the SQLite history file as text and search for cheat-related URLs
      const content = fs.readFileSync(historyPath, 'utf-8').toLowerCase()
      const foundKeywords: string[] = []

      for (const keyword of SUSPICIOUS_KEYWORDS) {
        if (content.includes(keyword)) {
          foundKeywords.push(`browser:${keyword}`)
        }
      }

      if (foundKeywords.length > 0) {
        results.push({
          path: historyPath,
          fileName: path.basename(historyPath),
          type: 'browser',
          risk: foundKeywords.length >= 3 ? 'high' : foundKeywords.length >= 2 ? 'medium' : 'low',
          matches: foundKeywords,
          size: stat.size,
          modifiedAt: stat.mtime.toISOString(),
        })
      }
    } catch {
      // Can't read browser history
    }
  }

  return results
}

// ── IPC Handler ────────────────────────────────

export function registerScanHandlers() {
  ipcMain.handle('start-scan', async (event) => {
    const startTime = Date.now()
    const results: ScanResult[] = []
    const win = BrowserWindow.fromWebContents(event.sender)
    let filesScanned = 0

    // Phase 1: Scan directories
    for (let i = 0; i < SCAN_DIRS.length; i++) {
      const dir = SCAN_DIRS[i]
      if (!fs.existsSync(dir)) continue

      win?.webContents.send('scan-progress', {
        phase: 'scanning',
        currentDir: dir,
        filesFound: results.length,
        filesScanned,
        totalDirs: SCAN_DIRS.length,
        dirsDone: i,
      } as ScanProgress)

      const files: string[] = []
      for (const filePath of walkDir(dir)) {
        files.push(filePath)
      }

      for (const filePath of files) {
        filesScanned++
        const r = await scanFile(filePath)
        if (r) results.push(r)

        // Send progress every 20 files
        if (filesScanned % 20 === 0) {
          win?.webContents.send('scan-progress', {
            phase: 'scanning',
            currentDir: dir,
            filesFound: results.length,
            filesScanned,
            totalDirs: SCAN_DIRS.length,
            dirsDone: i,
          } as ScanProgress)
        }
      }
    }

    // Phase 2: Check browser history
    win?.webContents.send('scan-progress', {
      phase: 'analyzing',
      currentDir: 'Browser history',
      filesFound: results.length,
      filesScanned,
      totalDirs: SCAN_DIRS.length,
      dirsDone: SCAN_DIRS.length,
    } as ScanProgress)

    const browserResults = await scanBrowserHistory()
    results.push(...browserResults)

    // Summary stats
    const highRiskCount = results.filter(r => r.risk === 'high').length

    win?.webContents.send('scan-progress', {
      phase: 'done',
      currentDir: '',
      filesFound: results.length,
      filesScanned,
      totalDirs: SCAN_DIRS.length,
      dirsDone: SCAN_DIRS.length,
    } as ScanProgress)

    return {
      results,
      summary: {
        totalScanned: filesScanned,
        suspiciousFiles: results.length,
        highRiskCount,
        scanTimeMs: Date.now() - startTime,
      },
    } as ScanResponse
  })
}
