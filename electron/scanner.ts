import { ipcMain, BrowserWindow } from 'electron'
import crypto from 'crypto'
import fs from 'fs'
import fsp from 'fs/promises'
import path from 'path'
import os from 'os'
import { execSync } from 'child_process'

import {
  KNOWN_PROCESSES,
  KNOWN_CHEAT_FILES,
  KNOWN_LUA_SCRIPTS,
  KNOWN_CHEAT_FOLDERS,
  KNOWN_BINARY_SIGNATURES,
  KNOWN_CHEAT_HASHES,
  mergeCheatHashes,
  GAME_PROCESSES,
  REGISTRY_SCAN_KEYS,
  getScanPaths,
  TARGET_EXTENSIONS,
  isPlatformWhitelisted,
} from './cheats-db'

import {
  evaluateYara,
  isTrustedPath,
  isTrustedCompany,
  analyzePeHeaders,
  analyzeSectionEntropy,
} from './cheat-rules'

import {
  scanAllBrowsers,
  getBrowserCount,
  type BrowserHistoryResult,
  type HistoryEntry,
} from './browser-history'

import {
  checkAutoRules,
  learnFromFile,
} from './auto-yara'

import {
  dumpAndAnalyze,
  dumpProcessMemory,
} from './memory-dump'

import {
  analyzeApiHashingStatic,
  analyzeApiHashingInDump,
} from './api-hashing'

import {
  scanProcessForAmsiEtw,
} from './etw-amsi-patch'

import {
  buildBehaviorProfile,
  profileToScanResult,
} from './behavior-profile'

import {
  scanRwxAndThreads,
  rwxResultToScanResult,
} from './rwx-scanner'

import {
  scanDiskVsMemory,
  dvmResultToScanResult,
} from './disk-vs-memory'

// ── Event-loop yield ──
const yieldToEventLoop = () => new Promise(resolve => setImmediate(resolve))

// ── Concurrency-limited batch processor ──
// Processes items in parallel with a fixed concurrency limit.
// Useful for CPU-bound tasks like file scanning that benefit from async I/O
// but should not overwhelm the event loop or disk subsystem.
const SCAN_CONCURRENCY = 4

async function processBatch<T, R>(
  items: T[],
  fn: (item: T) => Promise<R>,
  concurrency: number = SCAN_CONCURRENCY,
): Promise<R[]> {
  const results: R[] = []
  const executing = new Set<Promise<void>>()

  for (const item of items) {
    const p = (async () => {
      const index = results.length
      results.push(await fn(item))
      return index
    })().then(() => {
      executing.delete(p)
    }) as Promise<void>

    executing.add(p)

    if (executing.size >= concurrency) {
      await Promise.race(executing)
    }
  }

  await Promise.all(executing)
  return results
}

// ── Types ──────────────────────────────────────

export type ScanMode = 'files' | 'processes' | 'cheats' | 'dma' | 'extended' | 'network'

export interface ScanResult {
  path: string
  fileName: string
  type: 'file' | 'browser' | 'process' | 'registry' | 'hardware' | 'software'
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

// ── Config ──────────────────────────────────────

// PE header cache — avoids re-reading the same file for analyzePeHeaders, analyzeSectionEntropy, and API-hashing
const _peHeaderCache = new Map<string, { peInfo: any; secEntropy: any[]; mtime: number; filepath: string }>()
const PE_CACHE_MAX = 500 // max cache entries to prevent memory leak

const _PF = process.env.ProgramFiles || 'C:\\Program Files'
const _PF86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
const _PD = process.env.ProgramData || 'C:\\ProgramData'
const _WR = process.env.SystemRoot || 'C:\\Windows'
const _HOME = os.homedir()

// ── v2 Constants (from predator_scanner_v2.py) ──

interface CheatCategory {
  names: string[]
  strings: Buffer[]
  description: string
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'WARNING'
}

const SUSPICIOUS_CATEGORIES: Record<string, CheatCategory> = {
  injector: {
    names: ['inject', 'injector', 'map', 'manualmap', 'threadhijack'],
    strings: [Buffer.from('CreateRemoteThread'), Buffer.from('NtCreateThreadEx'), Buffer.from('RtlCreateUserThread'),
              Buffer.from('WriteProcessMemory'), Buffer.from('VirtualAllocEx'), Buffer.from('MapViewOfFile')],
    description: 'DLL injector — code injection into processes',
    risk: 'CRITICAL',
  },
  debugger: {
    names: ['debug', 'debugger', 'cheatengine', 'ce', 'x64dbg', 'ollydbg', 'ida'],
    strings: [Buffer.from('IsDebuggerPresent'), Buffer.from('CheckRemoteDebuggerPresent'), Buffer.from('NtQueryInformationProcess')],
    description: 'Debugger / memory hacking tool',
    risk: 'CRITICAL',
  },
  hook: {
    names: ['hook', 'detour', 'minhook', 'easyhook'],
    strings: [Buffer.from('SetWindowsHookEx'), Buffer.from('DetourAttach'), Buffer.from('MinHook'), Buffer.from('EasyHook')],
    description: 'System function hooking',
    risk: 'HIGH',
  },
  driver: {
    names: ['.sys', 'driver', 'kernel', 'km', 'ring0'],
    strings: [Buffer.from('\\Device\\'), Buffer.from('\\DosDevices\\'), Buffer.from('IoCreateDevice'), Buffer.from('PsSetCreateProcessNotifyRoutine')],
    description: 'Kernel-level driver',
    risk: 'CRITICAL',
  },
  spoofer: {
    names: ['spoofer', 'spoof', 'hwid', 'mac', 'serial', 'disk'],
    strings: [Buffer.from('HardwareID'), Buffer.from('MACAddress'), Buffer.from('DiskSerial'), Buffer.from('SMBIOS')],
    description: 'Hardware ID spoofing',
    risk: 'HIGH',
  },
  bypass: {
    names: ['bypass', 'evade', 'anti', 'block', 'disable'],
    strings: [Buffer.from('bypass'), Buffer.from('evade'), Buffer.from('anti-cheat'), Buffer.from('anti cheat')],
    description: 'Security mechanism bypass',
    risk: 'CRITICAL',
  },
  menu: {
    names: ['menu', 'gui', 'overlay', 'imgui', 'd3d'],
    strings: [Buffer.from('ImGui'), Buffer.from('Direct3D'), Buffer.from('OpenGL'), Buffer.from('overlay'), Buffer.from('esp'), Buffer.from('aimbot')],
    description: 'Game menu / overlay',
    risk: 'HIGH',
  },
  network: {
    names: ['proxy', 'vpn', 'socks', 'mitm', 'packet'],
    strings: [Buffer.from('WSASocket'), Buffer.from('connect'), Buffer.from('send'), Buffer.from('recv'), Buffer.from('socks'), Buffer.from('proxy')],
    description: 'Network manipulation tools',
    risk: 'MEDIUM',
  },
  obfuscator: {
    names: ['obf', 'pack', 'crypt', 'protect', 'vm', 'virtual'],
    strings: [Buffer.from('VMProtect'), Buffer.from('Themida'), Buffer.from('Enigma'), Buffer.from('Obsidium'), Buffer.from('Armadillo')],
    description: 'Code obfuscation / packing (hides malicious code)',
    risk: 'HIGH',
  },
}

// Protected paths — game mod directories where files should not be
const PROTECTED_PATHS = [
  // FiveM
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'mods'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'plugins'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'cache'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'data'),
  path.join(_HOME, 'AppData', 'Roaming', 'CitizenFX'),
  // RAGE MP — dinput8.dll / .asi files in root = cheats
  path.join(_PF, 'RAGEMP'),
  path.join(_PF86, 'RAGEMP'),
  path.join(_HOME, 'RAGEMP'),
  // ALT:V — modules/ resources/ directories
  path.join(_HOME, 'AppData', 'Local', 'altv', 'modules'),
  path.join(_HOME, 'AppData', 'Local', 'altv', 'resources'),
  // GTA 5 root — dinput8.dll, .asi = cheats
  path.join(_PF, 'Rockstar Games', 'Grand Theft Auto V'),
  path.join(_PF86, 'Rockstar Games', 'Grand Theft Auto V'),
  path.join(_PF, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
  path.join(_PF86, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
]

// Suspicious file extensions with descriptions
const SUSPICIOUS_EXTENSIONS: Record<string, string> = {
  '.dll': 'Dynamic library (possible inject)',
  '.asi': 'ASI mod GTA (game modification)',
  '.lua': 'Lua script (often used in cheats)',
  '.luac': 'Compiled Lua script',
  '.exe': 'Executable file',
  '.sys': 'System driver',
  '.bin': 'Binary file (may contain cheat config)',
  '.dat': 'Data file',
  '.cfg': 'Configuration file',
  '.ini': 'Configuration file',
  '.js': 'JavaScript (may contain cheat loader)',
  '.ahk': 'AutoHotkey script',
}

// v2 scan config
const SCAN_CONFIG = {
  SCAN_DEPTH: 3,
  MAX_FILE_SIZE: 100 * 1024 * 1024,
  MIN_FILE_SIZE: 1024,
  SUSPICIOUS_AGE_DAYS: 30,
  ENTROPY_THRESHOLD: 7.5,
}

// All known cheat/process names as keywords for matching
const ALL_CHEAT_KEYWORDS = [
  ...KNOWN_PROCESSES.map(n => n.replace(/\.exe$/i, '').replace(/_\*\.exe$/i, '').replace(/\*\.exe$/i, '')),
  ...KNOWN_CHEAT_FILES.map(n => n.replace(/\.(dll|exe|asi)$/i, '')),
  ...KNOWN_LUA_SCRIPTS.map(n => n.replace(/\.lua$/i, '')),
  ...KNOWN_CHEAT_FOLDERS,
  'cheat', 'hack', 'inject', 'bypass', 'mod menu', 'trainer',
  'aimbot', 'wallhack', 'esp', 'triggerbot', 'norecoil', 'nospread',
  'godmode', 'teleport', 'moneydrop', 'recovery', 'unlockall',
  'nightfall', 'dma', 'fpga', 'pcileech', 'fuser', 'screamer',
  'kmem', 'memprocfs', 'winpmem',
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
  /[Dd][Mm][Aa]/i,
  /[Ff][Pp][Gg][Aa]/i,
  /[Pp][Cc][Ii]\s*[Ll]eech/i,
]

// Browser history scanning now uses sql.js-based parser (./browser-history.ts)

// ── v2 Helpers ─────────────────────────────────

/** Shannon entropy (0–8). High = possibly packed / encrypted. O(n) single-pass. */
function calculateEntropy(data: Buffer): number {
  if (!data || data.length === 0) return 0
  const freq = new Array(256).fill(0)
  for (const b of data) freq[b]++
  const len = data.length
  let entropy = 0
  for (const count of freq) {
    if (count > 0) {
      const p = count / len
      entropy -= p * Math.log2(p)
    }
  }
  return entropy
}

/** Extract ASCII + Unicode strings from a binary file */
function scanStrings(filepath: string, maxSize = 5 * 1024 * 1024): string[] {
  const strings: string[] = []
  try {
    const stat = fs.statSync(filepath)
    if (stat.size > maxSize) return strings

    const fd = fs.openSync(filepath, 'r')
    const data = Buffer.alloc(Math.min(stat.size, maxSize))
    fs.readSync(fd, data, 0, data.length, 0)
    fs.closeSync(fd)

    // ASCII strings (4+ readable chars 0x20–0x7E)
    let ascii = ''
    for (const b of data) {
      if (b >= 0x20 && b <= 0x7E) {
        ascii += String.fromCharCode(b)
      } else {
        if (ascii.length >= 4) strings.push(ascii)
        ascii = ''
      }
    }
    if (ascii.length >= 4) strings.push(ascii)

    // Unicode UTF-16LE strings (4+ chars with \0 interleave)
    let uniBuf: number[] = []
    for (let i = 0; i < data.length - 1; i += 2) {
      if (data[i] >= 0x20 && data[i] <= 0x7E && data[i + 1] === 0x00) {
        uniBuf.push(data[i])
      } else {
        if (uniBuf.length >= 4) strings.push(String.fromCharCode(...uniBuf))
        uniBuf = []
      }
    }
    if (uniBuf.length >= 4) strings.push(String.fromCharCode(...uniBuf))
  } catch (_e) { /* skip */ }
  return strings
}

/** Cached digital signature check via PowerShell Get-AuthenticodeSignature */
const _sigCache = new Map<string, boolean>()

function checkDigitalSignature(filepath: string): boolean {
  const cached = _sigCache.get(filepath)
  if (cached !== undefined) return cached
  try {
    const out = execSync(
      `powershell -Command "(Get-AuthenticodeSignature '${filepath.replace(/'/g, "''")}').Status"`,
      { encoding: 'utf-8', timeout: 5000 },
    )
    const valid = out.includes('Valid')
    _sigCache.set(filepath, valid)
    return valid
  } catch (_e) {
    _sigCache.set(filepath, false)
    return false
  }
}

interface HeuristicResult {
  riskScore: number
  suspicions: string[]
}

/** Heuristic file analysis — entropy, signatures, name, age, protected paths */
function heuristicFileScan(filepath: string): HeuristicResult | null {
  try {
    const stat = fs.statSync(filepath)
    if (!stat.isFile() || stat.size > SCAN_CONFIG.MAX_FILE_SIZE || stat.size < SCAN_CONFIG.MIN_FILE_SIZE) {
      return null
    }

    const fileName = path.basename(filepath).toLowerCase()
    const ext = path.extname(filepath).toLowerCase()
    const ageDays = (Date.now() - stat.mtimeMs) / (1000 * 60 * 60 * 24)
    const suspicions: string[] = []
    let riskScore = 0

    // 1. Extension check
    if (SUSPICIOUS_EXTENSIONS[ext]) {
      suspicions.push(`Extension ${ext}: ${SUSPICIOUS_EXTENSIONS[ext]}`)
      riskScore += 20
    }

    // 2. Name check against categories
    for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
      for (const name of cat.names) {
        if (fileName.includes(name)) {
          suspicions.push(`Name → [${catName}]: ${cat.description}`)
          riskScore += 40
          break
        }
      }
    }

    // ── v0.0.13: Masquerading as system file ──
    // Check if the file is named like a critical system process but NOT in System32
    const system32Path = path.join(_WR, 'System32').toLowerCase()
    const syswow64Path = path.join(_WR, 'SysWOW64').toLowerCase()
    const filepathLower = filepath.toLowerCase()
    // fileName already includes the extension from path.basename()
    if (SYSTEM_PROC_NAMES.has(fileName)) {
      const isInSystemDir = filepathLower.startsWith(system32Path) || filepathLower.startsWith(syswow64Path)
      if (!isInSystemDir && !isTrustedPath(filepath)) {
        suspicions.push(`🎭 Masquerading as system process: ${fileName} (expected in System32, found in unexpected location)`)
        riskScore += 50
      }
    }

    // 3. Age check (recently created = suspicious)
    if (ageDays < SCAN_CONFIG.SUSPICIOUS_AGE_DAYS) {
      suspicions.push(`Recently created (${Math.round(ageDays)} days ago)`)
      riskScore += 15
    }

    // v3.0: Whitelist check — reduce score for trusted paths
    if (isTrustedPath(filepath)) {
      riskScore = Math.max(riskScore - 30, 0) // Trusted path = much less suspicious
    }

    // 4. Binary analysis (exe, dll, asi, sys)
    const binaryExts = new Set(['.exe', '.dll', '.asi', '.sys', '.drv'])
    if (binaryExts.has(ext) && stat.size >= 4096 && stat.size < 50 * 1024 * 1024) {
      const fd = fs.openSync(filepath, 'r')
      const sampleSize = Math.min(65536, stat.size)
      const sample = Buffer.alloc(sampleSize)
      fs.readSync(fd, sample, 0, sampleSize, 0)
      fs.closeSync(fd)

      // Entropy analysis (single-pass O(n))
      const entropy = calculateEntropy(sample)
      if (entropy > SCAN_CONFIG.ENTROPY_THRESHOLD) {
        suspicions.push(`High entropy (${entropy.toFixed(2)}) — possibly packed/encrypted`)
        riskScore += 30
      }

      // String signature analysis (ASCII + Unicode)
      const strings = scanStrings(filepath)
      const stringsLower = strings.map(s => s.toLowerCase())

      // v3.0: YARA-like rule evaluation (must be after stringsLower)
      const yaraMatches = evaluateYara(sample, stringsLower)
      for (const yMatch of yaraMatches) {
        suspicions.push(`YARA [${yMatch.ruleName}]: ${yMatch.description}`)
        riskScore += yMatch.risk === 'CRITICAL' ? 60 : yMatch.risk === 'HIGH' ? 40 : 20
      }

      // v3.0: PE analysis — cached to avoid re-reading headers for entropy + API hashing
      // Key: filepath + mtime so cache invalidates on file changes
      const peCacheKey = `${filepath}|${stat.mtimeMs}`
      let peInfo: any = null
      let secEntropy: any[] = []

      const cachedPe = _peHeaderCache.get(peCacheKey)
      if (cachedPe) {
        peInfo = cachedPe.peInfo
        secEntropy = cachedPe.secEntropy
      } else {
        // Parse PE headers ONCE
        peInfo = (ext === '.exe' || ext === '.dll' || ext === '.sys') ? analyzePeHeaders(filepath) : null
        try {
          secEntropy = analyzeSectionEntropy(filepath)
        } catch (_e) { /* skip */ }
        _peHeaderCache.set(peCacheKey, { peInfo, secEntropy, mtime: stat.mtimeMs, filepath })
        // Trim cache if it grows too large
        if (_peHeaderCache.size > PE_CACHE_MAX) {
          const firstKey = _peHeaderCache.keys().next().value
          if (firstKey) _peHeaderCache.delete(firstKey)
        }
      }

      const sigValid = (ext === '.exe' || ext === '.dll' || ext === '.sys') ? checkDigitalSignature(filepath) : false
      // NOTE: checkDigitalSignature() MUST be called before the fuzzy block to populate _sigCache

      if (ext === '.exe' || ext === '.dll' || ext === '.sys') {
        if (peInfo && peInfo.isValidPe && peInfo.isSuspicious) {
          if (peInfo.suspiciousSections.length > 0) {
            suspicions.push(`PE: Unusual sections: ${peInfo.suspiciousSections.join(', ')}`)
            riskScore += 25
          }
          if (peInfo.entryPointInSuspiciousSection) {
            suspicions.push('PE: Entry point in unusual section')
            riskScore += 20
          }
          if (peInfo.relocsStripped) {
            suspicions.push('PE: Relocations stripped (suggests packed/ASLR disabled)')
            riskScore += 15
          }
        }

        // ── v0.0.15: Section Entropy — per-section analysis (cached) ──
        if (secEntropy.length > 0) {
          const suspiciousSections = secEntropy.filter(s => s.isSuspicious)
          for (const sec of suspiciousSections) {
            suspicions.push(`📊 Section [${sec.name}]: ${sec.reason}`)
            riskScore += 30
          }
          // .rsrc with very high entropy is especially dangerous
          const rsrcHigh = secEntropy.find(s => s.name === '.rsrc' && s.entropy > 7.5)
          if (rsrcHigh) {
            suspicions.push(`🚩 .rsrc entropy ${rsrcHigh.entropy.toFixed(2)} > 7.5 — shellcode/config likely hidden in resources`)
            riskScore += 40
          }
        }
        }

        // ── v0.0.14: API Hashing static detection ──
        const apiHashRes = analyzeApiHashingStatic(filepath)
        if (apiHashRes && apiHashRes.detected) {
          suspicions.push(`🔐 API Hashing detected (confidence: ${apiHashRes.confidence}%)`)
          for (const p of apiHashRes.patterns.slice(0, 3)) {
            suspicions.push(`  → ${p}`)
          }
          riskScore += Math.min(apiHashRes.confidence * 0.5, 45)
        }

        const FUZZY_SIZE_LOWER_MB = 16
        const FUZZY_SIZE_UPPER_MB = 28
        const FUZZY_ENTROPY_THRESHOLD = 7.2
        const FUZZY_SECTION_MIN = 7
        const FUZZY_SIZE_BYTES_LOWER = FUZZY_SIZE_LOWER_MB * 1024 * 1024
        const FUZZY_SIZE_BYTES_UPPER = FUZZY_SIZE_UPPER_MB * 1024 * 1024

        // Only run fuzzy for .exe and .dll (not .asi, .sys)
        if (ext === '.exe' || ext === '.dll') {
          let fuzzyScore = 0
          const fuzzySignals: string[] = []

          // 1) File size in cheat loader range (e.g., EpicGamesLauncher.exe = 22.6 MB)
          if (stat.size >= FUZZY_SIZE_BYTES_LOWER && stat.size <= FUZZY_SIZE_BYTES_UPPER) {
            fuzzyScore += 25
            fuzzySignals.push(`Size ${(stat.size / 1024 / 1024).toFixed(1)} MB (loader range ${FUZZY_SIZE_LOWER_MB}–${FUZZY_SIZE_UPPER_MB} MB)`)
          }

          // 2) High entropy (packed/obfuscated)
          if (entropy > FUZZY_ENTROPY_THRESHOLD) {
            fuzzyScore += 20
            fuzzySignals.push(`Entropy ${entropy.toFixed(2)} > ${FUZZY_ENTROPY_THRESHOLD} (packed/obfuscated)`)
          }

          // 3) Many PE sections (> 6 suggests packing/obfuscation)
          if (peInfo && peInfo.sectionCount >= FUZZY_SECTION_MIN) {
            fuzzyScore += 25
            fuzzySignals.push(`${peInfo.sectionCount} PE sections ≥ ${FUZZY_SECTION_MIN} (packing)`)
          }

          // 4) Suspicious PE subsystem (not WINDOWS_GUI(2) or WINDOWS_CUI(3))
          if (peInfo && peInfo.subsystem !== '' && peInfo.subsystem !== 'WINDOWS_GUI' && peInfo.subsystem !== 'WINDOWS_CUI' && peInfo.subsystem !== 'NATIVE') {
            fuzzyScore += 15
            fuzzySignals.push(`PE subsystem: ${peInfo.subsystem} (unusual for EXE)`)
          }

          // 5) Unsigned executable (most cheat loaders lack signatures)
          if (!sigValid) {
            fuzzyScore += 15
            fuzzySignals.push('Unsigned executable (no digital signature)')
          }

          // If fuzzy match threshold met
          if (fuzzyScore >= 50) {
            suspicions.push(`🧬 Fuzzy loader match (score ${fuzzyScore}/100): ${fuzzySignals.join('; ')}`)
            riskScore += Math.min(fuzzyScore, 60)
          }
        }

      // Category signature analysis (ASCII + Unicode)
      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        const found: string[] = []
        for (const sigBuf of cat.strings) {
          const sigStr = sigBuf.toString().toLowerCase()
          if (stringsLower.some(s => s.includes(sigStr))) {
            found.push(sigStr)
          }
        }
        if (found.length > 0) {
          suspicions.push(`Signatures [${catName}]: ${found.slice(0, 3).join(', ')}`)
          riskScore += 50
        }
      }

      // Hash check against known cheat database
      if (KNOWN_CHEAT_HASHES.length > 0) {
        try {
          const h = crypto.createHash('sha256')
          const fd2 = fs.openSync(filepath, 'r')
          const hashBuf = Buffer.alloc(Math.min(stat.size, 50 * 1024 * 1024))
          fs.readSync(fd2, hashBuf, 0, hashBuf.length, 0)
          fs.closeSync(fd2)
          h.update(hashBuf)
          const hex = h.digest('hex')
          if (KNOWN_CHEAT_HASHES.includes(hex)) {
            suspicions.push(`Hash match: known cheat file (SHA256: ${hex.slice(0, 16)}...)`)
            riskScore += 60
          }
        } catch (_e) { /* skip */ }
      }

      // Digital signature — adjust score (sigValid was already computed before fuzzy block)
      if (sigValid) {
        riskScore -= 10 // Signed = less suspicious
      } else {
        suspicions.push('No digital signature')
        riskScore += 20
      }
    }

    // 5. Check if in a protected path
    for (const protectedPath of PROTECTED_PATHS) {
      if (filepath.toLowerCase().includes(protectedPath.toLowerCase())) {
        suspicions.push(`File in protected folder: ${protectedPath}`)
        riskScore += 25
        break
      }
    }

    // ── v0.0.13: Auto-YARA check against learned rules ──
    if (binaryExts.has(ext) && stat.size < 50 * 1024 * 1024) {
      try {
        const auto = checkAutoRules(filepath)
        if (auto.matched) {
          suspicions.push(`AutoYara [${auto.rules.length} правил]: score ${auto.score.toFixed(0)}`)
          riskScore += auto.score * 0.6
        }
      } catch (_e) { /* skip */ }
    }

    // ── Auto-YARA: learn from high-risk files ──
    if (riskScore > 70 && binaryExts.has(ext)) {
      try {
        learnFromFile(filepath, riskScore)
      } catch (_e) { /* skip */ }
    }

    if (riskScore === 0) return null

    return { riskScore, suspicions }
  } catch (_e) {
    return null
  }
}

function riskScoreToLevel(score: number): 'high' | 'medium' | 'low' {
  if (score > 80) return 'high'
  if (score > 50) return 'medium'
  return 'low'
}

/** Deduplication set for findings — cleared at start of each scan */
const _findingDedup = new Set<string>()

function addFindingDedup(key: string): boolean {
  if (_findingDedup.has(key)) return false
  _findingDedup.add(key)
  // Periodic cleanup: dedup sets grow during a single scan session.
  // Each scan run clears them explicitly via _findingDedup.clear().
  return true
}

// ── Standard helpers ───────────────────────────

function getFileRiskLevel(fileName: string, matches: string[]): 'high' | 'medium' | 'low' {
  const ext = path.extname(fileName).toLowerCase()
  const highRiskExts = ['.exe', '.dll', '.sys', '.drv', '.bat', '.ps1', '.vbs', '.ahk']
  const mediumRiskExts = ['.js', '.lua', '.py', '.cs', '.asi', '.luac']

  const hasHighKeyword = matches.some(k =>
    ['dll inject', 'memory hack', 'injector', 'aimbot', 'wallhack',
     'triggerbot', 'dma', 'fpga', 'pcileech', 'fuser'].includes(k)
  )

  if ((highRiskExts.includes(ext) && hasHighKeyword) || matches.length >= 3) return 'high'
  if (highRiskExts.includes(ext) || mediumRiskExts.includes(ext) || matches.length >= 2) return 'medium'
  return 'low'
}

// ── Async directory walker ──
async function* walkDirAsync(dirPath: string): AsyncGenerator<string> {
  try {
    const entries = await fsp.readdir(dirPath, { withFileTypes: true })
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name)
      if (entry.isDirectory()) {
        if (!entry.name.startsWith('.') && entry.name !== 'node_modules' && entry.name !== 'Temp') {
          await yieldToEventLoop()
          yield* walkDirAsync(fullPath)
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase()
        if (TARGET_EXTENSIONS.has(ext)) yield fullPath
      }
    }
  } catch (_e) { /* skip */ }
}

async function sendProgress(win: BrowserWindow | null, data: ScanProgress) {
  win?.webContents.send('scan-progress', data)
  await yieldToEventLoop()
}

function execCmd(cmd: string, psCmd: string, opts = {}): string {
  try {
    return execSync(cmd, { encoding: 'utf-8', timeout: 8000, ...opts })
  } catch (_e) {
    try {
      return execSync(psCmd, { encoding: 'utf-8', timeout: 8000, ...opts })
    } catch (_e) {
      return ''
    }
  }
}

// ── Pre-normalized arrays for fast substring matching ──

const _PROC_BASES = KNOWN_PROCESSES.map(n =>
  n.toLowerCase()
    .replace(/\.exe$/i, '')
    .replace(/_\*\.exe$/i, '')
    .replace(/\*\.exe$/i, '')
)
const _FILE_NAMES = KNOWN_CHEAT_FILES.map(n => n.toLowerCase())
const _LUA_NAMES = KNOWN_LUA_SCRIPTS.map(n => n.toLowerCase())
const _FOLDER_NAMES = KNOWN_CHEAT_FOLDERS.map(n => n.toLowerCase())

const _cheatNameCache = new Map<string, string[]>()

function matchKnownCheat(name: string): string[] {
  const lower = name.toLowerCase()
  const cached = _cheatNameCache.get(lower)
  if (cached !== undefined) return cached

  const matches: string[] = []
  for (const base of _PROC_BASES) {
    if (lower.includes(base)) matches.push(`process:${base}`)
  }
  for (const file of _FILE_NAMES) {
    if (lower.includes(file)) matches.push(`file:${file}`)
  }
  for (const lua of _LUA_NAMES) {
    if (lower.includes(lua)) matches.push(`lua:${lua}`)
  }
  for (const folder of _FOLDER_NAMES) {
    if (lower.includes(folder)) matches.push(`folder:${folder}`)
  }
  _cheatNameCache.set(lower, matches)
  return matches
}

/** Check if a file matches any known hash (SHA256) in the database. Streams the file. */
async function checkFileHash(filePath: string): Promise<{ matched: boolean; hash: string }> {
  if (KNOWN_CHEAT_HASHES.length === 0) return { matched: false, hash: '' }
  try {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)
    for await (const chunk of stream) hash.update(chunk as Buffer)
    const hex = hash.digest('hex')
    return { matched: KNOWN_CHEAT_HASHES.includes(hex), hash: hex }
  } catch (_e) {
    return { matched: false, hash: '' }
  }
}

// ═══════════════════════════════════════════════════
// PLATFORM-SPECIFIC SCANS (FiveM, RAGE MP, ALT:V)
// ═══════════════════════════════════════════════════

interface GamePid {
  pid: number
  platform: 'fivem' | 'rage' | 'altv' | 'gta5'
}

/**
 * Get PIDs of running game processes for all supported platforms.
 * Returns PID + platform for each detected game instance.
 */
function getGamePids(): GamePid[] {
  const targets = [
    { name: 'GTA5.exe', platform: 'gta5' as const },
    { name: 'FiveM_GTAProcess.exe', platform: 'fivem' as const },
    { name: 'FiveM.exe', platform: 'fivem' as const },
    { name: 'ragemp_v.exe', platform: 'rage' as const },
    { name: 'altv.exe', platform: 'altv' as const },
  ]

  const results: GamePid[] = []
  try {
    const names = targets.map(t => `name='${t.name}'`).join(' or ')
    const out = execSync(`wmic process where "${names}" get ProcessId,Name /format:csv 2>nul`, { encoding: 'utf-8', timeout: 5000 })
    if (!out.trim()) return results

    for (const line of out.trim().split('\n').slice(1)) {
      const parts = line.split(',').map(s => s.trim())
      const name = parts[parts.length - 2]?.toLowerCase()
      const pid = parseInt(parts[parts.length - 1], 10)
      if (isNaN(pid) || !name) continue

      const target = targets.find(t => t.name.toLowerCase() === name)
      if (target) results.push({ pid, platform: target.platform })
    }
  } catch (_e) { /* WMIC failed */ }

  return results
}

/**
 * Scan modules loaded in game processes.
 * Flags: unsigned modules, non-whitelisted modules in suspicious locations,
 * known cheat DLLs loaded into the game process.
 */
function scanGameModules(): ScanResult[] {
  const results: ScanResult[] = []
  const gameProcs = getGamePids()
  if (gameProcs.length === 0) return results

  for (const { pid, platform } of gameProcs) {
    try {
      const ps = `Get-Process -Id ${pid} | Select-Object -ExpandProperty Modules | Select-Object ModuleName,FileName | ConvertTo-Json -Compress`
      const out = execSync(`powershell -Command "${ps}"`, { encoding: 'utf-8', timeout: 8000 })
      if (!out.trim()) continue

      const parsed = JSON.parse(out)
      const modules = Array.isArray(parsed) ? parsed : [parsed]

      for (const mod of modules) {
        if (!mod.ModuleName) continue
        const name = (mod.ModuleName || '').toLowerCase()
        const modPath = (mod.FileName || '').toLowerCase()
        const isSystem32 = modPath.includes('\\windows\\system32') || modPath.includes('\\windows\\syswow64')
        const isProgramFiles = modPath.includes('\\program files\\') || modPath.includes('\\program files (x86)\\')
        const isTrusted = isSystem32 || isProgramFiles || isTrustedPath(modPath)

        // Level 1: Whitelisted module in non-standard location = ALERT
        if (isPlatformWhitelisted(name, platform) && !isTrusted) {
          if (addFindingDedup(`mod-whitelist:${pid}:${name}`)) {
            results.push({
              path: mod.FileName,
              fileName: `${mod.ModuleName} (unusual location)`,
              type: 'process',
              risk: 'high',
              matches: [`Whitelisted module in ${platform} (PID: ${pid})`, `Expected in System32/Program Files, found elsewhere`, `Platform: ${platform}`],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
          continue
        }

        // Level 2: Not whitelisted, not trusted path, unsigned = ALERT
        if (!isPlatformWhitelisted(name, platform) && !isTrusted) {
          const isSigned = isSystem32 ? true : checkDigitalSignature(mod.FileName)
          if (!isSigned && addFindingDedup(`mod-unsigned:${pid}:${name}`)) {
            results.push({
              path: mod.FileName,
              fileName: `${mod.ModuleName} (unsigned)`,
              type: 'process',
              risk: 'high',
              matches: [`Unsigned module loaded in ${platform} (PID: ${pid})`, `Possibly injected cheat`],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }

        // Level 3: Known cheat name match
        const cheatMatches = matchKnownCheat(name)
        if (cheatMatches.length > 0 && addFindingDedup(`mod-cheat:${pid}:${name}`)) {
          results.push({
            path: mod.FileName,
            fileName: `${mod.ModuleName} (cheat)`,
            type: 'process',
            risk: 'high',
            matches: [...cheatMatches, `Loaded in ${platform} (PID: ${pid})`],
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    } catch (_e) { /* skip module scan for this PID */ }
  }

  return results
}

/**
 * Check game integrity for all platforms.
 * FiveM: .dll/.asi in mods/plugins directories
 * RAGE MP: dinput8.dll or .asi next to ragemp_v.exe
 * ALT:V: suspicious .dll/.js in modules/
 * GTA 5: dinput8.dll, dsound.dll, .asi files in game root
 */
function scanGameIntegrity(): ScanResult[] {
  const results: ScanResult[] = []

  // Critical files that should NOT be in game directories
  const CRITICAL_MOD_FILES = ['dinput8.dll', 'dsound.dll', 'winmm.dll', 'scripthookv.dll', 'scripthookvdotnet.dll']
  const GTA5_DIRS = [
    path.join(_PF, 'Rockstar Games', 'Grand Theft Auto V'),
    path.join(_PF86, 'Rockstar Games', 'Grand Theft Auto V'),
    path.join(_PF, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
    path.join(_PF86, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
  ]

  // ── FiveM: mods/plugins ──
  const FIVEM_DIRS = [
    path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'mods'),
    path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'plugins'),
  ]
  for (const dir of FIVEM_DIRS) {
    if (!fs.existsSync(dir)) continue
    for (const entry of fs.readdirSync(dir)) {
      const fullPath = path.join(dir, entry)
      const lower = entry.toLowerCase()
      if ((lower.endsWith('.dll') || lower.endsWith('.asi')) && addFindingDedup(`fivem:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: ['Unauthorized file in FiveM directory', `Location: ${path.basename(dir)}`, 'DLL/ASI in mods/plugins = cheat loader'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
    }
  }

  // ── RAGE MP: ragemp_v.exe adjacent ──
  const RAGE_DIRS = [
    path.join(_PF, 'RAGEMP'),
    path.join(_PF86, 'RAGEMP'),
    path.join(_HOME, 'RAGEMP'),
  ]
  for (const rageDir of RAGE_DIRS) {
    if (!fs.existsSync(rageDir)) continue
    for (const entry of fs.readdirSync(rageDir)) {
      const fullPath = path.join(rageDir, entry)
      const lower = entry.toLowerCase()

      if (lower === 'dinput8.dll' && addFindingDedup(`rage:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: ['dinput8.dll in RAGEMP directory — ASI loader/cheat', 'ScriptHookV injection method used for MP cheating'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }

      if (lower.endsWith('.asi') && addFindingDedup(`rage-asi:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: ['ASI file in RAGEMP directory', 'Single-player cheat loaded in multiplayer'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
    }
  }

  // ── ALT:V modules/resources ──
  const ALTV_DIRS = [
    path.join(_HOME, 'AppData', 'Local', 'altv', 'modules'),
    path.join(_HOME, 'AppData', 'Local', 'altv', 'resources'),
    path.join(_PF, 'altv', 'modules'),
  ]
  const SUS_MOD_NAMES = ['aim', 'esp', 'wall', 'money', 'recovery', 'god', 'teleport', 'inject', 'bypass', 'cheat']
  for (const altvDir of ALTV_DIRS) {
    if (!fs.existsSync(altvDir)) continue
    for (const entry of fs.readdirSync(altvDir)) {
      const fullPath = path.join(altvDir, entry)
      const lower = entry.toLowerCase()

      // Suspicious module name
      if (SUS_MOD_NAMES.some(k => lower.includes(k)) && addFindingDedup(`altv-name:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: [`Suspicious ALT:V module name`, `Keyword match in ${path.basename(altvDir)}`],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }

      // Unsigned DLL in modules
      if (lower.endsWith('.dll') && !isTrustedPath(fullPath) && addFindingDedup(`altv-unsign:${fullPath}`)) {
        const signed = checkDigitalSignature(fullPath)
        if (!signed) {
          try {
            const stat = fs.statSync(fullPath)
            results.push({
              path: fullPath, fileName: entry, type: 'file', risk: 'medium',
              matches: ['Unsigned DLL in ALT:V modules directory', 'Possible cheat module'],
              size: stat.size, modifiedAt: stat.mtime.toISOString(),
            })
          } catch (_e) { /* skip */ }
        }
      }
    }
  }

  // ── GTA 5 root: dinput8.dll, dsound.dll, .asi files ──
  for (const gtaPath of GTA5_DIRS) {
    if (!fs.existsSync(gtaPath)) continue
    for (const entry of fs.readdirSync(gtaPath)) {
      const fullPath = path.join(gtaPath, entry)
      const lower = entry.toLowerCase()

      if (CRITICAL_MOD_FILES.includes(lower) && addFindingDedup(`gta5-root:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: [`${entry} in GTA 5 root — cheat/mod loader`, 'Used by ScriptHookV/trainers for MP cheating'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }

      if (lower.endsWith('.asi') && addFindingDedup(`gta5-asi:${fullPath}`)) {
        try {
          const stat = fs.statSync(fullPath)
          results.push({
            path: fullPath, fileName: entry, type: 'file', risk: 'high',
            matches: ['ASI mod in GTA 5 directory', 'Common cheat format (Menyoo, SimpleTrainer, etc.)'],
            size: stat.size, modifiedAt: stat.mtime.toISOString(),
          })
        } catch (_e) { /* skip */ }
      }
    }
  }

  return results
}

// ═══════════════════════════════════════════════
// MASQUERADING DETECTION
// ═══════════════════════════════════════════════

/** System process names that cheat loaders commonly masquerade as */
const SYSTEM_PROC_NAMES = new Set([
  'svchost.exe', 'csrss.exe', 'lsass.exe', 'services.exe', 'smss.exe',
  'winlogon.exe', 'explorer.exe', 'spoolsv.exe', 'conhost.exe',
  'rundll32.exe', 'taskhostw.exe', 'sihost.exe', 'ctfmon.exe',
  'dwm.exe', 'fontdrvhost.exe', 'RuntimeBroker.exe',
  'SearchIndexer.exe', 'SecurityHealthSystray.exe',
  'LogonUI.exe', 'SystemSettings.exe', 'LockApp.exe',
  'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
  'applicationframehost.exe', 'SearchApp.exe',
])

/**
 * Scan running processes for masquerading — processes with system process names
 * running from unexpected locations (not C:\Windows\System32 or C:\Windows\SysWOW64).
 * Chit loaders often rename themselves to svchost.exe, csrss.exe, lsass.exe, etc.
 */
function scanMasqueradingProcesses(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    // Get all running processes with their executable paths using PowerShell
    const psCmd = `powershell -Command "Get-Process | Where-Object { $_.MainModule.FileName -match '\\\\[^\\\\]+\\.exe$' } | Select-Object Name, Id, @{N='Path';E={$_.MainModule.FileName}} | ConvertTo-Json -Compress"`
    const out = execSync(psCmd, { encoding: 'utf-8', timeout: 10000 })
    if (!out || out.trim().length < 5) return results

    const parsed = JSON.parse(out)
    const processes = Array.isArray(parsed) ? parsed : [parsed]

    const systemDir = _WR.toLowerCase()
    const system32 = path.join(systemDir, 'system32').toLowerCase()
    const syswow64 = path.join(systemDir, 'syswow64').toLowerCase()

    for (const proc of processes) {
      const procName = (proc.Name || '').toLowerCase() + '.exe'
      const procPath = (proc.Path || '').toLowerCase()

      // Only check processes named like system processes
      if (!SYSTEM_PROC_NAMES.has(procName)) continue

      // Skip if the process is running from a legitimate system directory
      if (procPath.startsWith(system32) || procPath.startsWith(syswow64)) continue

      // Also skip trusted paths (Program Files, etc.)
      if (isTrustedPath(procPath)) continue

      // Flag as masquerading
      const dedupKey = `masquerade:${procName}:${proc.Id}`
      if (addFindingDedup(dedupKey)) {
        results.push({
          path: `process:${proc.Name} (PID: ${proc.Id})`,
          fileName: `🎭 Masquerading: ${proc.Name}.exe`,
          type: 'process',
          risk: 'high',
          matches: [
            `Process named like system process: ${procName}`,
            `Running from unexpected path: ${procPath}`,
            `Expected in: ${system32}`,
            'Masquerading as system process = cheat loader hiding technique',
          ],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (_e) {
    // PowerShell failed — silently skip
  }

  return results
}

/**
 * Scan for processes that have open handles to GTA5.exe (external cheats).
 * Critical for RAGE MP and ALT:V where cheats are external memory readers.
 * Requires Sysinternals handle64.exe for best results.
 */
function scanOpenHandles(): ScanResult[] {
  const results: ScanResult[] = []
  const gameProcs = getGamePids()
  const gamePids = new Set(gameProcs.map(g => g.pid))
  if (gamePids.size === 0) return results

  // System processes that legitimately open handles to GTA5
  const SYSTEM_PROCS = new Set([
    'explorer.exe', 'taskmgr.exe', 'svchost.exe', 'csrss.exe',
    'lsass.exe', 'services.exe', 'smss.exe', 'fontdrvhost.exe',
    'dwm.exe', 'searchindexer.exe', 'shellexperiencehost.exe',
    'discord.exe', 'steam.exe',
    'gtavlauncher.exe', 'playgtav.exe',
    'fivem.exe', 'fivem_gtaprocess.exe', 'ragemp_v.exe', 'altv.exe',
  ])

  try {
    // Try Sysinternals handle64.exe first
    const out = execSync('handle64.exe -a GTA5.exe -nobanner 2>nul', { encoding: 'utf-8', timeout: 10000 })
    if (!out.trim()) return results

    const lines = out.split('\n')
    for (const line of lines) {
      const m = line.match(/^(\S+)\s+pid:\s+(\d+)\s+type:\s+(\w+)\s+(\w+):\s+(.+)$/i)
      if (!m) continue
      const [, procName, pidStr, type, , target] = m
      const pid = parseInt(pidStr, 10)

      // Skip system processes, launchers, and the game itself
      if (SYSTEM_PROCS.has(procName.toLowerCase())) continue
      if (gamePids.has(pid)) continue

      // Everything else that opened GTA5.exe = suspicious
      if (addFindingDedup(`handle:${procName}:${pid}`)) {
        results.push({
          path: `handle:${procName} (PID: ${pid})`,
          fileName: procName,
          type: 'process',
          risk: 'high',
          matches: [`Process opened GTA5.exe handle`, `Handle type: ${type}`, `PID: ${pid}`, 'Possible external cheat (memory read/write)'] as string[],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (_e) {
    // handle64.exe not found — silently skip (most systems don't have it)
  }

  return results
}

// ═══════════════════════════════════════════════
// MODE 1: FILE SCAN
// ═══════════════════════════════════════════════

async function scanFile(filePath: string): Promise<ScanResult | null> {
  try {
    const stat = await fsp.stat(filePath)
    if (!stat.isFile() || stat.size > 5 * 1024 * 1024) return null

    const fileName = path.basename(filePath)
    const matches: string[] = []

    // Check known cheat names
    const sigMatches = matchKnownCheat(fileName)
    matches.push(...sigMatches)

    // Check suspicious name patterns
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(fileName)) matches.push(`pattern:${pattern.source.replace(/\\/g, '')}`)
    }

    // Check known file hashes (SHA256)
    const hashCheck = await checkFileHash(filePath)
    if (hashCheck.matched) {
      matches.push(`hash:${hashCheck.hash.slice(0, 16)}...`)
      // Also push the full SHA256 so admin panel can extract it from scan results
      matches.push(`sha256:${hashCheck.hash}`)
    }

    // Text content scanning
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

    // Binary signature scanning
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

async function scanBrowserHistory(keywords?: string[]): Promise<ScanResult[]> {
  const kw = keywords || ALL_CHEAT_KEYWORDS
  const results: ScanResult[] = []

  try {
    // Use sql.js-based structured browser history parser
    const browserResults = await scanAllBrowsers(kw)

    for (const br of browserResults) {
      if (br.entries.length === 0) continue

      // Group entries by keyword match for the ScanResult.matches format
      const matchSet = new Set<string>()
      let maxRisk: 'low' | 'medium' | 'high' = 'low'
      let matchCount = 0

      for (const entry of br.entries) {
        const url = entry.url.toLowerCase()
        const title = entry.title.toLowerCase()
        for (const keyword of kw) {
          if (url.includes(keyword.toLowerCase()) || title.includes(keyword.toLowerCase())) {
            matchSet.add(`browser:${keyword}`)
            matchCount++
          }
        }
      }

      if (matchSet.size > 0) {
        if (matchCount >= 5) maxRisk = 'high'
        else if (matchCount >= 3) maxRisk = 'medium'

        results.push({
          path: br.path,
          fileName: `История (${br.browser})`,
          type: 'browser',
          risk: maxRisk,
          matches: Array.from(matchSet).slice(0, 15),
          size: br.entries.length,
          modifiedAt: br.entries[0]?.lastVisitTime || new Date().toISOString(),
        })

        // Add detail entries for high-value findings (URLs)
        const suspiciousEntries = br.entries.filter(e => {
          const url = e.url.toLowerCase()
          const title = e.title.toLowerCase()
          return kw.some(k => url.includes(k.toLowerCase()) || title.includes(k.toLowerCase()))
        })

        for (const entry of suspiciousEntries.slice(0, 8)) {
          const urlMatch = kw.find(k =>
            entry.url.toLowerCase().includes(k.toLowerCase()) ||
            entry.title.toLowerCase().includes(k.toLowerCase())
          )
          results.push({
            path: entry.url,
            fileName: `[${br.browser}] ${entry.title.slice(0, 60)}`,
            type: 'browser',
            risk: maxRisk,
            matches: [`browser:${urlMatch || 'suspicious'}`, `visited:${entry.lastVisitTime.slice(0, 10)}`, `count:${entry.visitCount}`],
            size: entry.url.length,
            modifiedAt: entry.lastVisitTime,
          })
        }
      }
    }
  } catch (err) {
    console.error('Browser history scan error:', err)
  }

  await yieldToEventLoop()
  return results
}

async function runFileScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  // Clear dedup for a fresh scan
  _findingDedup.clear()

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

    // Collect files first, then scan in parallel with concurrency limit
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
        if (r) {
          results.push(r)
        }
      }

      await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
    }

    await sendProgress(win, { phase: 'scanning', currentDir: dir, filesFound: results.length, filesScanned, totalDirs: scanDirs.length, dirsDone: i + 1 })
  }

  return { results, filesScanned }
}

// ═══════════════════════════════════════════════
// MODE 2: PROCESS SCAN
// ═══════════════════════════════════════════════

function scanRunningProcesses(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const output = execSync('tasklist /FO CSV /NH', { encoding: 'utf-8', timeout: 5000 })
    for (const line of output.trim().split('\n')) {
      try {
        const parts = line.match(/"([^"]+)","(\d+)","(\d+)","([^"]+)"/)
        if (!parts) continue
        const name = parts[1].toLowerCase()
        const pid = parseInt(parts[2], 10)
        const memStr = parts[3].replace(/[^\d]/g, '')
        const memory = parseInt(memStr, 10) || 0

        const matches = matchKnownCheat(name)

        if (matches.length > 0) {
          results.push({
            path: `process:${parts[1]} (PID: ${pid})`, fileName: parts[1], type: 'process',
            risk: matches.length >= 2 ? 'high' : 'medium',
            matches, size: memory * 1024, modifiedAt: new Date().toISOString(),
          })
        }
      } catch (_e) { /* skip */ }
    }
  } catch (_e) { /* tasklist failed */ }

  return results
}

function scanRecentItems(): ScanResult[] {
  const results: ScanResult[] = []
  const recentDir = path.join(_HOME, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent')

  try {
    if (!fs.existsSync(recentDir)) return results
    for (const item of fs.readdirSync(recentDir)) {
      const matches = matchKnownCheat(item)
      if (matches.length > 0) {
        const itemPath = path.join(recentDir, item)
        try {
          const stat = fs.statSync(itemPath)
          results.push({ path: itemPath, fileName: item, type: 'file', risk: matches.length >= 2 ? 'high' : 'medium', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
        } catch (_e) { /* skip */ }
      }
    }
  } catch (_e) { /* skip */ }

  return results
}

function scanPrefetchFiles(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  try {
    if (!fs.existsSync(prefetchDir)) return results
    for (const file of fs.readdirSync(prefetchDir)) {
      const matches = matchKnownCheat(file)
      if (matches.length > 0) {
        const filePath = path.join(prefetchDir, file)
        try {
          const stat = fs.statSync(filePath)
          results.push({ path: filePath, fileName: file, type: 'file', risk: matches.length >= 2 ? 'high' : 'medium', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
        } catch (_e) { /* skip */ }
      }
    }
  } catch (_e) { /* skip */ }

  return results
}

/** v2: Advanced process scan — checks loaded DLLs and modules via PowerShell */
function scanRunningProcessesV2(): ScanResult[] {
  const results: ScanResult[] = []

  // Standard process scan first
  const basicResults = scanRunningProcesses()
  for (const r of basicResults) {
    if (addFindingDedup(`proc:${r.fileName}`)) results.push(r)
  }

  // Advanced: get process modules (ONE PowerShell call, shared across all analysis blocks)
  let processes: any[] = []
  try {
    const psOut = execSync(
      `powershell -Command "Get-Process | Where-Object { $_.Modules } | Select-Object Name, Id, @{N='Mods';E={$_.Modules | Select -Expand ModuleName}} | ConvertTo-Json -Depth 3"`,
      { encoding: 'utf-8', timeout: 10000 },
    )

    if (psOut && psOut.trim().length >= 5) {
      const parsed = JSON.parse(psOut)
      processes = Array.isArray(parsed) ? parsed : [parsed]
    }
  } catch (_e) { /* PowerShell failed */ }

  if (processes.length === 0) return results

  // ── Phase 1: Module analysis (check process DLLs for suspicious names) ──
  // Uses the SAME `processes` data as the other phases — no duplicate PowerShell call.
  for (const proc of processes) {
    const procName = (proc.Name || '').toLowerCase()
    const modules: string[] = proc.Mods || []

    for (const modName of modules) {
      if (!modName || typeof modName !== 'string') continue
      const modLower = modName.toLowerCase()

      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        for (const name of cat.names) {
          if (modLower.includes(name) && addFindingDedup(`mod:${procName}:${modLower}`)) {
            results.push({
              path: `process:${proc.Name} (PID: ${proc.Id})`,
              fileName: `Module: ${modName}`,
              type: 'process',
              risk: cat.risk === 'CRITICAL' || cat.risk === 'HIGH' ? 'high' : 'medium',
              matches: [`module:${name} (${catName})`, `process:${procName}`],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        }
      }
    }
  }

  // ── Phase 2: Memory dump + string analysis + API Hashing + AMSI/ETW ──
  // All dump-dependent analysis runs HERE while the dump file is alive.
  // dumpAndAnalyze() internally deletes the dump file, so reusing it later is NOT possible.
  for (const proc of processes) {
    const procName = (proc.Name || '').toLowerCase()
    if (!proc.Id) continue

    const nameMatches = matchKnownCheat(procName).length > 0
    const modMatches = (proc.Mods || []).some((m: string) => matchKnownCheat((m || '').toLowerCase()).length > 0)

    if (nameMatches || modMatches) {
      // dumpAndAnalyze() does: dump → analyze strings + auto-rules → delete dump → return results
      const dumpResult = dumpAndAnalyze(proc.Id, ALL_CHEAT_KEYWORDS, procName, undefined)
      if (dumpResult.success && dumpResult.riskScore > 40) {
        results.push({
          path: `memory-dump:${proc.Name} (PID: ${proc.Id})`,
          fileName: `Memory analysis: ${proc.Name}`,
          type: 'process',
          risk: dumpResult.riskScore > 70 ? 'high' : 'medium',
          matches: dumpResult.cheatMatches.slice(0, 5),
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }

      // API Hashing + AMSI/ETW need a separate dump (dumpAndAnalyze already deleted the first one)
      const dumpPath2 = dumpProcessMemory(proc.Id, `hash_${procName}`)
      if (dumpPath2) {
        try {
          const hashRes = analyzeApiHashingInDump(dumpPath2)
          if (hashRes.detected && addFindingDedup(`api-hash:${proc.Id}`)) {
            results.push({
              path: `memory:${proc.Name} (PID:${proc.Id})`,
              fileName: `API Hashing in memory`,
              type: 'process',
              risk: hashRes.confidence > 70 ? 'high' : 'medium',
              matches: hashRes.patterns.slice(0, 5),
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }

          const patchRes = scanProcessForAmsiEtw(proc.Id, procName, dumpPath2)
          if ((patchRes.amsiPatched || patchRes.etwPatched) && addFindingDedup(`patch:${proc.Id}`)) {
            results.push({
              path: `patch:${proc.Name} (PID:${proc.Id})`,
              fileName: `AMSI/ETW Patched`,
              type: 'process',
              risk: 'high',
              matches: patchRes.details.slice(0, 8),
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
        } finally {
          try { fs.unlinkSync(dumpPath2) } catch (_e) { /* ignore */ }
        }
      }
    }
  }

  // ── Phase 3: RWX + DVM + Behavior profiling (no dump needed) ──
  for (const proc of processes) {
    const procName = (proc.Name || '').toLowerCase()
    if (!proc.Id) continue
    const modules: string[] = proc.Mods || []

    // RWX memory regions (game processes only)
    const gameKeywords = ['gta5', 'fivem', 'ragemp', 'altv', 'gta', 'fivem_gtaprocess']
    const isGameProc = gameKeywords.some(k => procName.includes(k))
    if (isGameProc && proc.Id) {
      try {
        const rwxRes = scanRwxAndThreads(proc.Id, procName)
        const rwxItem = rwxResultToScanResult(rwxRes)
        if (rwxItem && addFindingDedup(`rwx:${proc.Id}`)) {
          results.push(rwxItem)
        }
      } catch (_e) { /* RWX scan optional */ }
    }

    // Disk vs Memory — inline hook detection
    if (proc.Id) {
      try {
        const dvmResult = scanDiskVsMemory(proc.Id, procName)
        const dvmItem = dvmResultToScanResult(dvmResult)
        if (dvmItem && addFindingDedup(`dvm:${dvmItem.fileName}`)) {
          results.push(dvmItem)
        }
      } catch (_e) { /* DVM scan optional */ }
    }

    // Behavior profile for ALL processes
    const profile = buildBehaviorProfile(proc.Id, procName, modules)
    const profileResult = profileToScanResult(profile)
    if (profileResult && addFindingDedup(`behavior:${proc.Id}`)) {
      results.push(profileResult)
    }
  }

  return results
}

async function runProcessScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'Running processes...', filesFound: 0, filesScanned: 0, totalDirs: 7, dirsDone: 1 })
  results.push(...scanRunningProcesses())

  await sendProgress(win, { phase: 'scanning', currentDir: 'Masquerading checks...', filesFound: results.length, filesScanned: results.length, totalDirs: 7, dirsDone: 2 })
  results.push(...scanMasqueradingProcesses())

  await sendProgress(win, { phase: 'scanning', currentDir: 'Recent items...', filesFound: results.length, filesScanned: results.length, totalDirs: 7, dirsDone: 3 })
  results.push(...scanRecentItems())

  await sendProgress(win, { phase: 'scanning', currentDir: 'Prefetch files...', filesFound: results.length, filesScanned: results.length, totalDirs: 7, dirsDone: 4 })
  results.push(...scanPrefetchFiles())

  await sendProgress(win, { phase: 'scanning', currentDir: 'Game integrity check...', filesFound: results.length, filesScanned: results.length, totalDirs: 7, dirsDone: 5 })
  results.push(...scanGameIntegrity())
  results.push(...scanGameModules())

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned: results.length, totalDirs: 7, dirsDone: 6 })

  const browserResults = await scanBrowserHistory()
  results.push(...browserResults)

  return { results, filesScanned: results.length + browserResults.length }
}

// ═══════════════════════════════════════════════
// BONUS: NAMED PIPES SCAN
// ═══════════════════════════════════════════════

/** Scan Windows Named Pipes for cheat-related IPC channels */
function scanNamedPipes(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execSync('powershell -Command "[System.IO.Directory]::GetFiles(\"\\\\\\.\\\\pipe\\\\\")" 2>$null', { encoding: 'utf-8', timeout: 5000 })
    const pipes = out.split('\n').map(l => l.trim()).filter(Boolean)

    const suspiciousPipePatterns = [
      /cheat/i, /hack/i, /inject/i, /menu/i, /gta/i, /fivem/i,
      /rage/i, /altv/i, /eulen/i, /redengine/i, /dma/i, /overlay/i,
    ]

    for (const pipe of pipes) {
      const lower = pipe.toLowerCase()
      for (const pat of suspiciousPipePatterns) {
        if (pat.test(lower)) {
          if (addFindingDedup(`pipe:${pipe}`)) {
            results.push({
              path: pipe,
              fileName: path.basename(pipe),
              type: 'software',
              risk: 'high',
              matches: [`Named pipe matches: ${pat.source}`, 'Possible cheat IPC channel'],
              size: 0,
              modifiedAt: new Date().toISOString(),
            })
          }
          break
        }
      }
    }
  } catch (_e) { /* ignore */ }
  return results
}

// ═══════════════════════════════════════════════
// BONUS: WMI PERSISTENCE SCAN
// ═══════════════════════════════════════════════

/** Scan WMI Event Subscription for cheat persistence */
function scanWmiPersistence(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execSync(
      'powershell -Command "Get-WmiObject -Class __EventFilter -Namespace \"root\\\\subscription\" | Select-Object Name, Query | ConvertTo-Json -Compress" 2>$null',
      { encoding: 'utf-8', timeout: 8000 },
    )
    if (!out.trim() || out.includes('null')) return results

    const parsed = JSON.parse(out)
    const items = Array.isArray(parsed) ? parsed : [parsed]

    const wmiSuspicious = ['process', 'create', 'gta', 'fivem', 'cheat', 'inject', 'bypass']
    for (const item of items) {
      const query = (item.Query || '').toLowerCase()
      const name = (item.Name || '').toLowerCase()

      if (wmiSuspicious.some(k => query.includes(k) || name.includes(k))) {
        results.push({
          path: `WMI:\\${item.Name}`,
          fileName: `WMI Filter: ${item.Name}`,
          type: 'registry',
          risk: 'high',
          matches: ['WMI Event Subscription — cheat persistence', `Query: ${(item.Query || '').slice(0, 80)}`],
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch (_e) { /* ignore */ }
  return results
}

// ═══════════════════════════════════════════════
// MODE 3: CHEAT-SPECIFIC SEARCH
// ═══════════════════════════════════════════════

const CHEAT_SOFTWARE_NAMES: Record<string, string[]> = {
  'Nightfall': ['nightfall', 'nightfall cheat', 'nightfall loader'],
  'DMA': ['dma', 'dma card', 'dma cheat', 'dma firmware'],
  '0XCheat': ['0xcheat', '0x cheat', 'oxcheat'],
  '1337 Cheat': ['1337', '1337 cheat', 'leet cheat'],
  'NoleetCheats': ['noleet', 'noleetcheats', 'noleet cheat'],
}

// ═══════════════════════════════════════════════
// SCHEDULED TASKS + WMI PERSISTENCE SCAN
// ═══════════════════════════════════════════════

/**
 * Scan for suspicious scheduled tasks — cheat loaders often persist via
 * schtasks under names like "Windows Update Helper", "Discord Updater", etc.
 */
function scanScheduledTasks(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    // Get scheduled tasks that:
    // 1. Are in the root path (\), not Microsoft\Windows\ etc
    // 2. Run from suspicious locations (Temp, AppData, Downloads)
    // 3. Are not by Microsoft, Adobe, Google, or known vendors
    const ps = `
Get-ScheduledTask | Where-Object {
  $_.TaskPath -eq '\\' -and
  $_.Author -notmatch 'Microsoft|Adobe|Google|Mozilla|Apple|Oracle|NVIDIA|AMD|Intel|Spotify|Discord|Slack|GitHub|Docker|JetBrains|Valve|Epic|Rockstar'
} | Select-Object TaskName, TaskPath, Author, State, @{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute }) -join '; '}} | ConvertTo-Json -Compress
`.trim()

    const out = execSync(`powershell -Command "${ps.replace(/"/g, '\\"').replace(/\n/g, '; ')}"`, {
      encoding: 'utf-8',
      timeout: 10000,
      windowsHide: true,
    }).trim()

    if (!out || out.length < 5) return results

    const parsed = JSON.parse(out)
    const tasks = Array.isArray(parsed) ? parsed : [parsed]

    for (const task of tasks) {
      const name = (task.TaskName || '').trim()
      const author = (task.Author || '').trim()
      const actions = (task.Actions || '').toLowerCase()
      const state = (task.State || '').trim()

      // Skip empty / trivial tasks
      if (!name || name === '') continue

      const matches: string[] = [`Scheduled task: ${name}`, `Author: ${author || 'N/A'}`, `State: ${state}`]
      let riskScore = 0

      // Suspicious indicators:
      // 1. Running from AppData/Local, Temp, or Downloads
      const suspiciousPaths = ['\\temp\\', '\\appdata\\local\\', '\\appdata\\roaming\\', '\\downloads\\', '\\users\\']
      const runsFromSuspiciousDir = suspiciousPaths.some(p => actions.includes(p))
      if (runsFromSuspiciousDir) {
        matches.push('Executes from user temp/AppData directory')
        riskScore += 25
      }

      // 2. No author (empty or null) — often means malware hiding origin
      if (!author || author === '' || author === 'null') {
        matches.push('No author information')
        riskScore += 15
      }

      // 3. Known cheat-related keywords in task name
      const cheatKeywords = ['cheat', 'hack', 'inject', 'bypass', 'loader', 'mod menu', 'gta', 'fivem', 'spoofer']
      for (const kw of cheatKeywords) {
        if (name.toLowerCase().includes(kw)) {
          matches.push(`Task name contains: ${kw}`)
          riskScore += 30
          break
        }
      }

      // 4. Executes a script (ps1, bat, vbs) from temp
      const scriptExts = ['.ps1', '.bat', '.vbs', '.cmd', '.js', '.exe']
      if (scriptExts.some(ext => actions.includes(ext)) && runsFromSuspiciousDir) {
        matches.push('Script executable from suspicious location')
        riskScore += 20
      }

      if (riskScore >= 20 && addFindingDedup(`schedtask:${name}`)) {
        results.push({
          path: `Scheduled Task: ${name}`,
          fileName: `Scheduled task: ${name}`,
          type: 'software',
          risk: riskScore > 50 ? 'high' : 'medium',
          matches: matches.slice(0, 6),
          size: 0,
          modifiedAt: new Date().toISOString(),
        })
      }
    }
  } catch { /* schtasks optional */ }

  return results
}

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

function scanForCheatFiles(cheatName: string, keywords: string[]): ScanResult[] {
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

function scanRegistryForCheats(): ScanResult[] {
  const results: ScanResult[] = []

  for (const keyPath of REGISTRY_SCAN_KEYS) {
    try {
      const output = execSync(`reg query "${keyPath}" /s 2>nul`, { encoding: 'utf-8', timeout: 5000 })
      if (!output || output.trim().length === 0) continue

      const lower = output.toLowerCase()
      for (const keyword of ALL_CHEAT_KEYWORDS) {
        if (lower.includes(keyword.toLowerCase())) {
          const safeKey = keyword.slice(0, 40)
          results.push({
            path: keyPath, fileName: `Registry: ${safeKey}`, type: 'registry',
            risk: 'high', matches: [`registry:${safeKey} found`], size: 0, modifiedAt: new Date().toISOString(),
          })
          break
        }
      }
    } catch (_e) { /* skip */ }
  }

  return results
}

async function runCheatScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []
  const cheatNames = Object.keys(CHEAT_SOFTWARE_NAMES)
  let filesScanned = 0

  for (let i = 0; i < cheatNames.length; i++) {
    const cheatName = cheatNames[i]
    const keywords = CHEAT_SOFTWARE_NAMES[cheatName]

    await sendProgress(win, { phase: 'scanning', currentDir: `Searching for ${cheatName}...`, filesFound: results.length, filesScanned, totalDirs: cheatNames.length + 2, dirsDone: i + 1 })

    const fileResults = scanForCheatFiles(cheatName, keywords)
    results.push(...fileResults)
    filesScanned += fileResults.length
  }

  const cheatKw = Object.values(CHEAT_SOFTWARE_NAMES).flat()
  const browserResults = await scanBrowserHistory(cheatKw)
  results.push(...browserResults)

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Checking registry...', filesFound: results.length, filesScanned, totalDirs: cheatNames.length + 2, dirsDone: cheatNames.length + 1 })
  const registryResults = scanRegistryForCheats()
  results.push(...registryResults)

  return { results, filesScanned: results.length }
}

// ═══════════════════════════════════════════════
// MODE 4: DMA DETECTION
// ═══════════════════════════════════════════════

const KNOWN_DMA_VENDORS = [
  { name: 'Xilinx', ids: ['10ee'] },
  { name: 'Altera/Intel FPGA', ids: ['1172'] },
  { name: 'Lattice Semiconductor', ids: ['1204'] },
  { name: 'FTDI (USB-FPGA bridge)', ids: ['0403'] },
  { name: 'Texas Instruments (FPGA)', ids: ['104c'] },
]

function queryPnpDevices(filter: string): string {
  return execCmd(
    `wmic path Win32_PnPEntity where "${filter}" get DeviceID,Name,PNPDeviceID /format:csv 2>nul`,
    `powershell "Get-PnpDevice | Where-Object { $_.Class -eq '${filter.replace(/PNPClass='/g, '').replace(/'/g, '')}' } | Format-List"`,
  )
}

function scanDmaDevices(): ScanResult[] {
  const results: ScanResult[] = []

  const output = queryPnpDevices("PNPClass='PCI' OR PNPClass='System'")
  if (output) {
    const lower = output.toLowerCase()
    for (const vendor of KNOWN_DMA_VENDORS) {
      for (const id of vendor.ids) {
        if (lower.includes(id)) {
          results.push({
            path: 'System Devices', fileName: `PCI Device: ${vendor.name}`, type: 'hardware', risk: 'high',
            matches: [`pci:${vendor.name} (VEN_${id})`], size: 0, modifiedAt: new Date().toISOString(),
          })
        }
      }
    }
  }

  const dmaKeywords = ['dma', 'fpga', 'pcileech', 'fuser', 'screamer', 'leechcore', 'memprocfs', 'vmm', 'kmem', 'coremap', 'ftd3', 'ftd2']
  for (const dir of getScanPaths()) {
    if (!fs.existsSync(dir)) continue
    try {
      for (const entry of fs.readdirSync(dir)) {
        const lower = entry.toLowerCase()
        const matches: string[] = []
        for (const kw of dmaKeywords) {
          if (lower.includes(kw)) matches.push(`dma-keyword:${kw}`)
        }
        if (matches.length > 0) {
          try {
            const stat = fs.statSync(path.join(dir, entry))
            results.push({ path: path.join(dir, entry), fileName: entry, type: 'software', risk: 'high', matches, size: stat.size, modifiedAt: stat.mtime.toISOString() })
          } catch (_e) { /* skip */ }
        }
      }
    } catch (_e) { /* skip */ }
  }

  try {
    const sysDir = path.join(_WR, 'System32', 'drivers')
    if (fs.existsSync(sysDir)) {
      for (const driver of fs.readdirSync(sysDir)) {
        const lower = driver.toLowerCase()
        const matches: string[] = []
        if (dmaKeywords.some(k => lower.includes(k))) matches.push(`driver:${driver}`)
        if (matches.length > 0) {
          results.push({ path: path.join(sysDir, driver), fileName: `Driver: ${driver}`, type: 'software', risk: 'high', matches, size: 0, modifiedAt: new Date().toISOString() })
        }
      }
    }
  } catch (_e) { /* skip */ }

  return results
}

function scanDmaRegistry(): ScanResult[] {
  const results: ScanResult[] = []
  const svcPath = 'HKLM\\SYSTEM\\CurrentControlSet\\Services'

  for (const term of ['dma', 'fpga', 'pcileech', 'fuser', 'leech']) {
    try {
      const out = execSync(`reg query "${svcPath}" /s /f "${term}" 2>nul`, { encoding: 'utf-8', timeout: 5000 })
      if (out.trim().length > 0) {
        results.push({ path: svcPath, fileName: `Registry: ${term.toUpperCase()}-related services`, type: 'registry', risk: 'high', matches: [`registry:${term} service(s) found`], size: 0, modifiedAt: new Date().toISOString() })
      }
    } catch (_e) { /* skip */ }
  }

  return results
}

async function runDmaScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking PCI devices...', filesFound: 0, filesScanned: 0, totalDirs: 5, dirsDone: 1 })
  results.push(...scanDmaDevices())

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking USB devices...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 2 })
  const usbOut = queryPnpDevices("PNPClass='USB'")
  if (usbOut && (usbOut.toLowerCase().includes('ftdi') || usbOut.toLowerCase().includes('ftd3'))) {
    results.push({ path: 'USB Devices', fileName: 'USB Device: Possible DMA interface', type: 'hardware', risk: 'medium', matches: ['usb:FTDI device (common DMA interface)'], size: 0, modifiedAt: new Date().toISOString() })
  }

  await sendProgress(win, { phase: 'scanning', currentDir: 'Checking registry...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 3 })
  results.push(...scanDmaRegistry())

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history for DMA...', filesFound: results.length, filesScanned: results.length, totalDirs: 5, dirsDone: 4 })
  const dmaKw = ['dma', 'fpga', 'pcileech', 'fuser', 'screamer', 'kmem']
  const browserResults = await scanBrowserHistory(dmaKw)
  results.push(...browserResults)

  return { results, filesScanned: results.length + browserResults.length }
}

// ═══════════════════════════════════════════════
// MODE 5: EXTENDED — v2 FULL SYSTEM SCAN
// Based on predator_scanner_v2.py:
//   8 phases with heuristic analysis, entropy,
//   category-based signatures, risk scoring,
//   deduplication, digital signature verification.
// ═══════════════════════════════════════════════

const EXTENDED_CHEAT_KEYWORDS: string[] = [
  'eulen', 'redengine', 'skript.gg', 'impulse.one',
  'luna', 'paragon', 'ozark', 'cherax', 'stand.gg',
  '2take1.menu', 'modest', 'kiddions', 'majesty.rp',
  'menyoo', 'simpletrainer', 'nativeui',
  'xenos', 'extremeinjector', 'manualmap',
  'fivem bypass', 'rockstar bypass', 'ac bypass',
  'rpchanger', 'hwid spoofer', 'mac spoofer',
  'dma', 'fpga', 'pcileech', 'fuser', 'screamer',
  'leechcore', 'memprocfs', 'vmm', 'kmem', 'winpmem',
  'process hacker', 'dnspy', 'ollydbg', 'x64dbg', 'ida',
  'aimbot', 'wallhack', 'esp', 'triggerbot',
  'norecoil', 'godmode', 'teleport', 'moneydrop',
  'recovery', 'unlock all', 'mod menu',
  // v2 category keywords
  'inject', 'injector', 'hook', 'detour', 'bypass', 'evade',
  'spoofer', 'hwid', 'obfuscator', 'vmprotect', 'themida',
]

/** v2: Deep registry scan — checks all autorun paths against categories */
function scanRegistryDeepV2(): ScanResult[] {
  const results: ScanResult[] = []

  const regPaths = [
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKCU\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run',
    'HKLM\\SYSTEM\\CurrentControlSet\\Services',
    // v3.0: Winlogon paths
    'HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
  ]

  for (const keyPath of regPaths) {
    try {
      const output = execSync(`reg query "${keyPath}" /s 2>nul`, { encoding: 'utf-8', timeout: 5000 })
      if (!output || output.trim().length === 0) continue

      const lower = output.toLowerCase()

      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        for (const name of cat.names) {
          if (lower.includes(name)) {
            const dedupKey = `reg-deep:${catName}:${name}`
            if (addFindingDedup(dedupKey)) {
              results.push({
                path: keyPath,
                fileName: `Registry [${catName}]: ${name}`,
                type: 'registry',
                risk: cat.risk === 'CRITICAL' ? 'high' : cat.risk === 'HIGH' ? 'high' : 'medium',
                matches: [`registry-deep:${name} (${catName})`, `risk:${cat.risk}`],
                size: 0,
                modifiedAt: new Date().toISOString(),
              })
            }
          }
        }
      }
    } catch (_e) { /* skip */ }
  }

  return results
}

/** v2: Prefetch analysis against categories */
function scanPrefetchV2(): ScanResult[] {
  const results: ScanResult[] = []
  const prefetchDir = path.join(_WR, 'Prefetch')

  try {
    if (!fs.existsSync(prefetchDir)) return results
    for (const file of fs.readdirSync(prefetchDir)) {
      if (!file.toLowerCase().endsWith('.pf')) continue
      const fileLower = file.toLowerCase()

      for (const [catName, cat] of Object.entries(SUSPICIOUS_CATEGORIES)) {
        for (const name of cat.names) {
          if (fileLower.includes(name)) {
            const dedupKey = `pf:${catName}:${file}`
            if (addFindingDedup(dedupKey)) {
              const filePath = path.join(prefetchDir, file)
              let mtime = new Date().toISOString()
              try { mtime = fs.statSync(filePath).mtime.toISOString() } catch (_e) { /* skip */ }

              results.push({
                path: filePath,
                fileName: `Prefetch [${catName}]: ${file}`,
                type: 'file',
                risk: cat.risk === 'CRITICAL' || cat.risk === 'HIGH' ? 'high' : 'medium',
                matches: [`prefetch:${name} (${catName})`, `last-run:${mtime.slice(0, 10)}`],
                size: 0,
                modifiedAt: mtime,
              })
            }
          }
        }
      }
    }
  } catch (_e) { /* skip */ }

  return results
}

/** v2: Network connection scan — suspicious ports (proxy/VPN) */
function scanNetstatV2(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const out = execSync('netstat -ano', { encoding: 'utf-8', timeout: 8000 })
    const lines = out.split('\n')
    const suspiciousPortSet = new Set(['1080', '3128', '8080', '9050', '9150'])
    const foundPorts: string[] = []

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed.match(/^(TCP|UDP)/i)) continue
      const parts = trimmed.split(/\s+/)
      if (parts.length < 4) continue

      const localAddr = parts[1] || ''
      const remoteAddr = parts[2] || ''
      const pid = parts[parts.length - 1] || ''

      const port = localAddr.split(':').pop() || ''
      if (suspiciousPortSet.has(port)) {
        const dedupKey = `net-port:${port}`
        if (addFindingDedup(dedupKey)) {
          foundPorts.push(`${port} (PID: ${pid})`)
        }
      }

      // Check for connections from suspicious IP ranges (proxy/VPN hosting)
      const remoteIp = remoteAddr.split(':')[0]
      if (remoteIp && remoteIp !== '0.0.0.0' && remoteIp !== '127.0.0.1' && remoteIp !== '[::]') {
        const suspiciousIps = [/^185\./, /^5\./, /^91\./, /^188\./]
        for (const pattern of suspiciousIps) {
          if (pattern.test(remoteIp) && addFindingDedup(`net-ip:${remoteIp}`)) {
            foundPorts.push(`remote:${remoteIp} (PID: ${pid})`)
            break
          }
        }
      }
    }

    if (foundPorts.length > 0) {
      results.push({
        path: 'Network Connections',
        fileName: `Suspicious connections: ${foundPorts.length}`,
        type: 'software',
        risk: foundPorts.length >= 2 ? 'high' : 'medium',
        matches: foundPorts.map(p => `netstat:${p}`),
        size: 0,
        modifiedAt: new Date().toISOString(),
      })
    }
  } catch (_e) { /* skip */ }

  return results
}

const EXTENDED_SCAN_PATHS: string[] = getScanPaths()

/** Safe spread — logs and returns empty array if value is not iterable */
function safeSpread<T>(label: string, value: T[] | null | undefined): T[] {
  if (!Array.isArray(value)) {
    console.error(`[safeSpread] ${label} — expected array, got:`, typeof value, value)
    return []
  }
  return value
}

async function runExtendedScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  // Clear dedup for a fresh scan
  _findingDedup.clear()
  _sigCache.clear()

  const results: ScanResult[] = []
  let filesScanned = 0
  const totalPhases = 8

  // ── Phase 1/8: Advanced processes (v2) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 1/8: Продвинутая проверка процессов...',
    filesFound: 0, filesScanned: 0, totalDirs: totalPhases, dirsDone: 1,
  })
  const processes = scanRunningProcessesV2()
  results.push(...safeSpread('scanRunningProcessesV2', processes))
  filesScanned += processes.length
  await yieldToEventLoop()

  // ── Phase 2/8: Heuristic file scan (v2) ──
  await sendProgress(win, {
    phase: 'scanning',
    currentDir: 'Этап 2/8: Эвристический анализ файлов (энтропия, сигнатуры, подпись)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 2,
  })

  for (let i = 0; i < EXTENDED_SCAN_PATHS.length; i++) {
    const dir = EXTENDED_SCAN_PATHS[i]
    try {
      await fsp.access(dir)
    } catch (_e) {
      continue
    }

    for await (const filePath of walkDirAsync(dir)) {
      filesScanned++
      try {
        const stat = await fsp.stat(filePath)
        const heuristic = heuristicFileScan(filePath)
        if (heuristic && heuristic.riskScore > 30) {
          const dedupKey = `heuristic:${filePath}:${heuristic.riskScore}`
          if (addFindingDedup(dedupKey)) {
            results.push({
              path: filePath,
              fileName: `[Score:${heuristic.riskScore}] ${path.basename(filePath)}`,
              type: 'file',
              risk: riskScoreToLevel(heuristic.riskScore),
              matches: heuristic.suspicions.slice(0, 5),
              size: stat.size,
              modifiedAt: stat.mtime.toISOString(),
            })
          }
        }
      } catch (_e) { /* skip */ }
      await yieldToEventLoop()

      if (filesScanned % 15 === 0) {
        await sendProgress(win, {
          phase: 'scanning',
          currentDir: `Этап 2/8: ${path.basename(dir)} (${filesScanned} файлов)...`,
          filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 2,
        })
      }
    }
  }

  // ── Phase 3/8: Deep registry scan (v2) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 3/8: Глубокая проверка реестра (9 категорий)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 3,
  })
  const regResults = scanRegistryDeepV2()
  results.push(...safeSpread('scanRegistryDeepV2', regResults))
  await yieldToEventLoop()

  // ── Phase 4/8: Prefetch analysis (v2) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 4/8: Анализ Prefetch (по категориям)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 4,
  })
  const pfResults = scanPrefetchV2()
  results.push(...safeSpread('scanPrefetchV2', pfResults))
  await yieldToEventLoop()

  // ── Phase 5/8: Network connections (v2) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 5/8: Проверка сетевых соединений (прокси/VPN)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 5,
  })
  const netResults = scanNetstatV2()
  results.push(...safeSpread('scanNetstatV2', netResults))
  await yieldToEventLoop()

  // ── Phase 5a: Masquerading process detection ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 5a: Проверка маскировки под системные процессы...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 5,
  })
  results.push(...safeSpread('scanMasqueradingProcesses', scanMasqueradingProcesses()))
  await yieldToEventLoop()

  // ── Phase 5b: Game integrity + platform modules ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 5b: Проверка целостности игры (FiveM, RAGE, ALT:V)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 5,
  })
  results.push(...safeSpread('scanGameIntegrity', scanGameIntegrity()))
  results.push(...safeSpread('scanGameModules', scanGameModules()))
  results.push(...safeSpread('scanOpenHandles', scanOpenHandles()))
  await yieldToEventLoop()

  // ── Phase 5c: Named Pipes + WMI persistence + AMSI/ETW ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 5c: Named Pipes, WMI, AMSI/ETW...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 5,
  })
  results.push(...safeSpread('scanNamedPipes', scanNamedPipes()))
  results.push(...safeSpread('scanWmiPersistence', scanWmiPersistence()))

  // AMSI/ETW patch detection on all processes
  try {
    const psAmsi = execSync(
      `powershell -Command "Get-Process | Select-Object Name, Id | ConvertTo-Json -Compress"`,
      { encoding: 'utf-8', timeout: 8000 },
    )
    if (psAmsi && psAmsi.trim().length >= 5) {
      const parsedAmsi = JSON.parse(psAmsi)
      const procsAmsi = Array.isArray(parsedAmsi) ? parsedAmsi : [parsedAmsi]
      for (const proc of procsAmsi.slice(0, 50)) { // limit to 50 for performance
        if (!proc.Id) continue
        const patchAmsi = scanProcessForAmsiEtw(proc.Id, proc.Name || 'unknown')
        if (patchAmsi.riskScore > 0 && addFindingDedup(`ext-patch:${proc.Id}`)) {
          results.push({
            path: `patch:${proc.Name} (PID:${proc.Id})`,
            fileName: 'AMSI/ETW tampering detected',
            type: 'process',
            risk: patchAmsi.riskScore > 60 ? 'high' : 'medium',
            matches: patchAmsi.details.slice(0, 6),
            size: 0,
            modifiedAt: new Date().toISOString(),
          })
        }
      }
    }
  } catch (_e) { /* AMSI/ETW pass optional */ }
  await yieldToEventLoop()

  // ── Phase 6/8: DMA detection ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 6/8: Обнаружение DMA-устройств...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 6,
  })
  const dmaResults = scanDmaDevices()
  results.push(...safeSpread('scanDmaDevices', dmaResults))
  await yieldToEventLoop()

  // ── Phase 6b/8: Scheduled Tasks (persistence) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 6b/8: Проверка планировщика (персистентность читов)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 6,
  })
  results.push(...safeSpread('scanScheduledTasks', scanScheduledTasks()))
  await yieldToEventLoop()

  // ── Phase 7/8: Registry (standard cheat scan) ──
  await sendProgress(win, {
    phase: 'scanning', currentDir: 'Этап 7/8: Проверка реестра (чит-база)...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 7,
  })
  const regStdResults = scanRegistryForCheats()
  results.push(...safeSpread('scanRegistryForCheats', regStdResults))
  await yieldToEventLoop()

  // ── Phase 8/8: Browser history (v2 keywords) ──
  await sendProgress(win, {
    phase: 'analyzing', currentDir: 'Этап 8/8: Проверка истории браузера...',
    filesFound: results.length, filesScanned, totalDirs: totalPhases, dirsDone: 8,
  })
  const browserResults = await scanBrowserHistory(EXTENDED_CHEAT_KEYWORDS)
  results.push(...safeSpread('scanBrowserHistory', browserResults))

  return { results, filesScanned }
}

// ═══════════════════════════════════════════════
// MODE 6: NETWORK SCAN
// ═══════════════════════════════════════════════

const SUSPICIOUS_DOMAINS = [
  'nightfall', 'eulen', 'redengine', 'skript.gg', 'impulse.one',
  '2take1.menu', 'stand.gg', 'cherax.menu', 'paragon.menu',
  'ozark.menu', 'luna.menu', 'modest.menu', 'kiddions',
  'majesty.rp', 'unknowncheats', 'mpgh', 'elitepvpers',
  'fivem.cheat', 'gta5.hack', 'rpgta5',
]

const SUSPICIOUS_IP_PATTERNS = [
  /^185\./, /^5\./, /^104\.2[0-3]/, /^91\./, /^188\./,
  /^45\.33\./, /^107\./, /^108\./, /^162\./, /^23\./,
]

function scanDnsCache(): ScanResult[] {
  const results: ScanResult[] = []
  try {
    const out = execSync('ipconfig /displaydns', { encoding: 'utf-8', timeout: 8000 })
    const lines = out.split('\n')
    let currentName = ''
    const found: string[] = []

    for (const line of lines) {
      const nameMatch = line.match(/^\s*Record Name\s*[\s:]+\s*(.+)$/i)
      if (nameMatch) {
        currentName = nameMatch[1].toLowerCase().trim()
        for (const domain of SUSPICIOUS_DOMAINS) {
          if (currentName.includes(domain)) {
            found.push(`dns:${domain}`)
          }
        }
      }
    }

    if (found.length > 0) {
      results.push({
        path: 'DNS Cache', fileName: `DNS: Suspicious entries (${found.length})`,
        type: 'software', risk: found.length >= 3 ? 'high' : 'medium',
        matches: found, size: 0, modifiedAt: new Date().toISOString(),
      })
    }
  } catch (_e) { /* skip */ }
  return results
}

function scanHostsFile(): ScanResult[] {
  const results: ScanResult[] = []
  const hostsPath = path.join(_WR, 'System32', 'drivers', 'etc', 'hosts')

  try {
    if (!fs.existsSync(hostsPath)) return results
    const content = fs.readFileSync(hostsPath, 'utf-8')
    const lines = content.split('\n')
    let redirectCount = 0
    const suspicious: string[] = []

    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith('#') || trimmed.length === 0) continue

      const parts = trimmed.split(/\s+/)
      if (parts.length >= 2) {
        const ip = parts[0]
        const hostname = parts.slice(1).join(' ').toLowerCase()

        if ((ip === '0.0.0.0' || ip === '127.0.0.1') && SUSPICIOUS_DOMAINS.some(d => hostname.includes(d))) {
          suspicious.push(`hosts-block:${hostname}`)
          redirectCount++
        }

        if (ip !== '127.0.0.1' && ip !== '0.0.0.0' && ip !== '::1' && !ip.startsWith('255.')) {
          for (const domain of SUSPICIOUS_DOMAINS) {
            if (hostname.includes(domain)) {
              suspicious.push(`hosts-redirect:${hostname}→${ip}`)
              redirectCount++
            }
          }
        }
      }
    }

    if (suspicious.length > 0) {
      results.push({
        path: hostsPath, fileName: `Hosts: Suspicious entries (${redirectCount})`,
        type: 'file', risk: redirectCount >= 3 ? 'high' : 'medium',
        matches: suspicious, size: content.length, modifiedAt: new Date().toISOString(),
      })
    }

    const totalEntries = lines.filter(l => l.trim().length > 0 && !l.trim().startsWith('#')).length
    if (totalEntries > 20) {
      results.push({
        path: hostsPath, fileName: 'Hosts: Unusually large',
        type: 'file', risk: 'low',
        matches: [`hosts:${totalEntries} active entries (abnormal)`],
        size: content.length, modifiedAt: new Date().toISOString(),
      })
    }
  } catch (_e) { /* skip */ }

  return results
}

function scanNetstat(): ScanResult[] {
  const results: ScanResult[] = []

  try {
    const out = execSync('netstat -ano', { encoding: 'utf-8', timeout: 8000 })
    const lines = out.split('\n')
    let totalConnections = 0
    let establishedCount = 0
    let listeningCount = 0
    let foreignCount = 0
    const suspiciousPorts: string[] = []

    const KNOWN_CHEAT_PORTS = [
      1337, 1338, 4444, 4445, 5555, 6666, 6667, 6668, 6669,
      7000, 7777, 8000, 8443, 9000, 9001, 27015, 27016, 27017,
    ]

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed.match(/^(TCP|UDP)/i)) continue

      totalConnections++
      const parts = trimmed.split(/\s+/)
      if (parts.length < 4) continue

      const state = parts[parts.length - 2] || ''
      const foreignAddr = parts[parts.length - 3] || ''

      if (state === 'ESTABLISHED') establishedCount++
      if (state === 'LISTENING') listeningCount++

      const foreignIp = foreignAddr.split(':')[0]
      for (const pattern of SUSPICIOUS_IP_PATTERNS) {
        if (pattern.test(foreignIp)) {
          foreignCount++
          break
        }
      }

      const port = parseInt(foreignAddr.split(':').pop() || '0', 10)
      if (KNOWN_CHEAT_PORTS.includes(port)) {
        const pid = parts[parts.length - 1]
        suspiciousPorts.push(`port:${port} (PID: ${pid})`)
      }
    }

    if (suspiciousPorts.length > 0) {
      results.push({
        path: 'Active Connections', fileName: `Cheat-related ports: ${suspiciousPorts.length}`,
        type: 'software', risk: suspiciousPorts.length >= 2 ? 'high' : 'medium',
        matches: suspiciousPorts, size: 0, modifiedAt: new Date().toISOString(),
      })
    }

    results.push({
      path: 'Network Summary', fileName: `Connections: ${totalConnections}`,
      type: 'process', risk: 'low',
      matches: [
        `est:${establishedCount} active`, `lstn:${listeningCount} listening`,
        ...(foreignCount > 0 ? [`foreign:${foreignCount} unusual IPs`] : ['foreign:0']),
      ],
      size: 0, modifiedAt: new Date().toISOString(),
    })

  } catch (_e) { /* skip */ }

  return results
}

async function runNetworkScan(win: BrowserWindow | null): Promise<{ results: ScanResult[]; filesScanned: number }> {
  const results: ScanResult[] = []

  await sendProgress(win, { phase: 'scanning', currentDir: 'DNS Cache...', filesFound: 0, filesScanned: 0, totalDirs: 4, dirsDone: 1 })
  results.push(...scanDnsCache())
  await yieldToEventLoop()

  await sendProgress(win, { phase: 'scanning', currentDir: 'Hosts file...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 2 })
  results.push(...scanHostsFile())
  await yieldToEventLoop()

  await sendProgress(win, { phase: 'scanning', currentDir: 'Active connections...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 3 })
  results.push(...scanNetstat())
  await yieldToEventLoop()

  await sendProgress(win, { phase: 'analyzing', currentDir: 'Browser history...', filesFound: results.length, filesScanned: results.length, totalDirs: 4, dirsDone: 4 })
  const browserResults = await scanBrowserHistory(SUSPICIOUS_DOMAINS)
  results.push(...browserResults)

  return { results, filesScanned: results.length + browserResults.length }
}

// ═══════════════════════════════════════════════
// CLOUD SIGNATURE SYNC
// ═══════════════════════════════════════════════

// API base URL — same as in src/api.ts
const API_BASE_HOST = '5.164.42.189'
const API_BASE_PORT = 3001

/**
 * Fetch confirmed cheat hashes from server and merge into local database.
 * Runs periodically to keep signatures up-to-date.
 */
async function fetchCheatHashes(): Promise<void> {
  try {
    // Use fetch-like approach via http module
    const http = require('http')
    const url = `/api/auth/fetch-hashes?after=${encodeURIComponent('2000-01-01')}`
    
    const body = await new Promise<string>((resolve, reject) => {
      const req = http.get({ hostname: API_BASE_HOST, port: API_BASE_PORT, path: url, timeout: 8000 }, (res: any) => {
        let data = ''
        res.on('data', (chunk: string) => data += chunk)
        res.on('end', () => resolve(data))
      })
      req.on('error', reject)
      req.on('timeout', () => { req.destroy(); reject(new Error('timeout')) })
    })

    const parsed = JSON.parse(body)
    if (parsed && Array.isArray(parsed.hashes) && parsed.hashes.length > 0) {
      const newHashes: string[] = parsed.hashes.map((h: any) => h.sha256).filter(Boolean)
      if (newHashes.length > 0) {
        mergeCheatHashes(newHashes)
        console.log(`[Predator] Synced ${newHashes.length} cheat hashes from cloud (total: ${KNOWN_CHEAT_HASHES.length})`)
      }
    }
  } catch (err) {
    // Cloud sync is optional — silently skip on failure
    console.log('[Predator] Cloud hash sync failed (server unreachable? — will retry)')
  }
}

// ── Periodic sync timer ──
let _syncTimer: ReturnType<typeof setInterval> | null = null

/** Start periodic cloud signature sync (every 5 minutes) */
export function startCloudSync(): void {
  if (_syncTimer) return
  // Initial fetch on startup
  fetchCheatHashes()
  // Then every 5 minutes
  _syncTimer = setInterval(() => fetchCheatHashes(), 5 * 60 * 1000)
}

/** Stop periodic cloud signature sync */
export function stopCloudSync(): void {
  if (_syncTimer) {
    clearInterval(_syncTimer)
    _syncTimer = null
  }
}

// ═══════════════════════════════════════════════
// MAIN IPC HANDLER
// ═══════════════════════════════════════════════

export function registerScanHandlers() {
  ipcMain.handle('start-scan', async (event, mode: ScanMode = 'files', options?: { tokenId?: number }) => {
    const startTime = Date.now()
    const win = BrowserWindow.fromWebContents(event.sender)
    const tokenId = options?.tokenId || null
    let results: ScanResult[] = []
    let filesScanned = 0

    try {
      switch (mode) {
        case 'files':     ({ results, filesScanned } = await runFileScan(win)); break
        case 'processes': ({ results, filesScanned } = await runProcessScan(win)); break
        case 'cheats':    ({ results, filesScanned } = await runCheatScan(win)); break
        case 'dma':       ({ results, filesScanned } = await runDmaScan(win)); break
        case 'extended':  ({ results, filesScanned } = await runExtendedScan(win)); break
        case 'network':   ({ results, filesScanned } = await runNetworkScan(win)); break
      }
    } catch (scanErr) {
      console.error('Scan error:', scanErr)
      // Return empty results instead of crashing
      results = results || []
      filesScanned = filesScanned || 0
    }

    // Safety: ensure results is always an array
    if (!Array.isArray(results)) results = []
    filesScanned = filesScanned || 0

    const highRiskCount = results.filter(r => r.risk === 'high').length

    sendProgress(win, { phase: 'done', currentDir: '', filesFound: results.length, filesScanned, totalDirs: 4, dirsDone: 4 })

    // ── Cloud hash submission (fire-and-forget) ──
    try {
      const topFindings = results
        .filter(r => r.type === 'file' && r.size > 0 && r.size < 100 * 1024 * 1024)
        .sort((a, b) => a.risk === 'high' ? -1 : b.risk === 'high' ? 1 : 0)
        .slice(0, 10)

      if (topFindings.length > 0) {
        const hashes: Array<{ sha256: string; file_name: string; file_size: number; risk_score: number }> = []
        for (const f of topFindings) {
          try {
            if (!fs.existsSync(f.path)) continue
            const h = crypto.createHash('sha256')
            const stream = fs.createReadStream(f.path)
            for await (const chunk of stream) h.update(chunk as Buffer)
            hashes.push({
              sha256: h.digest('hex'),
              file_name: f.fileName,
              file_size: f.size,
              risk_score: f.risk === 'high' ? 80 : f.risk === 'medium' ? 50 : 20,
            })
          } catch (_e) { /* skip */ }
        }
        if (hashes.length > 0) {
          const http = require('http')
          const body = JSON.stringify({
            hashes,
            pc_username: os.hostname(),
            token_id: tokenId,
          })
          const req = http.request({
            hostname: API_BASE_HOST,
            port: API_BASE_PORT,
            path: '/api/auth/submit-hashes',
            method: 'POST',
            timeout: 10000,
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
          })
          req.write(body)
          req.end()
        }
      }
    } catch (_e) { /* cloud hash submission optional */ }

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
