/**
 * Predator — Heuristic Analysis Engine
 *
 * The core scoring logic that decides whether a file or process is suspicious.
 * Extracted from the monolithic scanner.ts for testability and clarity.
 */

import crypto from 'crypto'
import fs from 'fs'
import path from 'path'
import { execSync, spawnSync } from 'child_process'

import {
  KNOWN_PROCESSES,
  KNOWN_CHEAT_FILES,
  KNOWN_LUA_SCRIPTS,
  KNOWN_CHEAT_FOLDERS,
  KNOWN_CHEAT_HASHES,
  KNOWN_BINARY_SIGNATURES,
  TARGET_EXTENSIONS,
  MASQUERADING_FILENAMES,
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
  checkAutoRules,
  learnFromFile,
} from './auto-yara'

import {
  analyzeApiHashingStatic,
  analyzeApiHashingInDump,
} from './api-hashing'

import type { HeuristicResult, CheatCategory } from './types'
import type { PeAnalysisResult, SectionEntropy } from './cheat-rules'
import { _PF, _PF86, _HOME, _WR, ctx } from './types'
import { calculateEntropy } from './analysis/entropy'
import { scanStrings } from './analysis/strings'

// ═══════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════

export const SUSPICIOUS_CATEGORIES: Record<string, CheatCategory> = {
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

export const SUSPICIOUS_EXTENSIONS: Record<string, string> = {
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
  '.zip': 'Archive (may contain cheat files)',
  '.rar': 'Archive (may contain cheat files)',
  '.7z': 'Archive (may contain cheat files)',
  '.msi': 'Installer (may contain cheat)',
}

export const SCAN_CONFIG = {
  SCAN_DEPTH: 3,
  MAX_FILE_SIZE: 100 * 1024 * 1024,
  MIN_FILE_SIZE: 0, // Scan ALL files — small configs/loaders can be < 1KB
  SUSPICIOUS_AGE_DAYS: 90,
  ENTROPY_THRESHOLD: 7.5,
}

export const ALL_CHEAT_KEYWORDS = [
  ...KNOWN_PROCESSES.map(n => n.replace(/\.exe$/i, '').replace(/_\*\.exe$/i, '').replace(/\*\.exe$/i, '')),
  ...KNOWN_CHEAT_FILES.map(n => n.replace(/\.(dll|exe|asi)$/i, '')),
  ...KNOWN_LUA_SCRIPTS.map(n => n.replace(/\.lua$/i, '')),
  ...KNOWN_CHEAT_FOLDERS,
  'cheat', 'hack', 'inject', 'bypass', 'mod menu', 'trainer',
  'aimbot', 'wallhack', 'esp', 'triggerbot', 'norecoil', 'nospread',
  'godmode', 'teleport', 'moneydrop', 'recovery', 'unlockall',
  'nightfall', 'dma', 'fpga', 'pcileech', 'fuser', 'screamer',
  'kmem', 'memprocfs', 'winpmem',
  // New from research
  'manual map', 'manualmap', 'reflective loader', 'reflective dll',
  'kernel injector', 'kernel driver', 'kdmapper', 'drvmap',
  'byovd', 'vulnerable driver', 'physmem',
  'screenshot bypass', 'screenshare bypass', 'pc check bypass',
  'ragemp', 'altv', 'fivem', 'gta5',
  'executor', 'injector', 'loader', 'spoofer',
  'resource injector', 'server executor', 'client hook',
  'cef hook', 'cef injector', 'cef devtools',
  'devtools', 'remote debugging', 'chromium embedded',
  'js executor', 'dotnet inject', 'compiled resource',
  'dump', 'dumper', 'decompiler', 'deobfuscator',
  // DMA hardware specifics from research
  'pcileech', 'leechcore', 'vmm', 'memprocfs',
  'ftd3xx', 'ft601', 'ft2232', 'ftdibus',
  'xc7a35t', 'xc7a75t', 'xc7a100t', 'artix-7',
  'xilinx fpga', 'altera fpga', 'pcie leech',
  'dma card', 'dma firmware', 'fpga firmware',
  'captaindma', 'leetch', 'enigma x1', 'screamer m2',
  'raptor dma', 'zdma', 'gbox',
  // 0xCheats / LeetCheats / Unicore / Vanish / Nightfall (research confirmed)
  '0xcheats', '0xcheat', 'oxcheat', 'oxcheats',
  'leetcheats', 'leetcheat', 'noleet', 'noleetcheats',
  '1337 cheat', '1337cheat',
  'unicore', 'unicorecheat', 'unicoremenu',
  'vanish', 'vanishcheat', 'vanish spoofer',
  'nightfall', 'nightfallmenu', 'nightfall loader',
  'kernel cheat', 'vanish driver', // Vanish uses kernel driver injection
  // CEF/Chromium exploit patterns
  'cef_browser', 'chromium embedded framework',
  'remote debugging port', 'devtools protocol',
  'natives handler', 'native invoker',
  'get_native_handler', 'crossmap',
  // ALT:V specific
  'alt-client', 'alt_server', 'bytecode module',
  'js bytecode', 'resource cache', 'client_packages',
  // HWID spoofing
  'hwid spoofer', 'volumeid', 'mac spoof',
  'disk serial', 'smbios', 'motherboard serial',
  'permanent spoof', 'perm spoof',
  // RAM disk evasion
  'ram disk', 'memory disk', 'imdisk',
  'tmpfs', 'ramdrive', 'virtual drive',
  // ADS (Alternate Data Streams)
  'alternate data stream', ':zone.identifier',
]

export const SUSPICIOUS_PATTERNS = [
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
  // New from research
  /[Ss]usano/i,
  /[Ll]ambda\s*[Mm]enu/i,
  /[Vv][Mm]enu/i,
  /[Mm]anual\s*[Mm]ap/i,
  /[Rr]eflective\s*([Dd]ll|[Ll]oader)/i,
  /[Kk][Dd][Mm]apper/i,
  /[Dd][Rr][Vv][Mm]ap/i,
  /[Bb][Yy][Oo][Vv][Dd]/i,
  /[Cc][Ee][Ff]\s*([Hh]ook|[Ii]nject|[Dd]ev[tT]ools)/i,
  /[Rr](esource|AGE)\s*[Ii]nject/i,
  /[Ss]erver\s*[Ee]xec/i,
  /[Ee]xecutor/i,
  /[Ss]creenshot\s*[Bb]ypass/i,
  /[Ss]creenshare\s*[Bb]ypass/i,
  /[Pp][Cc]\s*[Cc]heck\s*[Bb]ypass/i,
  /[Ss]poof(?:er|ing)/i,
  /[Cc]lean(?:er|ing)\s*(?:trace|log)/i,
  /[Hh][Ww][Ii][Dd]\s*[Ss]poof/i,
  // DMA hardware specifics
  /[Xx][Cc]7[Aa]\d{1,3}[Tt]/i,
  /[Aa]rtix-?\s*7/i,
  /[Ff][Tt]60[01]/i,
  /[Ff][Tt]2232/i,
  /[Ll]eech[Dd][Mm][Aa]/i,
  /[Cc]aptain[Dd][Mm][Aa]/i,
  /[Ee]nigma\s*[Xx]1/i,
  /[Ss]creamer\s*[Mm]2/i,
  /[Rr]aptor\s*[Dd][Mm][Aa]/i,
  // CEF / Chromium exploit patterns
  /remote-?\s*debugging-?\s*port/i,
  /chrome\.devtools/i,
  /native\s*invoker/i,
  /get_native_handler/i,
  // RAM disk / memory evasion
  /[Rr][Aa][Mm]\s*[Dd](isk|rive)/i,
  /[Ii][Mm][Dd]isk/i,
  /[Tt][Mm][Pp][Ff][Ss]/i,
  // Alternate Data Streams (NTFS ADS)
  /:zone\.identifier/i,
  /alternate\s*data\s*stream/i,
  // Permanent HWID spoofers
  /[Pp]erm(?:anent)?\s*[Ss]poof/i,
  /[Ee][Ff][Ii]\s*[Ss]poof/i,
  /[Ss][Mm][Bb][Ii][Oo][Ss]\s*[Ss]poof/i,
  // 0xCheats / LeetCheats / Unicore / Vanish / Nightfall
  /0x[Cc]heats?/i,
  /[Oo]x[Cc]heat/i,
  /[Ll]eet[Cc]heats?/i,
  /[Nn]oleet[Cc]heats?/i,
  /1337\s*[Cc]heat/i,
  /[Uu]nicore/i,
  /[Vv]anish\s*([Cc]heat|[Mm]enu|[Ss]poof)/i,
  /[Nn]ightfall\s*([Cc]heat|[Mm]enu|[Ll]oader)/i,
  /[Kk]ernel\s*[Cc]heat/i,
]

// Protected paths — game mod directories where files should not be
export const PROTECTED_PATHS = [
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'mods'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'plugins'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'cache'),
  path.join(_HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'data'),
  path.join(_HOME, 'AppData', 'Roaming', 'CitizenFX'),
  path.join(_PF, 'RAGEMP'),
  path.join(_PF86, 'RAGEMP'),
  path.join(_HOME, 'RAGEMP'),
  path.join(_HOME, 'AppData', 'Local', 'altv', 'modules'),
  path.join(_HOME, 'AppData', 'Local', 'altv', 'resources'),
  path.join(_PF, 'Rockstar Games', 'Grand Theft Auto V'),
  path.join(_PF86, 'Rockstar Games', 'Grand Theft Auto V'),
  path.join(_PF, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
  path.join(_PF86, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
]

/** System process names that cheat loaders commonly masquerade as */
export const SYSTEM_PROC_NAMES = new Set([
  'svchost.exe', 'csrss.exe', 'lsass.exe', 'services.exe', 'smss.exe',
  'winlogon.exe', 'explorer.exe', 'spoolsv.exe', 'conhost.exe',
  'rundll32.exe', 'taskhostw.exe', 'sihost.exe', 'ctfmon.exe',
  'dwm.exe', 'fontdrvhost.exe', 'RuntimeBroker.exe',
  'SearchIndexer.exe', 'SecurityHealthSystray.exe',
  'LogonUI.exe', 'SystemSettings.exe', 'LockApp.exe',
  'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
  'applicationframehost.exe', 'SearchApp.exe',
])

// ═══════════════════════════════════════════════════
// CACHES — managed by ctx (ScanContext in types.ts)

// Pre-normalized arrays for fast substring matching
const _PROC_BASES = KNOWN_PROCESSES.map(n =>
  n.toLowerCase()
    .replace(/\.exe$/i, '')
    .replace(/_\*\.exe$/i, '')
    .replace(/\*\.exe$/i, '')
)
const _FILE_NAMES = KNOWN_CHEAT_FILES.map(n => n.toLowerCase())
const _LUA_NAMES = KNOWN_LUA_SCRIPTS.map(n => n.toLowerCase())
const _FOLDER_NAMES = KNOWN_CHEAT_FOLDERS.map(n => n.toLowerCase())

// ═══════════════════════════════════════════════════
// PURE FUNCTIONS (re-exported from analysis/)
// ═══════════════════════════════════════════════════

export { calculateEntropy } from './analysis/entropy'
export { scanStrings } from './analysis/strings'

// ═══════════════════════════════════════════════════
// MASQUERADING EXECUTABLE HEURISTIC
// ═══════════════════════════════════════════════════

/**
 * Check if a file is a masquerading executable — a cheat loader disguised
 * as a legitimate utility (e.g., dxwebsetup.exe, epicgameslauncher.exe).
 *
 * Detection logic:
 *   1. Filename is in MASQUERADING_FILENAMES (known masquerading targets)
 *   2. File is NOT in a trusted Windows/system path
 *   3. File has NO digital signature (legitimate versions always have one)
 *   4. Optional: file is packed (high entropy, many sections, no PE metadata)
 *
 * Returns: { isMasquerading, signals } where signals explains why.
 */
export function checkMasqueradingExecutable(
  fileName: string,
  filepath: string,
  stat: fs.Stats,
  peInfo: PeAnalysisResult | null,
  secEntropy: SectionEntropy[],
  entropy: number,
  sigValid: boolean,
): { isMasquerading: boolean; signals: string[] } {
  const signals: string[] = []
  const lowerName = fileName.toLowerCase()

  // Step 1: Check if filename is a known masquerading target
  if (!MASQUERADING_FILENAMES.has(lowerName)) {
    return { isMasquerading: false, signals }
  }

  signals.push(`Filename matches masquerading target: ${fileName}`)

  // Step 2: Check location — system32/syswow64 is fine (legit Windows files live there)
  const systemPaths = [
    path.join(_WR, 'System32').toLowerCase(),
    path.join(_WR, 'SysWOW64').toLowerCase(),
    path.join(_WR).toLowerCase(),
  ]
  const fpLower = filepath.toLowerCase()
  const inSystemDir = systemPaths.some(p => fpLower.startsWith(p))

  if (inSystemDir) {
    // If it's in System32 with a legitimate Windows filename, it's likely legit
    const winSysFiles = new Set(['conhost.exe', 'rundll32.exe', 'svchost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'explorer.exe', 'notepad.exe'])
    if (winSysFiles.has(lowerName)) {
      signals.push(`Located in System32 — legitimate Windows component, not flagged`)
      return { isMasquerading: false, signals }
    }
  }

  // Step 3: Digital signature check (most important signal)
  if (sigValid) {
    signals.push(`Has valid digital signature — likely legitimate version`)
    // Still suspicious if packed even with valid sig — reduce severity
    if (entropy > 7.0 || (peInfo && peInfo.sectionCount >= 7)) {
      signals.push('But file is packed/obfuscated despite valid signature — suspicious')
    } else {
      return { isMasquerading: false, signals }
    }
  } else {
    signals.push('No digital signature — legitimate versions of this software ALWAYS have one')
  }

  // Step 4: PE structure anomalies
  if (peInfo) {
    if (peInfo.sectionCount >= 7) {
      signals.push(`Suspicious: ${peInfo.sectionCount} PE sections (expected 3-5 for legitimate tool)`)
    }
    if (peInfo.relocsStripped) {
      signals.push('PE relocations stripped — suggests packing/obfuscation')
    }
    if (peInfo.entryPointInSuspiciousSection) {
      signals.push('Entry point in unusual section — packed executable')
    }
  }

  // Step 5: Section entropy anomalies
  if (secEntropy.length > 0) {
    const highEntropySections = secEntropy.filter(s => s.entropy > 7.5)
    for (const sec of highEntropySections) {
      signals.push(`Section [${sec.name}] entropy ${sec.entropy.toFixed(2)} > 7.5 — packed`)
    }
  }

  // Step 6: File entropy (overall sample)
  if (entropy > 7.2) {
    signals.push(`Overall entropy ${entropy.toFixed(2)} > 7.2 — packed/encrypted`)
  }

  // Step 7: Size check — known masquerading cheat loaders are typically 16-30 MB
  if (stat.size >= 15 * 1024 * 1024 && stat.size <= 35 * 1024 * 1024) {
    signals.push(`File size ${(stat.size / 1024 / 1024).toFixed(1)} MB — matches masquerading loader range`)
  }

  return { isMasquerading: signals.length >= 2, signals }
}

/** Cached digital signature check via PowerShell Get-AuthenticodeSignature */
export function checkDigitalSignature(filepath: string): boolean {
  const cached = ctx.sigCache.get(filepath)
  if (cached !== undefined) return cached
  try {
    const out = execSync(
      `powershell -Command "(Get-AuthenticodeSignature '${filepath.replace(/'/g, "''")}').Status"`,
      { encoding: 'utf-8', timeout: 2000 },
    )
    const valid = out.includes('Valid')
    ctx.sigCache.set(filepath, valid)
    return valid
  } catch (_e) {
    ctx.sigCache.set(filepath, false)
    return false
  }
}

/**
 * Match a name against the known cheat database.
 * Uses cached lookups for performance.
 */
export function matchKnownCheat(name: string): string[] {
  const lower = name.toLowerCase()
  const cached = ctx.cheatNameCache.get(lower)
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
  ctx.cheatNameCache.set(lower, matches)
  return matches
}

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
     'triggerbot', 'dma', 'fpga', 'pcileech', 'fuser'].includes(k)
  )

  if ((highRiskExts.includes(ext) && hasHighKeyword) || matches.length >= 3) return 'high'
  if (highRiskExts.includes(ext) || mediumRiskExts.includes(ext) || matches.length >= 2) return 'medium'
  return 'low'
}

// ═══════════════════════════════════════════════════
// COMBO DETECTOR — Universal unsigned binary heuristic
// ═══════════════════════════════════════════════════

/**
 * Universal combo-detector for unsigned .exe/.dll files.
 *
 * Catches cheat loaders REGARDLESS of filename — no name matching needed.
 * Uses 5 behavioral signals:
 *   1. Strange size (5–100 MB) — too big for a utility, too small for a game
 *   2. High entropy (> 7.0) — packed/encrypted (VMProtect, Themida)
 *   3. Few readable strings (< 10) — fully obfuscated binary
 *   4. Suspicious directory — Downloads/Desktop/Temp
 *   5. Many PE sections (>= 7) — typical for packed binaries
 *
 * Scoring:
 *   >= 2 signals → HIGH risk (+70)
 *   >= 1 signal + suspicious dir → MEDIUM risk (+40)
 *   1 signal → LOW risk (+15)
 *
 * Legitimate software is NEVER all of: unsigned + packed + no strings + wrong size.
 */
export function comboScoreUnsignedBinary(
  ext: string,
  sizeBytes: number,
  entropy: number,
  stringCount: number,
  filepath: string,
  sectionCount: number,
  sigValid: boolean,
): { signals: string[]; riskBonus: number } {
  // Only applies to PE files
  if (ext !== '.exe' && ext !== '.dll') {
    return { signals: [], riskBonus: 0 }
  }

  // Signed = trust (legitimate vendors sign their software)
  if (sigValid) {
    return { signals: [], riskBonus: 0 }
  }

  let signalCount = 0
  const reasons: string[] = []

  const fpLow = filepath.toLowerCase()
  const inSuspiciousDir = fpLow.includes('downloads') || fpLow.includes('download') ||
    fpLow.includes('desktop') || fpLow.includes('temp') || fpLow.includes('загрузки')

  // Signal 1: Strange size (5–100 MB)
  // Legitimate: small utils < 5MB, big games > 100MB. Cheat loaders: 5–100MB.
  if (sizeBytes >= 5 * 1024 * 1024 && sizeBytes <= 100 * 1024 * 1024) {
    signalCount++
    reasons.push(`Strange size: ${(sizeBytes / 1024 / 1024).toFixed(1)} MB (unsigned binary of this size is unusual)`)
  }

  // Signal 2: High entropy (> 7.0) — packed/encrypted
  if (entropy > 7.0) {
    signalCount++
    reasons.push(`Entropy ${entropy.toFixed(2)} > 7.0 — packed/encrypted (VMProtect/Themida/obsufcation)`)
  }

  // Signal 3: Few readable strings (< 10) — fully obfuscated
  // Legitimate EXEs always have readable strings (error messages, resource names, etc.)
  if (stringCount < 10) {
    signalCount++
    reasons.push(`Only ${stringCount} readable strings — fully obfuscated binary`)
  }

  // Signal 4: Suspicious directory
  if (inSuspiciousDir) {
    signalCount++
    reasons.push('Located in user directory (Downloads/Desktop/Temp)')
  }

  // Signal 5: Many PE sections (>= 7) — packing signature
  if (sectionCount >= 7) {
    signalCount++
    reasons.push(`${sectionCount} PE sections — typical for packed/VMProtected binaries (normal: 3–5)`)
  }

  // ── Scoring ──

  // Count "strong" signals (entropy, strings, sections) — requiring at least one
  // prevents false positives on legitimate unsigned utilities (e.g. open-source tools)
  const strongSignals = [entropy > 7.0, stringCount < 10, sectionCount >= 7].filter(Boolean).length

  if (signalCount >= 2 && strongSignals >= 1) {
    return { signals: reasons, riskBonus: 70 }
  }

  if (signalCount === 1 && inSuspiciousDir) {
    return { signals: reasons, riskBonus: 40 }
  }

  if (signalCount === 1) {
    return { signals: reasons, riskBonus: 15 }
  }

  return { signals: [], riskBonus: 0 }
}

/** Check if a file matches any known hash (SHA256) in the database. Streams the file. */
export async function checkFileHash(filePath: string): Promise<{ matched: boolean; hash: string }> {
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
// HEURISTIC FILE SCAN (core business logic)
// ═══════════════════════════════════════════════════

/**
 * Heuristic file analysis — entropy, signatures, name, age, protected paths.
 * This is the primary function that decides whether a file is suspicious.
 */
export function heuristicFileScan(filepath: string): HeuristicResult | null {
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

    // Masquerading as system file
    const system32Path = path.join(_WR, 'System32').toLowerCase()
    const syswow64Path = path.join(_WR, 'SysWOW64').toLowerCase()
    const filepathLower = filepath.toLowerCase()
    if (SYSTEM_PROC_NAMES.has(fileName)) {
      const isInSystemDir = filepathLower.startsWith(system32Path) || filepathLower.startsWith(syswow64Path)
      if (!isInSystemDir && !isTrustedPath(filepath)) {
        suspicions.push(`🎭 Masquerading as system process: ${fileName} (expected in System32, found in unexpected location)`)
        riskScore += 50
      }
    }

    // 3. Age check
    if (ageDays < SCAN_CONFIG.SUSPICIOUS_AGE_DAYS) {
      suspicions.push(`Recently created (${Math.round(ageDays)} days ago)`)
      riskScore += 15
    }

    // ── FAST PATH: skip expensive binary analysis for trusted system paths ──
    // Files in C:\Windows, C:\Program Files are signed by Microsoft/vendors.
    // If there are NO name/extension signals, they're safe — no need for
    // entropy/strings/PE analysis which costs 500ms+ per file.
    if (isTrustedPath(filepath) && riskScore === 0) {
      return null
    }

    // Whitelist check — reduce score for remaining trusted-path files with signals
    if (isTrustedPath(filepath)) {
      riskScore = Math.max(riskScore - 30, 0)
    }

    // 4. Binary analysis
    const binaryExts = new Set(['.exe', '.dll', '.asi', '.sys', '.drv'])
    const textExts = new Set(['.js', '.lua', '.cs', '.bat', '.ps1', '.vbs', '.ahk', '.cfg', '.ini', '.json', '.xml'])

    // Content scan for text-based files (JS loaders, Lua, scripts, configs)
    if (textExts.has(ext) && stat.size < 512 * 1024) {
      try {
        const content = fs.readFileSync(filepath, 'utf-8').toLowerCase()
        let contentMatches = 0
        for (const keyword of ALL_CHEAT_KEYWORDS) {
          if (content.includes(keyword.toLowerCase())) {
            suspicions.push(`content:${keyword}`)
            contentMatches++
            riskScore += 25
            if (contentMatches >= 5) break // cap at 5 keyword matches
          }
        }
        // Check for suspicious patterns in content
        for (const pattern of SUSPICIOUS_PATTERNS) {
          if (pattern.test(content)) {
            suspicions.push(`content-pattern:${pattern.source}`)
            riskScore += 20
          }
        }
      } catch (_e) { /* binary or unreadable */ }
    }

    // Archive content scan (.zip/.rar/.7z)
    if (ARCHIVE_EXTS.has(ext) && stat.size < 100 * 1024 * 1024) {
      try {
        const archiveMatches = scanArchiveContents(filepath)
        for (const m of archiveMatches) {
          suspicions.push(m)
          riskScore += 30
        }
      } catch (_e) { /* archive scan optional */ }
    }

    if (binaryExts.has(ext) && stat.size >= 4096 && stat.size < 50 * 1024 * 1024) {
      const fd = fs.openSync(filepath, 'r')
      const sampleSize = Math.min(65536, stat.size)
      const sample = Buffer.alloc(sampleSize)
      fs.readSync(fd, sample, 0, sampleSize, 0)
      fs.closeSync(fd)

      const entropy = calculateEntropy(sample)
      if (entropy > SCAN_CONFIG.ENTROPY_THRESHOLD) {
        suspicions.push(`High entropy (${entropy.toFixed(2)}) — possibly packed/encrypted`)
        riskScore += 30
      }

      const strings = scanStrings(filepath)
      const stringsLower = strings.map(s => s.toLowerCase())

      const yaraMatches = evaluateYara(sample, stringsLower)
      for (const yMatch of yaraMatches) {
        suspicions.push(`YARA [${yMatch.ruleName}]: ${yMatch.description}`)
        riskScore += yMatch.risk === 'CRITICAL' ? 60 : yMatch.risk === 'HIGH' ? 40 : 20
      }

      const peCacheKey = `${filepath}|${stat.mtimeMs}`
      let peInfo: PeAnalysisResult | null = null
      let secEntropy: SectionEntropy[] = []

      const cachedPe = ctx.peHeaderCache.get(peCacheKey)
      if (cachedPe) {
        peInfo = cachedPe.peInfo
        secEntropy = cachedPe.secEntropy
      } else {
        peInfo = (ext === '.exe' || ext === '.dll' || ext === '.sys') ? analyzePeHeaders(filepath) : null
        try {
          secEntropy = analyzeSectionEntropy(filepath)
        } catch (_e) { /* skip */ }
        ctx.peHeaderCache.set(peCacheKey, { peInfo, secEntropy, mtime: stat.mtimeMs, filepath })
        if (ctx.peHeaderCache.size > ctx.PE_CACHE_MAX) {
          const firstKey = ctx.peHeaderCache.keys().next().value
          if (firstKey) ctx.peHeaderCache.delete(firstKey)
        }
      }

      const sigValid = (ext === '.exe' || ext === '.dll' || ext === '.sys') ? checkDigitalSignature(filepath) : false

      // ── UNIVERSAL COMBO DETECTOR ──
      // Catches ANY unsigned .exe/.dll with 2+ suspicious signals, regardless of filename.
      // Replaces the old catch-all that only worked in Downloads + known names.
      const comboResult = comboScoreUnsignedBinary(
        ext,
        stat.size,
        entropy,
        strings.length,
        filepath,
        peInfo?.sectionCount ?? 0,
        sigValid,
      )
      if (comboResult.riskBonus > 0) {
        for (const signal of comboResult.signals) {
          suspicions.push(`🧬 COMBO: ${signal}`)
        }
        const signalCount = comboResult.signals.length
        suspicions.push(`🧬 Combo-detector: ${signalCount} signals matched → +${comboResult.riskBonus} risk (ANY unsigned binary with these traits is suspicious)`)
        riskScore += comboResult.riskBonus
      }

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

        if (secEntropy.length > 0) {
          const suspiciousSections = secEntropy.filter(s => s.isSuspicious)
          for (const sec of suspiciousSections) {
            suspicions.push(`📊 Section [${sec.name}]: ${sec.reason}`)
            riskScore += 30
          }
          const rsrcHigh = secEntropy.find(s => s.name === '.rsrc' && s.entropy > 7.5)
          if (rsrcHigh) {
            suspicions.push(`🚩 .rsrc entropy ${rsrcHigh.entropy.toFixed(2)} > 7.5 — shellcode/config likely hidden in resources`)
            riskScore += 40
          }
        }

        const apiHashRes = analyzeApiHashingStatic(filepath)
        if (apiHashRes && apiHashRes.detected) {
          suspicions.push(`🔐 API Hashing detected (confidence: ${apiHashRes.confidence}%)`)
          for (const p of apiHashRes.patterns.slice(0, 3)) {
            suspicions.push(`  → ${p}`)
          }
          riskScore += Math.min(apiHashRes.confidence * 0.5, 45)
        }

        // Masquerading executable check
        const masqResult = checkMasqueradingExecutable(fileName, filepath, stat, peInfo, secEntropy, entropy, sigValid)
        if (masqResult.isMasquerading) {
          for (const signal of masqResult.signals) {
            suspicions.push(`🎭 ${signal}`)
            riskScore += 25
          }
        }

        // Fuzzy loader match — only if combo-detector didn't already flag it
        // (combo-detector checks the same signals; avoid double-counting)
        if (comboResult.riskBonus === 0) {
        const FUZZY_SIZE_LOWER_MB = 16
        const FUZZY_SIZE_UPPER_MB = 28
        const FUZZY_ENTROPY_THRESHOLD = 7.2
        const FUZZY_SECTION_MIN = 7

        if (ext === '.exe' || ext === '.dll') {
          let fuzzyScore = 0
          const fuzzySignals: string[] = []

          if (stat.size >= FUZZY_SIZE_LOWER_MB * 1024 * 1024 && stat.size <= FUZZY_SIZE_UPPER_MB * 1024 * 1024) {
            fuzzyScore += 25
            fuzzySignals.push(`Size ${(stat.size / 1024 / 1024).toFixed(1)} MB (loader range ${FUZZY_SIZE_LOWER_MB}–${FUZZY_SIZE_UPPER_MB} MB)`)
          }
          if (entropy > FUZZY_ENTROPY_THRESHOLD) {
            fuzzyScore += 20
            fuzzySignals.push(`Entropy ${entropy.toFixed(2)} > ${FUZZY_ENTROPY_THRESHOLD} (packed/obfuscated)`)
          }
          if (peInfo && peInfo.sectionCount >= FUZZY_SECTION_MIN) {
            fuzzyScore += 25
            fuzzySignals.push(`${peInfo.sectionCount} PE sections ≥ ${FUZZY_SECTION_MIN} (packing)`)
          }
          if (peInfo && peInfo.subsystem !== '' && peInfo.subsystem !== 'WINDOWS_GUI' && peInfo.subsystem !== 'WINDOWS_CUI' && peInfo.subsystem !== 'NATIVE') {
            fuzzyScore += 15
            fuzzySignals.push(`PE subsystem: ${peInfo.subsystem} (unusual for EXE)`)
          }
          if (!sigValid) {
            fuzzyScore += 15
            fuzzySignals.push('Unsigned executable (no digital signature)')
          }

          if (fuzzyScore >= 50) {
            suspicions.push(`🧬 Fuzzy loader match (score ${fuzzyScore}/100): ${fuzzySignals.join('; ')}`)
            riskScore += Math.min(fuzzyScore, 60)
          }
        }
        } // end fuzzy loader match gate
      }

      // Category signature analysis
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

      // Hash check against known cheat database (only if already suspicious)
      // Streaming SHA256 of entire file is expensive — skip for clean files
      if (KNOWN_CHEAT_HASHES.length > 0 && riskScore > 30) {
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

      if (sigValid) {
        riskScore -= 10
      } else {
        suspicions.push('No digital signature')
        riskScore += 20
      }
    }

    // 5. Protected path check
    for (const protectedPath of PROTECTED_PATHS) {
      if (filepath.toLowerCase().includes(protectedPath.toLowerCase())) {
        suspicions.push(`File in protected folder: ${protectedPath}`)
        riskScore += 25
        break
      }
    }

    // Auto-YARA check
    if (binaryExts.has(ext) && stat.size < 50 * 1024 * 1024) {
      try {
        const auto = checkAutoRules(filepath)
        if (auto.matched) {
          suspicions.push(`AutoYara [${auto.rules.length} правил]: score ${auto.score.toFixed(0)}`)
          riskScore += auto.score * 0.6
        }
      } catch (_e) { /* skip */ }
    }

    // Auto-YARA: learn from high-risk files
    if (riskScore > 70 && binaryExts.has(ext)) {
      try {
        learnFromFile(filepath, riskScore)
      } catch (_e) { /* skip */ }
    }

    // Dev-mode logging: trace why a file was or wasn't flagged
    if (process.env.NODE_ENV === 'development' && (riskScore > 0 || (ext === '.exe' && stat.size > 1024 * 1024))) {
      const label = riskScore > 0 ? `FLAGGED (score=${riskScore})` : 'SKIPPED (score=0)'
      console.log(`[Heuristic] ${label}: ${fileName} (${(stat.size / 1024 / 1024).toFixed(1)}MB, ${ext}) — ${suspicions.slice(0, 3).join(' | ') || 'no signals'}`)
    }

    if (riskScore === 0) return null

    return { riskScore, suspicions }
  } catch (_e) {
    return null
  }
}

// ═══════════════════════════════════════════════════
// ARCHIVE CONTENT SCANNING
// ═══════════════════════════════════════════════════

const ARCHIVE_EXTS = new Set(['.zip', '.rar', '.7z'])

/** Peek into archives and check filenames against cheat patterns. Returns suspicions if found. */
export function scanArchiveContents(filepath: string): string[] {
  const matches: string[] = []
  const ext = path.extname(filepath).toLowerCase()
  if (!ARCHIVE_EXTS.has(ext)) return matches

  try {
    let output = ''
    if (ext === '.zip') {
      // PowerShell Expand-Archive -WhatIf for .zip listing
      const shell = spawnSync('powershell', [
        '-NoProfile', '-Command',
        `[System.IO.Compression.ZipFile]::OpenRead('${filepath.replace(/'/g, "''")}').Entries | Select-Object -ExpandProperty FullName`,
      ], { encoding: 'utf-8', timeout: 10000 })
      output = shell.stdout || ''
    } else {
      // .rar and .7z — try 7zip if installed
      const sevenZip = spawnSync('7z', ['l', '-slt', filepath], { encoding: 'utf-8', timeout: 10000 })
      output = sevenZip.stdout || ''
    }

    if (!output) return matches

    const lower = output.toLowerCase()
    // Check filenames inside archive
    const lines = lower.split(/[\r\n]+/)
    for (const line of lines) {
      const fileName = path.basename(line.trim())
      if (!fileName || fileName.length < 3) continue
      // Check against known cheat names
      for (const base of _PROC_BASES) {
        if (fileName.includes(base)) {
          matches.push(`archive:${fileName} → ${base}`)
          break
        }
      }
      for (const file of _FILE_NAMES) {
        if (fileName.includes(file)) {
          matches.push(`archive:${fileName} → ${file}`)
          break
        }
      }
      // Check against ALL_CHEAT_KEYWORDS
      for (const kw of ALL_CHEAT_KEYWORDS) {
        if (kw.length >= 4 && fileName.includes(kw.toLowerCase())) {
          matches.push(`archive-kw:${fileName} → ${kw}`)
          break
        }
      }
      // Check SUSPICIOUS_PATTERNS
      for (const pat of SUSPICIOUS_PATTERNS) {
        if (pat.test(fileName)) {
          matches.push(`archive-pat:${pat.source}`)
          break
        }
      }
      if (matches.length >= 5) break // cap
    }
  } catch (_e) { /* archive scanning optional */ }
  return matches
}
