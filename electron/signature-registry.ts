/**
 * Predator — Signature Registry
 *
 * SINGLE SOURCE OF TRUTH for ALL cheat detection signatures.
 *
 * Structure:
 *   - Categories (injector, debugger, hook, driver, etc.) — what to detect
 *   - Keywords (ALL_CHEAT_KEYWORDS) — strings matched against file/proc names and content
 *   - Patterns (SUSPICIOUS_PATTERNS) — regexes matched against file/proc names and content
 *
 * Query API:
 *   matchKeywords(text) → string[]     — which keywords are present in text
 *   matchPatterns(text) → string[]     — which regex patterns match text
 *   getCategory(name) → CheatCategory  — lookup category by name
 *
 * Separation of concerns:
 *   THIS FILE: pure data — what to detect
 *   heuristic.ts: pure logic — how to score matches
 */

import type { CheatCategory } from './types'
import {
  KNOWN_PROCESSES,
  KNOWN_CHEAT_FILES,
  KNOWN_LUA_SCRIPTS,
  KNOWN_CHEAT_FOLDERS,
} from './cheats-db'

// ═══════════════════════════════════════════════════
// 1. SUSPICIOUS CATEGORIES
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
    names: ['debug', 'debugger', 'cheatengine', 'x64dbg', 'ollydbg'],
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
    names: ['driver', 'kernel', 'km'],
    strings: [Buffer.from('\\\\Device\\\\'), Buffer.from('\\\\DosDevices\\\\'), Buffer.from('IoCreateDevice'), Buffer.from('PsSetCreateProcessNotifyRoutine')],
    description: 'Kernel-level driver',
    risk: 'CRITICAL',
  },
  spoofer: {
    names: ['spoofer', 'spoof', 'hwid', 'serial', 'diskid'],
    strings: [Buffer.from('HardwareID'), Buffer.from('MACAddress'), Buffer.from('DiskSerial'), Buffer.from('SMBIOS')],
    description: 'Hardware ID spoofing',
    risk: 'HIGH',
  },
  bypass: {
    names: ['bypass', 'evade', 'block', 'disable'],
    strings: [Buffer.from('bypass'), Buffer.from('evade'), Buffer.from('anti-cheat'), Buffer.from('anti cheat')],
    description: 'Security mechanism bypass',
    risk: 'CRITICAL',
  },
  menu: {
    names: ['menu', 'overlay', 'imgui', 'd3d'],
    strings: [Buffer.from('ImGui'), Buffer.from('Direct3D'), Buffer.from('OpenGL'), Buffer.from('overlay'), Buffer.from('aimbot')],
    description: 'Game menu / overlay',
    risk: 'HIGH',
  },
  network: {
    names: ['proxy', 'socks', 'mitm', 'packet'],
    strings: [Buffer.from('WSASocket'), Buffer.from('connect'), Buffer.from('send'), Buffer.from('recv'), Buffer.from('socks'), Buffer.from('proxy')],
    description: 'Network manipulation tools',
    risk: 'MEDIUM',
  },
  obfuscator: {
    names: ['obfusc', 'packer', 'crypt', 'protect', 'vmprotect'],
    strings: [Buffer.from('VMProtect'), Buffer.from('Themida'), Buffer.from('Enigma'), Buffer.from('Obsidium'), Buffer.from('Armadillo')],
    description: 'Code obfuscation / packing (hides malicious code)',
    risk: 'HIGH',
  },
}

// ═══════════════════════════════════════════════════
// 2. ALL CHEAT KEYWORDS — flat list for name/content matching
// ═══════════════════════════════════════════════════
//
// Generated from cheats-db arrays plus hardcoded terms.
// Used by: heuristic content scan, browser history scan, network scan, registry scan

export const ALL_CHEAT_KEYWORDS: string[] = [
  ...KNOWN_PROCESSES.map(n => n.replace(/\.exe$/i, '').replace(/_\*\.exe$/i, '').replace(/\*\.exe$/i, '')),
  ...KNOWN_CHEAT_FILES.map(n => n.replace(/\.(dll|exe|asi)$/i, '')),
  ...KNOWN_LUA_SCRIPTS.map(n => n.replace(/\.lua$/i, '')),
  ...KNOWN_CHEAT_FOLDERS,
  'cheat', 'hack', 'inject', 'bypass', 'mod menu', 'trainer',
  'aimbot', 'wallhack', 'esp', 'triggerbot', 'norecoil', 'nospread',
  'godmode', 'teleport', 'moneydrop', 'recovery', 'unlockall',
  'nightfall', 'dma', 'fpga', 'pcileech', 'fuser', 'screamer',
  'kmem', 'memprocfs', 'winpmem',
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
  'pcileech', 'leechcore', 'vmm', 'memprocfs',
  'ftd3xx', 'ft601', 'ft2232', 'ftdibus',
  'xc7a35t', 'xc7a75t', 'xc7a100t', 'artix-7',
  'xilinx fpga', 'altera fpga', 'pcie leech',
  'dma card', 'dma firmware', 'fpga firmware',
  'captaindma', 'leetch', 'enigma x1', 'screamer m2',
  'raptor dma', 'zdma', 'gbox',
  '0xcheats', '0xcheat', 'oxcheat', 'oxcheats',
  'leetcheats', 'leetcheat', 'noleet', 'noleetcheats',
  '1337 cheat', '1337cheat',
  'unicore', 'unicorecheat', 'unicoremenu',
  'vanish', 'vanishcheat', 'vanish spoofer',
  'nightfall', 'nightfallmenu', 'nightfall loader',
  'kernel cheat', 'vanish driver',
  'cef_browser', 'chromium embedded framework',
  'remote debugging port', 'devtools protocol',
  'natives handler', 'native invoker',
  'get_native_handler', 'crossmap',
  'alt-client', 'alt_server', 'bytecode module',
  'js bytecode', 'resource cache', 'client_packages',
  'hwid spoofer', 'volumeid', 'mac spoof',
  'disk serial', 'smbios', 'motherboard serial',
  'permanent spoof', 'perm spoof',
  'ram disk', 'memory disk', 'imdisk',
  'tmpfs', 'ramdrive', 'virtual drive',
  'alternate data stream', ':zone.identifier',
]

// ═══════════════════════════════════════════════════
// 3. SUSPICIOUS PATTERNS — regexes for name/content matching
// ═══════════════════════════════════════════════════

export const SUSPICIOUS_PATTERNS: RegExp[] = [
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
  /[Xx][Cc]7[Aa]\d{1,3}[Tt]/i,
  /[Aa]rtix-?\s*7/i,
  /[Ff][Tt]60[01]/i,
  /[Ff][Tt]2232/i,
  /[Ll]eech[Dd][Mm][Aa]/i,
  /[Cc]aptain[Dd][Mm][Aa]/i,
  /[Ee]nigma\s*[Xx]1/i,
  /[Ss]creamer\s*[Mm]2/i,
  /[Rr]aptor\s*[Dd][Mm][Aa]/i,
  /remote-?\s*debugging-?\s*port/i,
  /chrome\.devtools/i,
  /native\s*invoker/i,
  /get_native_handler/i,
  /[Rr][Aa][Mm]\s*[Dd](isk|rive)/i,
  /[Ii][Mm][Dd]isk/i,
  /[Tt][Mm][Pp][Ff][Ss]/i,
  /:zone\.identifier/i,
  /alternate\s*data\s*stream/i,
  /[Pp]erm(?:anent)?\s*[Ss]poof/i,
  /[Ee][Ff][Ii]\s*[Ss]poof/i,
  /[Ss][Mm][Bb][Ii][Oo][Ss]\s*[Ss]poof/i,
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

// ═══════════════════════════════════════════════════
// 4. QUERY API
// ═══════════════════════════════════════════════════

/** Minimum keyword length — prevents FP from short substrings like "ce" in "process" */
/** Minimum keyword length — prevents FP from short substrings like "ce" in "process" */
export const MIN_KEYWORD_LENGTH = 4

/**
 * Match keywords against a text string.
 * Returns list of matched keyword strings.
 */
export function matchKeywords(text: string): string[] {
  const lower = text.toLowerCase()
  const matches: string[] = []
  for (const kw of ALL_CHEAT_KEYWORDS) {
    if (kw.length < MIN_KEYWORD_LENGTH) continue
    if (lower.includes(kw.toLowerCase())) {
      matches.push(kw)
    }
  }
  return matches
}

/**
 * Match regex patterns against a text string.
 * Returns list of pattern.source values that matched.
 */
export function matchPatterns(text: string): string[] {
  const matches: string[] = []
  for (const pat of SUSPICIOUS_PATTERNS) {
    if (pat.test(text)) {
      matches.push(pat.source)
    }
  }
  return matches
}

/**
 * Get a suspicious category by name.
 */
export function getCategory(name: string): CheatCategory | undefined {
  return SUSPICIOUS_CATEGORIES[name]
}

/**
 * Get all category names as an array.
 */
export function getAllCategoryNames(): string[] {
  return Object.keys(SUSPICIOUS_CATEGORIES)
}

// ═══════════════════════════════════════════════════
// 5. HOT-RELOAD: Runtime signature updates
// ═══════════════════════════════════════════════════

/**
 * Append new keywords to the global list in runtime.
 * Deduplicates — won't add the same keyword twice.
 * Returns count of actually added keywords.
 */
export function addKeywords(keywords: string[]): number {
  const existing = new Set(ALL_CHEAT_KEYWORDS.map(k => k.toLowerCase()))
  let added = 0
  for (const kw of keywords) {
    const clean = kw.trim().toLowerCase()
    if (clean.length >= MIN_KEYWORD_LENGTH && !existing.has(clean)) {
      ALL_CHEAT_KEYWORDS.push(clean)
      existing.add(clean)
      added++
    }
  }
  return added
}

/**
 * Append new regex patterns to the global list in runtime.
 * Deduplicates by pattern.source.
 * Returns count of actually added patterns.
 */
export function addPatterns(patterns: RegExp[]): number {
  const existing = new Set(SUSPICIOUS_PATTERNS.map(p => p.source))
  let added = 0
  for (const pat of patterns) {
    if (!existing.has(pat.source)) {
      SUSPICIOUS_PATTERNS.push(pat)
      existing.add(pat.source)
      added++
    }
  }
  return added
}

/**
 * Get signature stats for diagnostics.
 */
export function getSignatureStats(): { keywords: number; patterns: number; categories: number } {
  return {
    keywords: ALL_CHEAT_KEYWORDS.length,
    patterns: SUSPICIOUS_PATTERNS.length,
    categories: Object.keys(SUSPICIOUS_CATEGORIES).length,
  }
}
