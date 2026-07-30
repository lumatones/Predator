/**
 * Predator — Server-side Cheat Knowledge Database
 *
 * Centralised intelligence for the Smart Classifier.
 * Mirrors key data from electron/cheats-db.ts and electron/signature-registry.ts
 * for server-side use, WITHOUT importing Electron modules.
 *
 * Three layers:
 *   Layer 1 — Exact names/strings (high confidence)
 *   Layer 2 — Pattern-based (medium confidence)
 *   Layer 3 — Behavioural indicators (low confidence, used in correlation)
 */

// ═══════════════════════════════════════════════════
// LAYER 1 — EXACT CHEAT NAMES (HIGH CONFIDENCE)
// ═══════════════════════════════════════════════════

/** Known cheat executable names (°exe without .exe) */
export const CHEAT_EXECUTABLES = new Set([
  // FiveM-specific cheat menus
  'eulen', 'eulenmenu', 'redengine', 'redenginev2',
  'skript', 'skript.gg', 'skriptmenu',
  'impulse', 'impulseone', 'impulsemenu',
  'luna', 'luna menu',
  'paragon', 'paragonmenu',
  'ozark', 'ozarkmenu',
  'cherax', 'cheraxmenu',
  'stand', 'standmenu',
  '2take1', '2take1menu',
  'modest', 'modestmenu',
  'kiddions', 'kiddion',
  'susano', 'susanomenu',
  'lambda', 'lambdamenu', 'vmenu',
  'absolute', 'nightfall', 'aurora',
  'hydrogen', 'oxide', 'havoc', 'revolution',

  // 0xCheats / LeetCheats / Unicore / Vanish
  '0xcheats', '0xcheat', 'oxcheat',
  'leetcheats', 'leetcheat', 'noleet', 'noleetcheats',
  'unicore', 'unicoremenu', 'unicorecheat',
  'vanish', 'vanishmenu', 'vanishcheat',
  'nightfall', 'nightfallmenu', 'nightfallcheat',

  // 2025-2026 new menus
  'phoenix', 'phoenixmenu', 'phoenixcheat',
  'eternal', 'eternalmenu', 'eternalcheat',
  'zenith', 'zenithmenu', 'zenithcheat',
  'dynasty', 'dynastymenu',
  'vertex', 'vertexmenu',
  'infinity', 'infinitymenu',
  'oblivion', 'oblivionmenu',
  'ares', 'aresmenu',
  'phantom', 'phantommenu', 'phantomcheat',
  'solara', 'solaraexecutor',
  'wave', 'wavemenu',
  'scriptware', 'scriptwarem',
  'synapse', 'synapsex', 'synapselauncher',
  'krnl', 'krnlss', 'krnlbeta',
  'fluxus', 'fluxusm',
  'codex', 'codexmenu',
  'vendetta', 'vendettamenu',
  'aresnal', 'aresnalclient',
  'nexus', 'nexusmenu', 'nexuscheat',

  // Majestic RP
  'majesty', 'majestycheat',

  // Injectors
  'xenos', 'xenos64', 'extremeinjector',
  'manualmapinjector', 'scylla',

  // DMA / hardware tools
  'fuser', 'fuser64', 'fuser_x64',
  'pcileech', 'pcileech64',
  'screamer', 'screamer_mem',
  'dma', 'dma64', 'fpga',
  'kmem', 'memprocfs', 'winpmem',
  'coremap', 'kdmapper', 'drvmap', 'physmem',
  'rtcore',

  // Spoofers / cleaners
  'rpchanger', 'hwidspoofer', 'spoofer',
  'macchanger', 'ipchanger', 'vpnchanger',
  'tracecleaner', 'logcleaner',

  // GTA 5 mod menus
  'menyoo', 'simpletrainer',
  'scripthookv', 'scripthookvdotnet',
  'gta5modmenu',

  // RAGE MP specific
  'ragemp_loader', 'rage_mp_cheat', 'ragemp_hack',
  'cef_injector', 'cef_hook_loader',
  'server_executor', 'resource_injector',
  'ragemp_spoofer', 'rage_spoofer',

  // ALT:V specific
  'altv_executor', 'altv_js_injector', 'altv_dotnet_loader',
  'altv_resource_dumper', 'altv_client_hook',
  'altv_bypass', 'altv_esp', 'altv_menu',
])

/** Known cheat DLL/ASI file names */
export const CHEAT_LIBRARIES = new Set([
  'cheatengine.dll', 'cehook.dll', 'speedhack.dll',
  'xenos.dll', 'injector.dll', 'manualmap.dll',
  'scripthookv.dll', 'scripthookvdotnet.dll',
  'eulen.dll', 'redengine.dll',
  'skript.dll', 'impulse.dll', 'luna.dll',
  'paragon.dll', 'ozark.dll', 'cherax.dll',
  'stand.dll', '2take1.dll', 'modest.dll', 'kiddions.dll',
  'susano.dll', 'lambda.dll', 'vmenu.dll',
  'absolute.dll', 'nightfall.dll', 'aurora.dll',
  'hydrogen.dll', 'oxide.dll', 'havoc.dll', 'revolution.dll',
  '0xcheats.dll', '0xcheat.dll', 'oxcheat.dll',
  'leetcheats.dll', 'leetcheat.dll', 'noleet.dll', 'noleetcheats.dll',
  'unicore.dll', 'unicoremenu.dll', 'unicorecheat.dll',
  'vanish.dll', 'vanishmenu.dll', 'vanishcheat.dll',
  'nightfall.dll', 'nightfallmenu.dll', 'nightfall_loader.dll',

  // DMA/FPGA
  'leechcore.dll', 'leechcore64.dll',
  'vmm.dll', 'vmm64.dll',
  'ftd3xx.dll', 'ftd2xx.dll',
  'pcileech.dll', 'pcileech_core.dll',
  'leechcore.dll', 'leechsvc.dll',
  'fpga.dll', 'dma_access.dll',

  // RAGE MP cheat DLLs
  'ragemp_hook.dll', 'ragemp_inject.dll',
  'ragemp_menu.dll', 'ragemp_cheat.dll',
  'ragemp_bypass.dll', 'ragemp_loader.dll',
  'cef_hook.dll', 'cef_inject.dll',
  'server_inject.dll', 'resource_hook.dll',

  // ALT:V cheat modules
  'altv_cheat.dll', 'altv_menu.dll',
  'altv_inject.dll', 'altv_esp.dll',
  'altv_bypass.dll', 'altv_loader.dll',
  'altv_resource.dll', 'altv_client_hook.dll',

  // Generic cheat DLLs
  'loader.dll', 'inject.dll', 'hack.dll',
  'menu.dll', 'modmenu.dll', 'cheat.dll',
  'aimbot.dll', 'esp.dll', 'wallhack.dll',
  'triggerbot.dll', 'norecoil.dll', 'nospread.dll',
  'godmode.dll', 'infiniteammo.dll', 'teleport.dll',
  'money.dll', 'moneydrop.dll', 'recovery.dll',
  'unlockall.dll', 'level.dll', 'rp.dll',
])

/** Cheat-related folder names (matched against file path) */
export const CHEAT_FOLDER_KEYWORDS = new Set([
  'eulen', 'redengine', 'skript', 'impulse',
  'luna', 'paragon', 'ozark', 'cherax', 'stand',
  '2take1', 'modest', 'kiddions', 'majesty',
  'xenos', 'extreme injector',
  'cheat engine',
  'unknowncheats', 'uc', 'mpgh', 'elitepvpers',
  'lambda menu', 'lambda', 'vmenu',
  'menyoo', 'simple trainer', 'nativeui',
  'scripthookv', 'openiv', 'codewalker',
  'bypass', 'ac bypass', 'anticheat bypass', 'anti_ban',
  'spoofer', 'hwid spoofer', 'rpchanger',
  'cleaner', 'trace cleaner', 'log cleaner',
  'nightfall', '0xcheats', '0xcheat', 'oxcheat',
  'leetcheats', 'unicore', 'vanish',
  'pcileech', 'fuser', 'screamer', 'leechcore',
  'memprocfs', 'vmm', 'winpmem',
  'ragemp cheat', 'ragemp hack', 'ragemp bypass',
  'rage mp cheat',
  'cef exploit', 'cef devtools', 'cef injector',
  'altv cheat', 'altv hack', 'altv bypass',
  'js executor', 'altv js', 'altv dotnet',
  'majestic', 'majesticrp',
  'wemod', 'fling',
  'dxwebsetup',
])

/** Files known to masquerade as legitimate software */
export const MASQUERADING_FILENAMES = new Set([
  'dxwebsetup.exe',
  'epicgameslauncher.exe', 'epicgameslauncher.dll',
  'java.exe', 'javaw.exe',
  'conhost.exe', 'rundll32.exe',
  'svchost.exe', 'lsass.exe',
  'services.exe', 'winlogon.exe',
  'explorer.exe', 'notepad.exe',
  'chrome.exe', 'msedge.exe', 'firefox.exe',
  'spotify.exe', 'discord.exe', 'steam.exe',
  'steamwebhelper.exe', 'battle.net.exe',
  'vanguard.exe',
  'rockstar-games-launcher.exe', 'socialclub.exe',
  'gta5.exe', 'fivem.exe', 'ragemp_v.exe', 'altv.exe',
  'vcredist.exe', 'vcredist_x64.exe',
  'dotnet-runtime.exe',
  'nvidia-installer.exe', 'amd-software.exe',
  'directx_installer.exe', 'd3dcompiler_installer.exe',
])

// ═══════════════════════════════════════════════════
// LAYER 2 — CHEAT KEYWORDS & PATTERNS (MEDIUM CONFIDENCE)
// ═══════════════════════════════════════════════════

/**
 * High-signal cheat keywords.
 * Found in match descriptions, file names, process names.
 */
export const CHEAT_KEYWORDS_HIGH = new Set([
  // Injectors & loaders
  'injector', 'manualmap', 'reflective loader', 'reflective dll',
  'kdmapper', 'drvmap', 'byovd', 'vulnerable driver',
  'dll inject', 'process hollow', 'process ghost', 'process doppelgäng',
  'early bird apc', 'thread hijack', 'apc inject',

  // DMA / hardware
  'pcileech', 'leechcore', 'fpga', 'dma card', 'dma firmware',
  'xilinx', 'artix-7', 'altera', 'ft601', 'ft2232', 'ftd3xx',
  'captaindma', 'screamer m2', 'enigma x1', 'raptor dma',
  'pcie leech', 'memprocfs', 'winpmem',

  // Known cheat menus
  'eulen', 'redengine', 'cherax', 'stand.gg', '2take1.menu',
  'luna menu', 'ozark', 'paragon', 'kiddions', 'modest menu',

  // Spoofers
  'hwid spoofer', 'mac spoofer', 'serial spoofer', 'smbios spoofer',
  'volumeid', 'efi spoofer', 'perm spoofer',

  // Anti-debug / evasion
  'screenshare bypass', 'screen share bypass',
  'pc check bypass', 'anticheat bypass',
  'eac bypass', 'battleye bypass', 'vanguard bypass',

  // Bypass methods
  'veh hook', 'vectored exception handler',
  'direct syscall', 'indirect syscall', 'hells gate', 'halos gate',
  'syswhispers', 'tartarus gate',
  'etw bypass', 'etw patch', 'amsi bypass', 'amsi patch',
  'dse bypass', 'patchguard bypass',
  'unhook windows', 'rehook ntdll', 'fresh ntdll',

  // FiveM/RAGE/ALT specific
  'cef hook', 'cef injector', 'cef devtools', 'cef exploit',
  'ragemp bypass', 'ragemp hack',
  'altv bypass', 'altv esp', 'altv cheat',
  'resource injector', 'server executor',
  'js executor', 'dotnet inject', 'compiled resource',
])

/**
 * Medium-signal cheat keywords.
 * Found in match descriptions — less specific but still suspicious.
 */
export const CHEAT_KEYWORDS_MEDIUM = new Set([
  // Generic cheat terms
  'cheat', 'hack', 'trainer', 'mod menu', 'modmenu',
  'aimbot', 'wallhack', 'esp', 'triggerbot',
  'norecoil', 'nospread', 'norecoil',
  'godmode', 'teleport', 'moneydrop', 'money drop',
  'recovery', 'unlockall', 'rp glitch',

  // Injection techniques
  'setwindowshookex', 'createremotethread',
  'ntcreatethreadex', 'writeprocessmemory',
  'virtualallocex', 'queueuserapc',
  'setthreadcontext', 'getthreadcontext',

  // Hook types
  'iat hook', 'eat hook', 'ssdt hook', 'idt hook',
  'irp hook', 'inline hook', 'detour', 'minhook',
  'easyhook', 'mhook',

  // Packers / obfuscators
  'vmprotect', 'themida', 'enigma protector', 'obsidium',
  'armadillo', 'packed', 'obfuscated',

  // Loaders & bypasses
  'loader', 'bypass', 'inject', 'executor',
  'dll proxy', 'dll sideload', 'dll hijack',
  'search order hijack', 'binary planting',

  // Memory manipulation
  'memory patch', 'hot patch', 'code cave',
  'shellcode', 'position independent',

  // Anti-forensic
  'wipe', 'cleaner', 'trace cleaner', 'log cleaner',
  'disk cleaner', 'serial cleaner',
  'tmpfs', 'ram disk', 'imdisk', 'memory only',
  'alternate data stream', 'zone.identifier',
])

// ═══════════════════════════════════════════════════
// LAYER 3 — BEHAVIORAL INDICATORS (LOW CONFIDENCE, CORRELATION ONLY)
// ═══════════════════════════════════════════════════

export const BEHAVIORAL_INDICATORS = new Set([
  'suspicious memory region', 'rwx memory', 'execute read write',
  'suspended process', 'hidden process', 'orphan thread',
  'unsigned driver', 'kernel callback',
  'remote thread', 'cross process write',
  'injected module', 'phantom dll',
  'debugger present', 'debug port', 'hardware breakpoint',
  'timing attack', 'rdtsc', 'queryperformancecounter',
  'vm detection', 'sandbox detection',
  'anti dump', 'anti debug', 'anti analysis',
])

// ═══════════════════════════════════════════════════
// FINDING KIND CLASSIFICATION — what kind of detection triggered
// ═══════════════════════════════════════════════════

/** Mapping of finding type → default weight multiplier */
export const FINDING_KIND_WEIGHTS: Record<string, number> = {
  file: 1.0,
  process: 1.2,     // Running processes are more concerning
  browser: 0.7,      // Browser history is weaker evidence
  registry: 0.8,     // Registry traces can be stale
  hardware: 1.5,     // DMA/FPGA hardware is very suspicious
  software: 1.0,
  system: 0.9,
  dma: 2.0,          // DMA findings are highly suspicious
  cleaner: 1.3,      // Cleaners specifically evade detection
  memory: 1.4,       // Memory-level findings
  network: 0.9,
  usb: 1.1,
}

// ═══════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════

/**
 * Normalise a file/process name for matching:
 * - lowercase
 * - remove .exe / .dll / .asi extension
 * - remove path prefix
 */
export function normaliseName(name: string): string {
  return name
    .toLowerCase()
    .replace(/\\/g, '/')
    .split('/')
    .pop()!
    .replace(/\.(exe|dll|asi|sys|drv)$/i, '')
    .trim()
}

/**
 * Extract all folder segments from a path for matching.
 */
export function getPathSegments(path: string): string[] {
  return path
    .toLowerCase()
    .replace(/\\/g, '/')
    .split('/')
    .filter(Boolean)
}

/**
 * Check if a file name matches a known cheat executable/library.
 */
export function matchCheatFileName(name: string): { matched: boolean; names: string[] } {
  const normalised = normaliseName(name)
  const matched: string[] = []
  if (CHEAT_EXECUTABLES.has(normalised)) matched.push(`known_cheat_exe:${normalised}`)
  if (CHEAT_LIBRARIES.has(normalised + '.dll')) matched.push(`known_cheat_dll:${normalised}`)
  if (MASQUERADING_FILENAMES.has(name.toLowerCase())) matched.push(`masquerading:${name.toLowerCase()}`)
  return { matched: matched.length > 0, names: matched }
}

/**
 * Check if a folder name matches known cheat directories.
 */
export function matchCheatFolder(path: string): { matched: boolean; folders: string[] } {
  const segments = getPathSegments(path)
  const matched: string[] = []
  for (const seg of segments) {
    if (CHEAT_FOLDER_KEYWORDS.has(seg)) {
      matched.push(seg)
    }
  }
  return { matched: matched.length > 0, folders: matched }
}

/**
 * Scan match strings for cheat keywords and patterns.
 */
export function matchCheatKeywords(matches: string[]): {
  high: string[]
  medium: string[]
  behavioral: string[]
  totalScore: number
} {
  const high: string[] = []
  const medium: string[] = []
  const behavioral: string[] = []

  for (const m of matches) {
    const lower = m.toLowerCase()
    for (const kw of CHEAT_KEYWORDS_HIGH) {
      if (lower.includes(kw)) high.push(kw)
    }
    for (const kw of CHEAT_KEYWORDS_MEDIUM) {
      if (lower.includes(kw)) medium.push(kw)
    }
    for (const ind of BEHAVIORAL_INDICATORS) {
      if (lower.includes(ind)) behavioral.push(ind)
    }
  }

  const totalScore = high.length * 20 + medium.length * 8 + behavioral.length * 5
  return {
    high: [...new Set(high)],
    medium: [...new Set(medium)],
    behavioral: [...new Set(behavioral)],
    totalScore,
  }
}

/**
 * Detect if finding kind is DMA/hardware-related.
 */
export function isHardwareDma(findingKind: string | undefined, matches: string[]): boolean {
  if (findingKind === 'dma' || findingKind === 'hardware') return true
  const lower = matches.join(' ').toLowerCase()
  return (
    lower.includes('dma') || lower.includes('fpga') || lower.includes('pcileech') ||
    lower.includes('ftd') || lower.includes('leechcore') || lower.includes('xilinx') ||
    lower.includes('artix') || lower.includes('altera')
  )
}

/**
 * Detect anti-forensic / cleaner activity.
 */
export function isCleanerActivity(findingKind: string | undefined, matches: string[]): boolean {
  if (findingKind === 'cleaner') return true
  const lower = matches.join(' ').toLowerCase()
  return (
    lower.includes('cleaner') || lower.includes('wipe') || lower.includes('trace cleaner') ||
    lower.includes('log cleaner') || lower.includes('anti forensic') ||
    lower.includes('clear') || lower.includes('temporary') && lower.includes('delete')
  )
}
