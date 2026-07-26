/**
 * Predator — Comprehensive cheat signature database
 * Sources: community research, known cheat software,
 *          Python anti-cheat scanner (расширенный 5-й режим)
 *
 * Supported games: FiveM, RAGE MP, ALT:V
 *
 * HOW TO UPDATE: just edit these arrays and rebuild.
 * No code changes needed — keep signatures up to date daily.
 */

import path from 'path'
import { CFG } from './config'

const { PF, PF86, HOME, PD, WR } = CFG

// ═══════════════════════════════════════════════════
// 0. GAME PROCESSES — what we protect
// ═══════════════════════════════════════════════════

export const GAME_PROCESSES = [
  // FiveM
  'FiveM.exe', 'FiveM_GTAProcess.exe', 'FiveM_ChromiumBrowser.exe',
  'FiveM_b2060_GTA.exe', 'FiveM_b2372_GTA.exe', 'FiveM_b2545_GTA.exe',
  'FiveM_b2612_GTA.exe', 'FiveM_b2699_GTA.exe', 'FiveM_b2802_GTA.exe',

  // RAGE MP
  'ragemp_v.exe', 'ragemp.exe', 'updater.exe',

  // ALT:V
  'altv.exe', 'altv-server.exe',

  // GTA 5 (shared)
  'GTA5.exe', 'GTAVLauncher.exe', 'PlayGTAV.exe',
]

// ═══════════════════════════════════════════════════
// 1. CHEAT PROCESSES (tasklist) — what we hunt
// ═══════════════════════════════════════════════════

export const KNOWN_PROCESSES: string[] = [
  // Injectors (external)
  'xenos.exe', 'xenos64.exe', 'extremeinjector.exe',
  'manualmapinjector.exe', 'scylla.exe',
  'processhacker.exe', 'process hacker.exe',

  // Debuggers / memory tools
  'cheatengine.exe', 'cheat engine.exe', 'ce.exe',
  'x64dbg.exe', 'x32dbg.exe', 'ollydbg.exe',
  'ida.exe', 'ida64.exe', 'ghidra.exe',
  'reclass.exe', 'reclass64.exe',

  // .NET reverse engineering
  'dnspy.exe', 'ilspy.exe', 'reflector.exe',

  // Network debuggers
  'fiddler.exe', 'wireshark.exe', 'charles.exe',

  // Trainer suites
  'wemod.exe', 'flingtrainer.exe',

  // FiveM-specific cheat menus
  'eulen.exe', 'eulenmenu.exe', 'redengine.exe', 'redenginev2.exe',
  'skript.gg.exe', 'skript.exe', 'skriptmenu.exe',
  'impulse.exe', 'impulseone.exe', 'impulsemenu.exe',
  'luna.exe', 'luna menu.exe',
  'paragon.exe', 'paragonmenu.exe',
  'ozark.exe', 'ozarkmenu.exe',
  'cherax.exe', 'cheraxmenu.exe',
  'stand.exe', 'standmenu.exe',
  '2take1.exe', '2take1menu.exe',
  'modest.exe', 'modestmenu.exe',
  'kiddions.exe', 'kiddion.exe', 'kiddionsmenu.exe',

  // GTA 5 mod menus (asi loaders — SP only, but used in MP)
  'gta5modmenu.exe', 'menyoo.exe',
  'simpletrainer.exe', 'scripthookv.exe', 'scripthookvdotnet.exe',

  // Majestic RP
  'majesty.exe', 'majestycheat.exe',

  // Spoofers / cleaners
  'rpchanger.exe', 'hwidspoofer.exe', 'spoofer.exe',
  'macchanger.exe', 'ipchanger.exe',
  'vpnchanger.exe', 'cleaner.exe',
  'tracecleaner.exe', 'logcleaner.exe',

  // DMA / memory hardware tools
  'fuser.exe', 'fuser64.exe', 'fuser_x64.exe',
  'pcileech.exe', 'pcileech64.exe',
  'screamer.exe', 'screamer_mem.exe',
  'dma.exe', 'dma64.exe', 'fpga.exe',
  'kmem.exe', 'memprocfs.exe', 'winpmem.exe',
  'coremap.exe',

  // Known cheat loaders masquerading as legit software
  'epicgameslauncher.exe', // detected cheat loader
  // NOTE: dxwebsetup.exe NOT added here — legitimate Microsoft DirectX Web Setup
  // Installer uses the exact same filename. Detection via SHA256 hash only.
]

// ═══════════════════════════════════════════════════
// 2. KNOWN CHEAT FILE NAMES (DLL, EXE, ASI)
// ═══════════════════════════════════════════════════

export const KNOWN_CHEAT_FILES: string[] = [
  // Cheat engine components
  'cheatengine.dll', 'cehook.dll', 'speedhack.dll',

  // Injectors
  'xenos.dll', 'injector.dll', 'manualmap.dll',

  // ScriptHookV
  'scripthookv.dll', 'scripthookvdotnet.dll',

  // GTA 5 cheat menus DLLs
  'eulen.dll', 'redengine.dll',
  'skript.dll', 'impulse.dll', 'luna.dll',
  'paragon.dll', 'ozark.dll', 'cherax.dll',
  'stand.dll', '2take1.dll', 'modest.dll', 'kiddions.dll',

  // Majestic RP
  'majesty.dll', 'rpchanger.dll',

  // Spoofers
  'spoofer.dll', 'hwid.dll', 'mac.dll', 'ip.dll',

  // Generic cheat DLLs
  'loader.dll', 'inject.dll', 'hack.dll',
  'menu.dll', 'modmenu.dll', 'cheat.dll',

  // Aimbot / ESP
  'aimbot.dll', 'esp.dll', 'wallhack.dll',
  'triggerbot.dll', 'norecoil.dll', 'nospread.dll',

  // Godmode / money
  'godmode.dll', 'infiniteammo.dll', 'teleport.dll',
  'money.dll', 'moneydrop.dll', 'recovery.dll',
  'unlockall.dll', 'level.dll', 'rp.dll',

  // DMA / memory tools
  'leechcore.dll', 'leechcore64.dll',
  'vmm.dll', 'vmm64.dll',
  'FTD3XX.dll', 'ftd2xx.dll',

  // RAGE MP cheat loaders
  'ragemp_hook.dll', 'ragemp_inject.dll',
  'ragemp_menu.dll', 'ragemp_cheat.dll',

  // ALT:V cheat modules
  'altv_cheat.dll', 'altv_menu.dll',
  'altv_inject.dll', 'altv_esp.dll',

  // EpicGames masquerading cheat loader
  'epicgameslauncher.exe',
  'epicgameslauncher.dll',

  // NOTE: dxwebsetup.exe/dll NOT added here — legitimate Microsoft DirectX Web Setup
  // Installer uses the exact same filename. Detection via SHA256 hash only.
]

// ═══════════════════════════════════════════════════
// 3. KNOWN CHEAT HASHES (SHA256)
// ═══════════════════════════════════════════════════
// These are exact file hashes of known cheat loaders.
// Updated: 2026-07-24 — added EpicGamesLauncher.exe masquerading loader

// ── Mutable — cloud-sync fetcher adds new hashes at runtime ──
export let KNOWN_CHEAT_HASHES: string[] = [
  // dxwebsetup.exe — masquerading as Microsoft DirectX Web Setup Installer
  // Sources: user reports + Falcon Sandbox (CrowdStrike 100% malicious, 103090 indicators)
  // Packer: VMProtect (confirmed by ESET: Win32/Packed.VMProtect.ACX trojan)
  // Malware family: Gen:Variant.Barys
  // AV detections: 9/27 — TR/W64.Agent, W64/ABTrojan.KHRQ-2517, Trojan_Win32_Kepavll_rfn
  // Also found as: EpicGamesLauncher.exe masquerading cheat loader (same hash)
  '1fe1755cb0c68a0e76e1c3c00f7832532f0c174e12efcd197a808f73a6e39040',
]

/** Replace the entire KNOWN_CHEAT_HASHES array with cloud-fetched data */
export function setKnownCheatHashes(hashes: string[]): void {
  KNOWN_CHEAT_HASHES = hashes
}

/** Merge new hashes into the existing set (deduplicates) */
export function mergeCheatHashes(hashes: string[]): void {
  const existing = new Set(KNOWN_CHEAT_HASHES)
  for (const h of hashes) {
    if (h.length === 64 && !existing.has(h)) {
      existing.add(h)
    }
  }
  KNOWN_CHEAT_HASHES = Array.from(existing)
}

// ═══════════════════════════════════════════════════
// 4. LUA SCRIPTS (cheat scripts for mod menus)
// ═══════════════════════════════════════════════════

export const KNOWN_LUA_SCRIPTS: string[] = [
  'eulen.lua', 'redengine.lua', 'skript.lua',
  'impulse.lua', 'luna.lua', 'paragon.lua',
  'ozark.lua', 'cherax.lua', 'stand.lua',
  '2take1.lua', 'modest.lua', 'kiddions.lua',
  'majesty.lua', 'rpchanger.lua', 'spoofer.lua',
  'bypass.lua', 'anticheat.lua', 'hack.lua',
  'menu.lua', 'modmenu.lua', 'cheat.lua',
  'aimbot.lua', 'esp.lua', 'wallhack.lua',
  'triggerbot.lua', 'norecoil.lua', 'nospread.lua',
  'godmode.lua', 'infiniteammo.lua', 'teleport.lua',
  'money.lua', 'moneydrop.lua', 'recovery.lua',
  'unlockall.lua', 'level.lua', 'rp.lua',
  'stats.lua', 'heist.lua', 'casino.lua',
  'vehicle.lua', 'weapon.lua', 'player.lua',
  'world.lua', 'network.lua', 'session.lua',
]

// ═══════════════════════════════════════════════════
// 5. FOLDER NAMES (known cheat directories)
// ═══════════════════════════════════════════════════

export const KNOWN_CHEAT_FOLDERS: string[] = [
  // Cheat engines
  'cheat engine', 'xenos', 'extreme injector',

  // GTA 5 specific menus
  'eulen', 'redengine', 'skript', 'impulse',
  'luna', 'paragon', 'ozark', 'cherax', 'stand',
  '2take1', 'modest', 'kiddions', 'majesty',

  // Spoofers
  'rpchanger', 'spoofer', 'hwid spoofer', 'hwid',

  // Modding forums
  'unknowncheats', 'uc', 'mpgh', 'elitepvpers',

  // Trainers
  'wemod', 'fling',

  // GTA 5 mods
  'menyoo', 'simple trainer', 'nativeui',
  'scripthookv', 'scripthookvdotnet',
  'openiv', 'codewalker',

  // FiveM cheats
  'lambda menu', 'lambda', 'vmenu',
  'ragepluginhook', 'rage', 'lspdfr',

  // Majestic RP
  'majestic', 'majesticrp', 'majestic launcher',
  'gta5rp', 'gta 5 rp', 'gta rp',

  // Bypasses
  'bypass', 'ac bypass', 'anticheat bypass', 'anti_ban',

  // Cleaners
  'cleaner', 'trace cleaner', 'log cleaner',

  // DMA / memory tools
  'pcileech', 'fuser', 'screamer', 'leechcore',
  'memprocfs', 'vmm', 'winpmem',

  // RAGE MP cheats
  'ragemp cheat', 'ragemp hack', 'ragemp menu',

  // ALT:V cheats
  'altv cheat', 'altv hack', 'altv menu',

  // DirectX masquerading cheat loaders
  // NOTE: potential FP on dev machines with DirectX documentation — use hash-only for zero-FP
  'dxwebsetup',
]

// ═══════════════════════════════════════════════════
// 6. BINARY STRING SIGNATURES (inside .exe/.dll)
// ═══════════════════════════════════════════════════

export const KNOWN_BINARY_SIGNATURES: Buffer[] = [
  // Cheat menu names
  B('eulen'), B('redengine'), B('skript.gg'), B('impulse.one'),
  B('2take1.menu'), B('stand.gg'), B('cherax.menu'),
  B('paragon.menu'), B('ozark.menu'), B('luna.menu'),
  B('modest.menu'), B('kiddions modest'), B('majesty.rp'),

  // Spoofers
  B('rpchanger'), B('hwid spoofer'), B('mac spoofer'),

  // DMA
  B('pcileech'), B('fuser'), B('screamer'),
  B('leechcore'), B('memprocfs'), B('vmm.dll'),
  B('fpga'), B('ftdi'), B('dma memory'),

  // RAGE MP cheat signatures
  B('ragemp_hook'), B('ragemp_inject'),

  // ALT:V cheat signatures
  B('altv_cheat'), B('altv_menu'),

  // External cheat loader patterns
  // d3d11.dll is NOT here — too many false positives (legit games use DirectX)
  // Detected contextually via scanGameModules() platform whitelist mismatch

  // Malware family: Gen:Variant.Barys — associated with masquerading cheat loaders (Falcon Sandbox)
  // NOTE: VMProtect strings NOT added here — already covered by SUSPICIOUS_CATEGORIES.obfuscator
  // and would cause FPs on legitimate software using VMProtect for copy protection.
  B('barys'),

  // NOTE: B('dxwebsetup') and B('DirectX Web Setup') are intentionally NOT added here
  // because the legitimate Microsoft DirectX Web Setup Installer also contains these strings.
  // Detection for this cheat relies on SHA256 hash only (filename detection would produce FPs).
]

function B(s: string): Buffer {
  return Buffer.from(s, 'utf-8')
}

// ═══════════════════════════════════════════════════
// 7. REGISTRY PATHS TO CHECK
// ═══════════════════════════════════════════════════

export const REGISTRY_SCAN_KEYS: string[] = [
  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
  'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',
  'HKLM\\SYSTEM\\CurrentControlSet\\Services',
  'HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache',
]

// ═══════════════════════════════════════════════════
// 8. PLATFORM-SPECIFIC MODULE WHITELISTS
// ═══════════════════════════════════════════════════
// These lists contain legitimate modules that each game process loads.
// Any module NOT in this list and NOT in a trusted path = suspicious.

export const FIVEM_WHITELIST = new Set([
  'fivem.exe', 'fivem_gtaprocess.exe', 'fivem_chromebrowser.exe',
  'citizen-scripting-v8.dll', 'citizen-resources-core.dll',
  'v8.dll', 'v8_libbase.dll', 'v8_libplatform.dll',
  'discord-rpc.dll',
  'steamclient64.dll', 'socialclub.dll', 'socialclubhelper.dll',
  'nvwgf2umx.dll', 'amd_ags_x64.dll',
  'bink2w64.dll',
])

export const RAGE_WHITELIST = new Set([
  'ragemp_v.exe', 'gta5.exe', 'gtavlauncher.exe',
  'v8.dll', 'node.dll', 'node_64.dll',
  'libcef.dll', 'chrome_elf.dll',
  'socialclub.dll', 'steamclient64.dll',
  'bink2w64.dll',
])

export const ALTV_WHITELIST = new Set([
  'altv.exe', 'gta5.exe',
  'altv-client.dll', 'coreclr.dll', 'clrjit.dll',
  'v8.dll', 'v8_libbase.dll', 'v8_libplatform.dll',
  'node.dll',
  'steamclient64.dll',
])

// Combined whitelist lookup
export function isPlatformWhitelisted(moduleName: string, platform: string): boolean {
  const lower = moduleName.toLowerCase()
  switch (platform) {
    case 'fivem': return FIVEM_WHITELIST.has(lower)
    case 'rage': return RAGE_WHITELIST.has(lower)
    case 'altv': return ALTV_WHITELIST.has(lower)
    default: return false
  }
}

// ═══════════════════════════════════════════════════
// 9. SCAN PATHS — FiveM, RAGE MP, ALT:V, GTA 5
// ═══════════════════════════════════════════════════

export function getScanPaths(): string[] {
  return [
    // System temp
    process.env.TEMP || 'C:\\Windows\\Temp',
    path.join(HOME, 'AppData', 'Local', 'Temp'),
    path.join(HOME, 'Downloads'),
    path.join(HOME, 'Desktop'),

    // GTA 5 (Rockstar / Steam / Epic)
    path.join(PF, 'Rockstar Games', 'Grand Theft Auto V'),
    path.join(PF86, 'Rockstar Games', 'Grand Theft Auto V'),
    path.join(PF, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),
    path.join(PF86, 'Steam', 'steamapps', 'common', 'Grand Theft Auto V'),

    // FiveM
    path.join(HOME, 'AppData', 'Local', 'FiveM'),
    path.join(HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app'),
    path.join(HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'mods'),
    path.join(HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'plugins'),
    path.join(HOME, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'cache'),
    path.join(HOME, 'AppData', 'Roaming', 'CitizenFX'),

    // RAGE MP
    path.join(PF, 'RAGEMP'),
    path.join(PF86, 'RAGEMP'),
    path.join(HOME, 'RAGEMP'),
    path.join(HOME, 'AppData', 'Roaming', 'RAGEMP'),
    path.join(HOME, 'AppData', 'Local', 'RAGEMP'),

    // ALT:V
    path.join(PF, 'altv'),
    path.join(PF86, 'altv'),
    path.join(HOME, 'AppData', 'Local', 'altv'),
    path.join(HOME, 'AppData', 'Local', 'altv', 'resources'),
    path.join(HOME, 'AppData', 'Local', 'altv', 'modules'),
    path.join(HOME, 'AppData', 'Roaming', 'altv'),

    // Common cheat directories
    path.join(HOME, 'Documents', 'Cheats'),
    path.join(HOME, 'Documents', 'Hacks'),
    path.join(HOME, 'Documents', 'Mods'),
  ]
}

// ═══════════════════════════════════════════════════
// 10. TARGET FILE EXTENSIONS
// ═══════════════════════════════════════════════════
// Removed: .txt, .log, .py, .cpp, .c, .h (too noisy)

// ═══════════════════════════════════════════════════
// 11. MASQUERADING FILENAMES — known cheat loaders disguised as legit software
// ═══════════════════════════════════════════════════
// These files are legitimate utilities that cheat loaders masquerade as.
// Detection heuristic: if one of these filenames is found WITHOUT a valid
// digital signature, PE metadata, or with packing artifacts — it's a cheat.
//
// Legitimate versions of these files ALWAYS have proper digital signatures
// and PE metadata (version info, resources).

export const MASQUERADING_FILENAMES = new Set([
  'dxwebsetup.exe',        // Microsoft DirectX Web Setup Installer
  'epicgameslauncher.exe',  // Epic Games Launcher
  'epicgameslauncher.dll',
  'java.exe',               // Java runtime — common masquerade for injectors
  'javaw.exe',
  'conhost.exe',            // Windows Console Host — masquerade for hidden injectors
  'rundll32.exe',           // Windows DLL host — masquerade for DLL loaders
  'svchost.exe',            // Windows Service Host — critical NEVER flag legit one
  'lsass.exe',              // Windows LSASS — masquerade for credential stealers
  'services.exe',           // Windows Services Controller
  'winlogon.exe',           // Windows Logon — masquerade for persistence
  'explorer.exe',           // Windows Explorer — masquerade for hidden processes
  'notepad.exe',            // Simple text editor — masquerade for test payloads
  'chrome.exe',             // Google Chrome
  'msedge.exe',             // Microsoft Edge
  'firefox.exe',            // Firefox
  'spotify.exe',            // Spotify
  'discord.exe',            // Discord
  'steam.exe',              // Steam
  'steamwebhelper.exe',
  'battle.net.exe',         // Battle.net
  'vanguard.exe',           // Riot Vanguard — ironic, cheats masquerade as anti-cheat
])

export const TARGET_EXTENSIONS = new Set([
  '.exe', '.dll', '.asi', '.luac', '.lua',
  '.js', '.cs',
  '.bat', '.ps1', '.vbs', '.ahk',
  '.cfg', '.ini', '.json', '.xml',
  '.rpf', // GTA 5 archive (RAGE MP cheats modify RPF)
  '.sys', '.drv',
])
