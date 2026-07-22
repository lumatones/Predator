/**
 * Predator — Comprehensive cheat signature database
 * Sources: community research, known cheat software,
 *          Python anti-cheat scanner (расширенный 5-й режим)
 *
 * HOW TO UPDATE: just edit these arrays and rebuild.
 * No code changes needed — keep signatures up to date daily.
 */

// ═══════════════════════════════════════════════════
// 1. PROCESS NAMES (tasklist)
// ═══════════════════════════════════════════════════

export const KNOWN_PROCESSES: string[] = [
  // Classic cheat engines
  'cheatengine.exe', 'cheat engine.exe', 'ce.exe',
  'processhacker.exe', 'process hacker.exe', 'ph.exe',
  // Injectors
  'xenos.exe', 'xenos64.exe', 'extremeinjector.exe',
  'manualmapinjector.exe', 'scylla.exe', 'pe-bear.exe',
  // .NET reverse engineering
  'dnspy.exe', 'ilspy.exe', 'reflector.exe',
  // Network debuggers
  'fiddler.exe', 'wireshark.exe', 'charles.exe',
  // Trainer suites
  'wemod.exe', 'flingtrainer.exe', 'platinum.exe',
  // GTA 5 specific cheat menus
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
  // Modding forums
  'unknowncheats.exe', 'uc.exe',
  // GTA 5 mod menus (asi loaders)
  'gta5modmenu.exe', 'menyoo.exe',
  'simpletrainer.exe', 'nativeui.exe',
  'scripthookv.exe', 'scripthookvdotnet.exe',
  // FiveM-specific
  'fivem.exe', 'fivem_b*.exe', 'cfx.exe',
  // Majestic RP specific
  'majesty.exe', 'majestycheat.exe',
  // Spoofers / cleaners
  'rpchanger.exe', 'hwidspoofer.exe', 'spoofer.exe',
  'macchanger.exe', 'ipchanger.exe',
  'vpnchanger.exe', 'cleaner.exe',
  'tracecleaner.exe', 'logcleaner.exe', 'tempcleaner.exe',
  // DMA / memory
  'fuser.exe', 'fuser64.exe', 'fuser_x64.exe',
  'pcileech.exe', 'pcileech64.exe',
  'screamer.exe', 'screamer_mem.exe',
  'dma.exe', 'dma64.exe', 'fpga.exe',
  'kmem.exe', 'memprocfs.exe', 'winpmem.exe',
  'coremap.exe',
  // Debuggers
  'x64dbg.exe', 'x32dbg.exe', 'ollydbg.exe',
  'ida.exe', 'ida64.exe', 'ghidra.exe',
  'reclass.exe', 'reclass64.exe',
]

// ═══════════════════════════════════════════════════
// 2. FILE NAMES (DLL, EXE, ASI — known cheat files)
// ═══════════════════════════════════════════════════

export const KNOWN_CHEAT_FILES: string[] = [
  // Cheat engine components
  'cheatengine.dll', 'cehook.dll', 'speedhack.dll',
  // Injectors
  'xenos.dll', 'injector.dll', 'manualmap.dll',
  // ScriptHookV
  'scripthookv.dll', 'scripthookvdotnet.dll',
  'dinput8.dll', 'dsound.dll', 'winmm.dll',
  'nativeui.dll', 'menyoo.asi', 'simpletrainer.asi',
  // GTA 5 cheat menus DLLs
  'eulen.dll', 'redengine.dll',
  'skript.dll', 'impulse.dll', 'luna.dll',
  'paragon.dll', 'ozark.dll', 'cherax.dll',
  'stand.dll', '2take1.dll', 'modest.dll', 'kiddions.dll',
  // Majestic RP
  'majesty.dll', 'rpchanger.dll',
  // Spoofers
  'spoofer.dll', 'hwid.dll', 'mac.dll', 'ip.dll',
  // Bypasses
  'bypass.dll', 'anticheatbypass.dll', 'ac_bypass.dll',
  'fivem_bypass.dll', 'cfx_bypass.dll', 'rockstar_bypass.dll',
  'majesty_bypass.dll', 'gta5_bypass.dll', 'rp_bypass.dll',
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
  'stats.dll', 'heist.dll', 'casino.dll',
  // Player / world
  'vehicle.dll', 'weapon.dll', 'player.dll',
  'world.dll', 'network.dll', 'session.dll',
  // DMA / memory tools
  'leechcore.dll', 'leechcore64.dll',
  'vmm.dll', 'vmm64.dll',
  'FTD3XX.dll', 'ftd2xx.dll',
]

// ═══════════════════════════════════════════════════
// 3. LUA SCRIPTS (cheat scripts for mod menus)
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
// 4. FOLDER NAMES (known cheat directories)
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
  // Modding
  'fivem cheats', 'gta5 cheats', 'gta v mods',
  'unknowncheats', 'uc', 'mpgh', 'elitepvpers',
  // Trainers
  'wemod', 'fling', 'platinum',
  // GTA 5 mods
  'menyoo', 'simple trainer', 'nativeui',
  'scripthookv', 'scripthookvdotnet',
  'openiv', 'codewalker',
  // FiveM
  'lambda menu', 'lambda', 'vmenu',
  'ragepluginhook', 'rage', 'lspdfr',
  'fivem', 'cfx', 'redm', 'rdr2',
  // Majestic RP
  'majestic', 'majesticrp', 'majestic launcher',
  'gta5rp', 'gta 5 rp', 'gta rp', 'rp',
  // Bypasses
  'bypass', 'ac bypass', 'anticheat bypass', 'anti_ban',
  // Cleaners
  'cleaner', 'trace cleaner', 'log cleaner',
  'temp cleaner', 'ccleaner', 'bleachbit',
  // DMA / memory tools
  'pcileech', 'fuser', 'screamer', 'leechcore',
  'memprocfs', 'vmm', 'winpmem',
]

// ═══════════════════════════════════════════════════
// 5. BINARY STRING SIGNATURES (inside .exe/.dll)
// ═══════════════════════════════════════════════════

export const KNOWN_BINARY_SIGNATURES: Buffer[] = [
  // Cheat menu names
  B('eulen'), B('redengine'), B('skript.gg'), B('impulse.one'),
  B('2take1.menu'), B('stand.gg'), B('cherax.menu'),
  B('paragon.menu'), B('ozark.menu'), B('luna.menu'),
  B('modest.menu'), B('kiddions modest'), B('majesty.rp'),
  // Spoofers
  B('rpchanger'), B('hwid spoofer'), B('mac spoofer'),
  // Hack features
  B('aimbot'), B('wallhack'), B('esp'), B('triggerbot'),
  B('godmode'), B('infinite ammo'), B('teleport'),
  B('money drop'), B('recovery'), B('unlock all'),
  // Bypasses
  B('bypass anticheat'), B('anticheat bypass'),
  B('fivem bypass'), B('rockstar bypass'),
  B('majestic bypass'),
  // Injection
  B('inject dll'), B('manual map'), B('process hacker'),
  B('speed hack'), B('no recoil'), B('no spread'),
  // Player modifications
  B('super jump'), B('super run'), B('noclip'),
  B('vehicle spawn'), B('weapon spawn'), B('player mod'),
  B('network event'), B('session joiner'), B('session spoofer'),
  // DMA
  B('pcileech'), B('fuser'), B('screamer'),
  B('leechcore'), B('memprocfs'), B('vmm.dll'),
  B('fpga'), B('ftdi'), B('dma memory'),
]

function B(s: string): Buffer {
  return Buffer.from(s, 'utf-8')
}

// ═══════════════════════════════════════════════════
// 6. REGISTRY PATHS TO CHECK
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
// 7. GTA 5 / FiveM / Majestic RP SPECIFIC PATHS
// ═══════════════════════════════════════════════════

import path from 'path'
import os from 'os'

function _pf(): string { return process.env.ProgramFiles || 'C:\\Program Files' }
function _pf86(): string { return process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)' }
function _pd(): string { return process.env.ProgramData || 'C:\\ProgramData' }
function _wr(): string { return process.env.SystemRoot || 'C:\\Windows' }
const home = os.homedir()

export function getScanPaths(): string[] {
  return [
    // System temp / common
    process.env.TEMP || 'C:\\Windows\\Temp',
    process.env.TMP || 'C:\\Windows\\Temp',
    path.join(home, 'AppData', 'Local', 'Temp'),
    path.join(home, 'AppData', 'Local'),
    path.join(home, 'AppData', 'Roaming'),
    path.join(home, 'Downloads'),
    path.join(home, 'Desktop'),
    _pd(),
    path.join(_wr(), 'Temp'),
    path.join(_wr(), 'Prefetch'),
    path.join(_wr(), 'Recent'),

    // GTA 5
    path.join(_pf(), 'Rockstar Games', 'Grand Theft Auto V'),
    path.join(_pf86(), 'Rockstar Games', 'Grand Theft Auto V'),

    // FiveM
    path.join(_pf(), 'FiveM'),
    path.join(_pf86(), 'FiveM'),
    path.join(home, 'AppData', 'Local', 'FiveM'),
    path.join(home, 'AppData', 'Local', 'FiveM', 'FiveM.app'),
    path.join(home, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'mods'),
    path.join(home, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'plugins'),
    path.join(home, 'AppData', 'Local', 'FiveM', 'FiveM.app', 'cache'),

    // CitizenFX
    path.join(home, 'AppData', 'Roaming', 'CitizenFX'),

    // Majestic RP
    path.join(home, 'AppData', 'Local', 'Majestic'),
    path.join(home, 'AppData', 'Local', 'MajesticRP'),
    path.join(home, 'AppData', 'Roaming', 'Majestic'),
    path.join(home, 'AppData', 'Roaming', 'MajesticRP'),
    path.join(_pf(), 'Majestic'),
    path.join(_pf86(), 'Majestic'),

    // GTA 5 RP
    path.join(home, 'AppData', 'Local', 'GTA5RP'),
    path.join(home, 'AppData', 'Roaming', 'GTA5RP'),
    path.join(_pf(), 'GTA5RP'),

    // Common cheat directories
    path.join(home, 'Documents', 'Cheats'),
    path.join(home, 'Documents', 'Hacks'),
    path.join(home, 'Documents', 'Mods'),
  ]
}

// ═══════════════════════════════════════════════════
// 8. TARGET FILE EXTENSIONS
// ═══════════════════════════════════════════════════

export const TARGET_EXTENSIONS = new Set([
  '.exe', '.dll', '.sys', '.drv', '.asi', '.luac',
  '.js', '.lua', '.py', '.cs', '.cpp', '.c', '.h',
  '.bat', '.ps1', '.vbs', '.ahk',
  '.cfg', '.ini', '.txt', '.log', '.json', '.xml',
])
