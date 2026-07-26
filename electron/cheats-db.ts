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
  'server.exe', 'ragemp-server.exe',

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
  'susano.exe', 'susanomenu.exe', // newer FiveM menu
  'lambda.exe', 'lambdamenu.exe', 'vmenu.exe',
  'absolute.exe', 'nightfall.exe', 'aurora.exe',
  'hydrogen.exe', 'oxide.exe', 'havoc.exe', 'revolution.exe',

  // 0xCheats / LeetCheats / Unicore / Vanish
  '0xcheats.exe', '0xcheat.exe', 'oxcheat.exe',
  'leetcheats.exe', 'leetcheat.exe', 'noleet.exe', 'noleetcheats.exe',
  'unicore.exe', 'unicoremenu.exe', 'unicorecheat.exe',
  'vanish.exe', 'vanishmenu.exe', 'vanishcheat.exe',

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
  'kdmapper.exe', 'drvmap.exe', 'physmem.exe',
  'rtcore.exe', 'gdrv.sys', // vulnerable driver loaders (BYOVD)

  // RAM disk tools (used to hide cheats in memory)
  'imdisk.exe', 'ramdisk.exe', 'softperfect.exe',
  'osfmount.exe', 'primo.exe', 'ultraramdisk.exe',

  // HWID spoofer tools
  'spoofer.exe', 'hwidspoofer.exe', 'hwid.exe',
  'serialspoofer.exe', 'macchanger.exe',
  'volumeid.exe', 'smbiosspoofer.exe',
  'amidespooler.exe', 'efispoofer.exe',

  // Disk serial cleaners / volume ID changers
  'diskcleaner.exe', 'serialcleaner.exe',
  'tracecleaner.exe', 'logkiller.exe',

  // PC cleaning scripts (bat/ps1 launchers)
  'cleaner.bat', 'cleantraces.bat', 'wipeall.bat',
  'pc_clean.bat', 'beforecheck.bat',
  'clean_traces.ps1', 'wipe_pc.ps1',

  // RAGE MP specific cheat loaders
  'ragemp_loader.exe', 'rage_mp_cheat.exe', 'ragemp_hack.exe',
  'cef_injector.exe', 'cef_hook_loader.exe',
  'server_executor.exe', 'resource_injector.exe',
  'ragemp_spoofer.exe', 'rage_spoofer.exe',

  // ALT:V specific cheat tools
  'altv_executor.exe', 'altv_js_injector.exe', 'altv_dotnet_loader.exe',
  'altv_resource_dumper.exe', 'altv_client_hook.exe',
  'altv_bypass.exe', 'altv_esp.exe', 'altv_menu.exe',

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
  'stand.dll',  '2take1.dll', 'modest.dll', 'kiddions.dll',

  // Newer FiveM menus
  'susano.dll', 'lambda.dll', 'vmenu.dll',
  'absolute.dll', 'nightfall.dll', 'aurora.dll',
  'hydrogen.dll', 'oxide.dll', 'havoc.dll', 'revolution.dll',

  // 0xCheats / LeetCheats / Unicore / Vanish / Nightfall DLLs
  '0xcheats.dll', '0xcheat.dll', 'oxcheat.dll',
  'leetcheats.dll', 'leetcheat.dll', 'noleet.dll', 'noleetcheats.dll',
  'unicore.dll', 'unicoremenu.dll', 'unicorecheat.dll',
  'vanish.dll', 'vanishmenu.dll', 'vanishcheat.dll',
  'nightfall.dll', 'nightfallmenu.dll', 'nightfall_loader.dll',

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
  // DMA-related drivers
  'leechcore.dll', 'leechcore64.dll',
  'vmm.dll', 'vmm64.dll',
  'FTD3XX.dll', 'ftd2xx.dll',
  'ftdibus.sys', 'ftser2k.sys',
  // PCILeech specific
  'pcileech.dll', 'pcileech_core.dll',
  'leechcore.dll', 'leechsvc.dll',
  'fpga.dll', 'dma_access.dll',

  // RAGE MP cheat loaders (CEF-based + resource injectors)
  'ragemp_hook.dll', 'ragemp_inject.dll',
  'ragemp_menu.dll', 'ragemp_cheat.dll',
  'ragemp_bypass.dll', 'ragemp_loader.dll',
  'cef_hook.dll', 'cef_inject.dll',
  'server_inject.dll', 'resource_hook.dll',

  // ALT:V cheat modules (JS resources + .NET assemblies)
  'altv_cheat.dll', 'altv_menu.dll',
  'altv_inject.dll', 'altv_esp.dll',
  'altv_bypass.dll', 'altv_loader.dll',
  'altv_resource.dll', 'altv_client_hook.dll',

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
  'ragemp bypass', 'ragemp injector', 'ragemp loader',
  'rage mp cheat', 'rage mp hack',
  'server executor', 'resource injector',
  'cef exploit', 'cef devtools',
  'cef injector', 'cef hook', 'cef loader',
  'ragemp luas', 'ragemp scripts',
  // ALT:V cheats
  'altv cheat', 'altv hack', 'altv menu',
  'altv bypass', 'altv injector', 'altv loader',
  'altv executor', 'altv esp',
  'altv resource', 'altv client',
  'js executor', 'altv js', 'altv dotnet',
  'altv compiled', 'altv dumper',

  // DirectX masquerading cheat loaders
  // NOTE: potential FP on dev machines with DirectX documentation — use hash-only for zero-FP
  'dxwebsetup',

  // 0xCheats / LeetCheats / Unicore / Vanish / Nightfall folders
  '0xcheats', '0xcheat', 'oxcheat',
  'leetcheats', 'leetcheat', 'noleet', 'noleetcheats',
  '1337 cheat', '1337cheat', 'leet',
  'unicore', 'unicore menu', 'unicore cheat',
  'vanish', 'vanish menu', 'vanish cheat', 'vanish spoofer',
  'nightfall', 'nightfall menu', 'nightfall loader',
  'ownhacks', 'up-game', // Unicore resellers
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

  // FTDI FT601 USB driver (DMA bridge)
  B('ftdibus'), B('ftser2k'), B('ftd3xx'),
  B('ft601'), B('ft600'), B('ft2232'),

  // PCILeech memory acquisition
  B('leechcore'), B('pcileech'),
  B('vmm_dll'), B('memprocfs'),
  B('fpga_memory'), B('dma_device'),
  B('pcie_leech'), B('dma_attack'),

  // FPGA chip model strings (found in firmware/config)
  B('xc7a35t'), B('xc7a75t'), B('xc7a100t'), B('xc7a200t'),
  B('xilinx'), B('artix-7'), B('artix7'),
  B('kintex'), B('virtex'), B('spartan6'),

  // RAM disk / memory-only cheat storage
  B('imdisk'), B('ramdisk'), B('aimp'),
  B('softperfect'), B('osfmount'), B('primo'),

  // RAGE MP cheat signatures (CEF + resource injection)
  B('ragemp_hook'), B('ragemp_inject'),
  B('ragemp_menu'), B('ragemp_bypass'),
  B('cef_hook'), B('cef_devtools'),
  B('cef_injector'), B('cef_loader'),
  B('server_resource'), B('resource_inject'),
  B('server_executor'), B('resource_hook'),
  B('devtools_enabled'), B('cef_browser'),
  B('chromium_embedded'), B('remote_debugging'),

  // ALT:V cheat signatures (JS + .NET module injection)
  B('altv_cheat'), B('altv_menu'),
  B('altv_bypass'), B('altv_inject'),
  B('altv_resource'), B('altv_client_hook'),
  B('altv_js_executor'), B('altv_dotnet_inject'),
  B('altv_compiled_res'), B('altv_dumper'),
  B('altv_resource_injector'), B('altv_esp_loader'),

  // External cheat loader patterns
  // d3d11.dll is NOT here — too many false positives (legit games use DirectX)
  // Detected contextually via scanGameModules() platform whitelist mismatch

  // BYOVD / kernel mapper signatures
  B('kdmapper'), B('drvmap'), B('physmem'),
  B('rtcore'), B('gdrv'), B('capcom'), // vulnerable drivers
  B('iqvw64e'), B('nvoclock'), // exploited GPU drivers

  // Malware family: Gen:Variant.Barys — associated with masquerading cheat loaders (Falcon Sandbox)
  // NOTE: VMProtect strings NOT added here — already covered by SUSPICIOUS_CATEGORIES.obfuscator
  // and would cause FPs on legitimate software using VMProtect for copy protection.
  B('barys'),

  // NOTE: B('dxwebsetup') and B('DirectX Web Setup') are intentionally NOT added here
  // because the legitimate Microsoft DirectX Web Setup Installer also contains these strings.
  // Detection for this cheat relies on SHA256 hash only (filename detection would produce FPs).

  // 0xCheats / LeetCheats / Unicore / Vanish / Nightfall binary strings
  B('0xcheats'), B('oxcheat'), B('0xcheat'),
  B('leetcheats'), B('noleet'), B('leetcheat'),
  B('unicore'), B('unicoremenu'), B('unicorecheat'),
  B('vanish'), B('vanishmenu'), B('vanishcheat'),
  B('nightfall'), B('nightfallmenu'),
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
  'libegl.dll', 'libglesv2.dll',
  'd3dcompiler_47.dll', 'dxgi.dll', 'd3d11.dll',
  'socialclub.dll', 'steamclient64.dll',
  'bink2w64.dll', 'xinput1_4.dll',
  'mfplat.dll', 'mfreadwrite.dll',
])

export const ALTV_WHITELIST = new Set([
  'altv.exe', 'gta5.exe',
  'altv-client.dll', 'coreclr.dll', 'clrjit.dll',
  'hostfxr.dll', 'hostpolicy.dll',
  'v8.dll', 'v8_libbase.dll', 'v8_libplatform.dll',
  'node.dll', 'libnode.dll',
  'steamclient64.dll', 'socialclub.dll',
  'd3dcompiler_47.dll', 'dxgi.dll',
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
    path.join(HOME, 'AppData', 'Local', 'altv', 'data'),
    path.join(HOME, 'AppData', 'Roaming', 'altv'),

    // RAGE MP — client_packages (server resources injected client-side)
    path.join(PF, 'RAGEMP', 'client_packages'),
    path.join(PF86, 'RAGEMP', 'client_packages'),
    path.join(HOME, 'RAGEMP', 'client_packages'),

    // ALT:V — compiled JS resources (possible obfuscated cheats)
    path.join(HOME, 'AppData', 'Local', 'altv', 'resources', 'compiled'),

    // Common cheat directories
    path.join(HOME, 'Documents', 'Cheats'),
    path.join(HOME, 'Documents', 'Hacks'),
    path.join(HOME, 'Documents', 'Mods'),

    // Specific cheat config directories (research confirmed)
    path.join(HOME, 'AppData', 'Roaming', 'Nightfall'),
    path.join(HOME, 'AppData', 'Roaming', '0xCheats'),
    path.join(HOME, 'AppData', 'Roaming', 'Unicore'),
    path.join(HOME, 'AppData', 'Local', 'Nightfall'),

    // RAGE MP additional paths
    path.join(HOME, 'AppData', 'Roaming', 'RAGEMP', 'server-files'),
    path.join(HOME, 'AppData', 'Local', 'RAGEMP', 'server-files'),

    // ALT:V compiled resources (potential obfuscated cheats)
    path.join(HOME, 'AppData', 'Local', 'altv', 'client_packages'),

    // Recently opened files (prefetch-like)
    path.join(HOME, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent'),
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
  '.zip', '.rar', '.7z', '.msi', // Archives — need content scanning
])
