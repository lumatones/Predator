/**
 * Predator — Heuristic Constants
 *
 * Extracted from heuristic.ts. Pure data — no logic, no imports from parent.
 *
 * Modules that used these from heuristic.ts continue to import from '../heuristic'
 * (the barrel re-exports everything).
 */

import path from 'path'
import { _PF, _PF86, _HOME, _WR } from '../types'

// ═══════════════════════════════════════════════════
// SUSPICIOUS EXTENSIONS
// ═══════════════════════════════════════════════════

export const SUSPICIOUS_EXTENSIONS: Record<string, string> = {
  '.dll': 'Dynamic library (possible inject)',
  '.asi': 'ASI mod GTA (game modification)',
  '.lua': 'Lua script (often used in cheats)',
  '.luac': 'Compiled Lua script',
  '.exe': 'Executable file',
  '.sys': 'System driver',
  '.cfg': 'Configuration file',
  '.ini': 'Configuration file',
  '.js': 'JavaScript (may contain cheat loader)',
  '.ahk': 'AutoHotkey script',
  '.zip': 'Archive (may contain cheat files)',
  '.rar': 'Archive (may contain cheat files)',
  '.7z': 'Archive (may contain cheat files)',
  '.msi': 'Installer (may contain cheat)',
}

// ═══════════════════════════════════════════════════
// NOISE FILTERS
// ═══════════════════════════════════════════════════

/** Known Electron/Chromium DLLs bundled unsigned with Electron apps. Never flag these. */
export const KNOWN_ELECTRON_DLLS = new Set([
  'd3dcompiler_47.dll', 'ffmpeg.dll', 'libegl.dll', 'libglesv2.dll',
  'vk_swiftshader.dll', 'vulkan-1.dll', 'vulkaninfo.exe',
  'elevate.exe', 'nsis7z.dll', 'nsprocess.dll', 'stdutils.dll',
  'system.dll', '7zr.exe',
])

/** Extensions to skip entirely (noise files with no cheat value). */
export const SKIPPABLE_EXTENSIONS = new Set([
  '.d.ts', '.d.ts.map', '.js.map', '.css.map', '.map',
  '.tsbuildinfo', '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp', '.webp',
  '.mp4', '.mp3', '.wav', '.ogg', '.flac', '.avi', '.mkv', '.mov',
  '.pak', '.bin', '.dat',
])

// ═══════════════════════════════════════════════════
// SCAN CONFIG
// ═══════════════════════════════════════════════════

export const SCAN_CONFIG = {
  SCAN_DEPTH: 3,
  MAX_FILE_SIZE: 100 * 1024 * 1024,
  MIN_FILE_SIZE: 0,
  SUSPICIOUS_AGE_DAYS: 90,
  ENTROPY_THRESHOLD: 7.5,
}

// ═══════════════════════════════════════════════════
// PROTECTED PATHS
// ═══════════════════════════════════════════════════

/** Protected paths — game mod directories where files should not be */
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

// ═══════════════════════════════════════════════════
// SYSTEM PROCESS NAMES
// ═══════════════════════════════════════════════════

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
