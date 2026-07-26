/**
 * Predator — Shared constants
 * Extracted from scanner.ts (Priority 1 refactoring)
 */

import { getScanPaths } from './cheats-db'

// ═══════════════════════════════════════════════════
// CHEAT SOFTWARE NAMES
// ═══════════════════════════════════════════════════

export const CHEAT_SOFTWARE_NAMES: Record<string, string[]> = {
  'Nightfall': ['nightfall', 'nightfall cheat', 'nightfall loader'],
  'DMA': ['dma', 'dma card', 'dma cheat', 'dma firmware'],
  '0XCheat': ['0xcheat', '0x cheat', 'oxcheat'],
  '1337 Cheat': ['1337', '1337 cheat', 'leet cheat'],
  'NoleetCheats': ['noleet', 'noleetcheats', 'noleet cheat'],
}

// ═══════════════════════════════════════════════════
// EXTENDED CHEAT KEYWORDS
// ═══════════════════════════════════════════════════

export const EXTENDED_CHEAT_KEYWORDS: string[] = [
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
  'inject', 'hook', 'bypass', 'obfuscator', 'vmprotect',
  'themida', 'enigma protector', 'obsidium',
  'eac bypass', 'battleye bypass', 'vanguard bypass',
  'faceit bypass', 'esportal bypass',
  'process hollowing', 'reflective dll',
  'kill process', 'protect process', 'hide process',
]

// ═══════════════════════════════════════════════════
// EXTENDED SCAN PATHS
// ═══════════════════════════════════════════════════

export const EXTENDED_SCAN_PATHS: string[] = getScanPaths()
