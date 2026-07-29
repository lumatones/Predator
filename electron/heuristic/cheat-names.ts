/**
 * Predator — Shared Cheat Name Arrays
 *
 * Pre-normalized arrays for fast substring matching, used by matchKnownCheat
 * and scanArchiveContents. Extracted from heuristic.ts to avoid circular deps.
 */
import {
  KNOWN_PROCESSES,
  KNOWN_CHEAT_FILES,
  KNOWN_LUA_SCRIPTS,
  KNOWN_CHEAT_FOLDERS,
} from '../cheats-db'

export const PROC_BASES = KNOWN_PROCESSES.map(n =>
  n.toLowerCase()
    .replace(/\.exe$/i, '')
    .replace(/_\*\.exe$/i, '')
    .replace(/\*\.exe$/i, ''),
)
export const FILE_NAMES = KNOWN_CHEAT_FILES.map(n => n.toLowerCase())
export const LUA_NAMES = KNOWN_LUA_SCRIPTS.map(n => n.toLowerCase())
export const FOLDER_NAMES = KNOWN_CHEAT_FOLDERS.map(n => n.toLowerCase())
