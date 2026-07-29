/**
 * Predator — Masquerading Executable Detection
 *
 * Detects executables that masquerade as legitimate Windows system processes
 * (e.g., svchost.exe, lsass.exe, csrss.exe) but are located outside System32.
 *
 * Pure function — no side effects, no heuristic imports.
 * Extracted from heuristic.ts for testability and modularity.
 */

import path from 'path'
import type { Stats } from 'fs'
import { MASQUERADING_FILENAMES } from '../cheats-db'
import { isTrustedPath } from '../cheat-rules'
import type { PeAnalysisResult, SectionEntropy } from '../cheat-rules'
import { _WR } from '../types'

/**
 * Check if a file is masquerading as a legitimate Windows system process.
 *
 * High-level logic:
 * 1. Filename must be in MASQUERADING_FILENAMES (known target names)
 * 2. If in System32 AND it's a known Windows system file → NOT masquerading
 * 3. If digitally signed → likely legitimate (unless packed)
 * 4. Multiple signals: no signature, many PE sections, high entropy, stripped relocs
 *
 * @returns Object with isMasquerading flag and human-readable signals
 */
export function checkMasqueradingExecutable(
  fileName: string,
  filepath: string,
  stat: Stats,
  peInfo: PeAnalysisResult | null,
  secEntropy: SectionEntropy[],
  entropy: number,
  sigValid: boolean,
): { isMasquerading: boolean; signals: string[] } {
  const signals: string[] = []
  const lowerName = fileName.toLowerCase()

  if (!MASQUERADING_FILENAMES.has(lowerName)) {
    return { isMasquerading: false, signals }
  }

  signals.push(`Filename matches masquerading target: ${fileName}`)

  const systemPaths = [
    path.join(_WR, 'System32').toLowerCase(),
    path.join(_WR, 'SysWOW64').toLowerCase(),
    path.join(_WR).toLowerCase(),
  ]
  const fpLower = filepath.toLowerCase()
  const inSystemDir = systemPaths.some(p => fpLower.startsWith(p))

  if (inSystemDir) {
    const winSysFiles = new Set(['conhost.exe', 'rundll32.exe', 'svchost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe', 'explorer.exe', 'notepad.exe'])
    if (winSysFiles.has(lowerName)) {
      signals.push(`Located in System32 — legitimate Windows component, not flagged`)
      return { isMasquerading: false, signals }
    }
  }

  if (sigValid) {
    signals.push(`Has valid digital signature — likely legitimate version`)
    if (entropy > 7.0 || (peInfo && peInfo.sectionCount >= 7)) {
      signals.push('But file is packed/obfuscated despite valid signature — suspicious')
    } else {
      return { isMasquerading: false, signals }
    }
  } else {
    signals.push('No digital signature — legitimate versions of this software ALWAYS have one')
  }

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

  if (secEntropy.length > 0) {
    const highEntropySections = secEntropy.filter(s => s.entropy > 7.5)
    for (const sec of highEntropySections) {
      signals.push(`Section [${sec.name}] entropy ${sec.entropy.toFixed(2)} > 7.5 — packed`)
    }
  }

  if (entropy > 7.2) {
    signals.push(`Overall entropy ${entropy.toFixed(2)} > 7.2 — packed/encrypted`)
  }

  if (stat.size >= 15 * 1024 * 1024 && stat.size <= 35 * 1024 * 1024) {
    signals.push(`File size ${(stat.size / 1024 / 1024).toFixed(1)} MB — matches masquerading loader range`)
  }

  return { isMasquerading: signals.length >= 2, signals }
}
