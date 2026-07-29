/**
 * Predator — Combo Detector
 *
 * Universal unsigned binary heuristic:
 * Flags suspicious unsigned .exe/.dll files by combining multiple weak signals
 * (entropy, string count, section count, file size, suspicious directory).
 *
 * Pure function — no side effects, no imports from heuristic or types.
 * Extracted from heuristic.ts for testability and modularity.
 */

/**
 * Score an unsigned binary file for combined suspicious signals.
 * Returns risk bonus and human-readable signals.
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
  if (ext !== '.exe' && ext !== '.dll') {
    return { signals: [], riskBonus: 0 }
  }

  if (sigValid) {
    return { signals: [], riskBonus: 0 }
  }

  let signalCount = 0
  const reasons: string[] = []

  const fpLow = filepath.toLowerCase()
  const inSuspiciousDir = fpLow.includes('downloads') || fpLow.includes('download') ||
    fpLow.includes('desktop') || fpLow.includes('temp') || fpLow.includes('загрузки')

  if (sizeBytes >= 5 * 1024 * 1024 && sizeBytes <= 100 * 1024 * 1024) {
    signalCount++
    reasons.push(`Strange size: ${(sizeBytes / 1024 / 1024).toFixed(1)} MB (unsigned binary of this size is unusual)`)
  }

  if (entropy > 7.0) {
    signalCount++
    reasons.push(`Entropy ${entropy.toFixed(2)} > 7.0 — packed/encrypted (VMProtect/Themida/obsufcation)`)
  }

  if (stringCount < 10) {
    signalCount++
    reasons.push(`Only ${stringCount} readable strings — fully obfuscated binary`)
  }

  if (inSuspiciousDir) {
    signalCount++
    reasons.push('Located in user directory (Downloads/Desktop/Temp)')
  }

  if (sectionCount >= 7) {
    signalCount++
    reasons.push(`${sectionCount} PE sections — typical for packed/VMProtected binaries (normal: 3–5)`)
  }

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
