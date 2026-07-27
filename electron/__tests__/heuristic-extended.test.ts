/**
 * Predator — Heuristic Extended Tests
 *
 * Additional tests for pure heuristic functions NOT covered by the existing test file:
 *   - comboScoreUnsignedBinary()     — universal unsigned binary detector
 *   - getFileRiskLevel()             — file risk classification
 *   - isSkippableExtension()         — noise file filtering
 *   - isKnownElectronDll()           — Electron DLL whitelist
 */
import { describe, it, expect } from 'vitest'
import {
  comboScoreUnsignedBinary,
  getFileRiskLevel,
  isSkippableExtension,
  isKnownElectronDll,
} from '../heuristic'

// ═══════════════════════════════════════════════════════
// comboScoreUnsignedBinary
// ═══════════════════════════════════════════════════════

describe('comboScoreUnsignedBinary', () => {
  // ── Extension whitelist ──

  it('returns zero risk for non-binary extensions (.txt, .png, .js)', () => {
    for (const ext of ['.txt', '.png', '.js', '.lua', '.bat']) {
      const result = comboScoreUnsignedBinary(ext, 10_000_000, 7.5, 5, 'C:\\Downloads\\file' + ext, 8, false)
      expect(result.riskBonus).toBe(0)
      expect(result.signals).toEqual([])
    }
  })

  it('returns zero risk for signed binaries', () => {
    const result = comboScoreUnsignedBinary('.exe', 10_000_000, 7.5, 5, 'C:\\Downloads\\unsigned.exe', 8, true)
    expect(result.riskBonus).toBe(0)
  })

  // ── Strong signals (70 bonus) ──

  it('returns 70 risk with 2+ signals and 1+ strong signal (high entropy)', () => {
    // Signal 1: size 5-100MB ✓
    // Signal 2: entropy > 7.0 ✓ (strong)
    // Signal 3: in Downloads dir ✓
    const result = comboScoreUnsignedBinary('.exe', 10_000_000, 7.8, 50, 'C:\\Downloads\\packed.exe', 5, false)
    expect(result.riskBonus).toBe(70)
    expect(result.signals.length).toBeGreaterThanOrEqual(2)
  })

  it('returns 70 risk with 2+ signals and 1+ strong signal (low strings)', () => {
    // Signal 1: size 5-100MB ✓
    // Signal 2: stringCount < 10 ✓ (strong)
    const result = comboScoreUnsignedBinary('.exe', 8_000_000, 6.0, 3, 'C:\\Downloads\\obfuscated.exe', 5, false)
    expect(result.riskBonus).toBe(70)
  })

  it('returns 70 risk with 2+ signals and 1+ strong signal (many sections)', () => {
    // Signal 1: size 5-100MB ✓
    // Signal 2: sectionCount >= 7 ✓ (strong)
    const result = comboScoreUnsignedBinary('.dll', 6_000_000, 6.0, 50, 'C:\\Temp\\packed.dll', 8, false)
    expect(result.riskBonus).toBe(70)
  })

  // ── Medium signal (40 bonus) ──

  it('returns 40 risk for single signal + suspicious directory', () => {
    // Signal 1: in Temp dir ✓ (suspiciousDir)
    // Only ONE real signal
    const result = comboScoreUnsignedBinary('.exe', 500_000, 5.0, 100, 'C:\\Temp\\small.exe', 5, false)
    expect(result.riskBonus).toBe(40)
  })

  // ── Low signal (15 bonus) ──

  it('returns 15 risk for single signal only (entropy)', () => {
    const result = comboScoreUnsignedBinary('.exe', 500_000, 7.1, 100, 'C:\\Program Files\\test.exe', 5, false)
    expect(result.riskBonus).toBe(15)
  })

  // ── Zero signals ──

  it('returns zero risk for small unsigned binary in trusted location', () => {
    const result = comboScoreUnsignedBinary('.exe', 500_000, 5.0, 100, 'C:\\Program Files\\App\\app.exe', 4, false)
    expect(result.riskBonus).toBe(0)
    expect(result.signals).toEqual([])
  })

  // ── Edge cases ──

  it('handles zero-size files correctly', () => {
    // Size 0, stringCount 0 (< 10 = strong signal), in Downloads = suspiciousDir
    // signalCount >= 2 + strongSignals >= 1 → returns 70
    const result = comboScoreUnsignedBinary('.exe', 0, 0, 0, 'C:\\Downloads\\empty.exe', 1, false)
    expect(result.riskBonus).toBe(70)
  })

  it('handles extremely large files (over 100MB)', () => {
    const result = comboScoreUnsignedBinary('.exe', 200_000_000, 7.5, 50, 'C:\\Downloads\\huge.exe', 5, false)
    // Size > 100MB → doesn't match 5-100MB signal
    // But entropy > 7.0 → strong signal
    // Only 1 real signal → 15 bonus (or 40 if in Downloads)
    expect(result.riskBonus).toBeGreaterThanOrEqual(15)
  })

  it('handles minimum boundary: exactly 5MB file size', () => {
    // 5MB exactly, entropy 6.5 (not >7.0), strings 50 (not <10), 5 sections (not >=7)
    // in Temp dir = suspiciousDir
    // signalCount = 2 (size + temp), strongSignals = 0
    // Code: signalCount>=2 && strongSignals>=1 → no (strong 0)
    // signalCount==1 && inSuspiciousDir → no (signalCount is 2)
    // signalCount==1 → no
    // Returns 0
    const result = comboScoreUnsignedBinary('.exe', 5_242_880, 6.5, 50, 'C:\\Temp\\border.exe', 5, false)
    expect(result.riskBonus).toBe(0)
  })

  it('does not flag .dll files with valid signatures', () => {
    const result = comboScoreUnsignedBinary('.dll', 10_000_000, 7.8, 5, 'C:\\Downloads\\weird.dll', 8, true)
    expect(result.riskBonus).toBe(0)
    expect(result.signals).toEqual([])
  })
})

// ═══════════════════════════════════════════════════════
// getFileRiskLevel
// ═══════════════════════════════════════════════════════

describe('getFileRiskLevel', () => {
  it('returns "high" for .exe with high-risk keyword matches', () => {
    expect(getFileRiskLevel('injector.exe', ['injector'])).toBe('high')
    expect(getFileRiskLevel('aimbot.exe', ['aimbot'])).toBe('high')
    expect(getFileRiskLevel('dma-card.exe', ['dma'])).toBe('high')
  })

  it('returns "high" for any extension with 3+ matches', () => {
    expect(getFileRiskLevel('test.js', ['match1', 'match2', 'match3'])).toBe('high')
  })

  it('returns "medium" for .exe/dll/sys without high-risk keywords', () => {
    expect(getFileRiskLevel('legit.exe', ['unknown-match'])).toBe('medium')
    expect(getFileRiskLevel('driver.sys', [])).toBe('medium')
  })

  it('returns "medium" for .asi/lua/js files with 2+ matches', () => {
    expect(getFileRiskLevel('script.lua', ['match1', 'match2'])).toBe('medium')
  })

  it('returns "low" for benign .txt file with one match', () => {
    expect(getFileRiskLevel('readme.txt', ['match1'])).toBe('low')
  })

  it('returns "low" for files with no extension and no matches', () => {
    expect(getFileRiskLevel('noext', [])).toBe('low')
  })

  it('returns "medium" for typical executable filenames (.exe always >= medium)', () => {
    // Any .exe with no matches is classified as 'medium' (binary executable)
    expect(getFileRiskLevel('notepad.exe', [])).toBe('medium')
    // Non-executable benign files return 'low'
    expect(getFileRiskLevel('document.pdf', [])).toBe('low')
  })
})

// ═══════════════════════════════════════════════════════
// isSkippableExtension
// ═══════════════════════════════════════════════════════

describe('isSkippableExtension', () => {
  it('returns true for asset files (.png, .jpg, .svg, .mp4)', () => {
    expect(isSkippableExtension('photo.png')).toBe(true)
    expect(isSkippableExtension('banner.jpg')).toBe(true)
    expect(isSkippableExtension('icon.svg')).toBe(true)
    expect(isSkippableExtension('video.mp4')).toBe(true)
  })

  it('returns true for font files (.woff, .ttf, .otf)', () => {
    expect(isSkippableExtension('font.woff')).toBe(true)
    expect(isSkippableExtension('font.woff2')).toBe(true)
    expect(isSkippableExtension('font.ttf')).toBe(true)
    expect(isSkippableExtension('font.otf')).toBe(true)
  })

  it('returns true for map and sourcemap files (.map, .js.map, .css.map)', () => {
    expect(isSkippableExtension('bundle.js.map')).toBe(true)
    expect(isSkippableExtension('app.css.map')).toBe(true)
  })

  it('returns false for .d.ts files (path.extname returns .ts, not .d.ts)', () => {
    // path.extname('types.d.ts') returns '.ts', which is NOT skippable
    expect(isSkippableExtension('types.d.ts')).toBe(false)
  })

  it('returns true for audio files (.mp3, .wav, .ogg)', () => {
    expect(isSkippableExtension('song.mp3')).toBe(true)
    expect(isSkippableExtension('sound.wav')).toBe(true)
    expect(isSkippableExtension('voice.ogg')).toBe(true)
  })

  it('returns true for .bin and .dat files', () => {
    expect(isSkippableExtension('data.bin')).toBe(true)
    expect(isSkippableExtension('config.dat')).toBe(true)
  })

  it('returns false for executable files (.exe, .dll, .asi)', () => {
    expect(isSkippableExtension('program.exe')).toBe(false)
    expect(isSkippableExtension('library.dll')).toBe(false)
    expect(isSkippableExtension('mod.asi')).toBe(false)
  })

  it('returns false for script files (.js, .lua, .bat)', () => {
    expect(isSkippableExtension('loader.js')).toBe(false)
    expect(isSkippableExtension('cheat.lua')).toBe(false)
    expect(isSkippableExtension('run.bat')).toBe(false)
  })

  it('returns false for archive files (.zip, .rar, .7z)', () => {
    expect(isSkippableExtension('archive.zip')).toBe(false)
  })

  it('is case-insensitive', () => {
    expect(isSkippableExtension('PHOTO.PNG')).toBe(true)
    expect(isSkippableExtension('PROGRAM.EXE')).toBe(false)
  })

  it('handles files with no extension', () => {
    expect(isSkippableExtension('Makefile')).toBe(false)
    expect(isSkippableExtension('README')).toBe(false)
  })
})

// ═══════════════════════════════════════════════════════
// isKnownElectronDll
// ═══════════════════════════════════════════════════════

describe('isKnownElectronDll', () => {
  it('returns true for known Electron DLLs', () => {
    expect(isKnownElectronDll('d3dcompiler_47.dll')).toBe(true)
    expect(isKnownElectronDll('ffmpeg.dll')).toBe(true)
    expect(isKnownElectronDll('libegl.dll')).toBe(true)
    expect(isKnownElectronDll('libglesv2.dll')).toBe(true)
    expect(isKnownElectronDll('vk_swiftshader.dll')).toBe(true)
  })

  it('returns true for known Electron executables', () => {
    expect(isKnownElectronDll('elevate.exe')).toBe(true)
    expect(isKnownElectronDll('7zr.exe')).toBe(true)
  })

  it('returns false for unknown DLLs', () => {
    expect(isKnownElectronDll('malicious.dll')).toBe(false)
    expect(isKnownElectronDll('inject.dll')).toBe(false)
  })

  it('is case-insensitive', () => {
    expect(isKnownElectronDll('FFMPEG.DLL')).toBe(true)
    expect(isKnownElectronDll('D3DCompiler_47.dll')).toBe(true)
  })

  it('returns false for empty string', () => {
    expect(isKnownElectronDll('')).toBe(false)
  })
})
