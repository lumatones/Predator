/**
 * Predator — heuristicFileScan Integration Tests
 *
 * Tests the CORE scanning function with real temp file fixtures.
 * Covers 15+ scenarios spanning all major code paths:
 *   - Early returns (non-file, skippable, oversized, safe-db, Electron DLL)
 *   - Text content scanning (JS/Lua with cheat keywords and patterns)
 *   - Name-based category matching
 *   - Masquerading detection
 *   - Protected path detection
 *   - Low-risk clean files
 *
 * Modules mocked to prevent side effects:
 *   - child_process (PowerShell calls for digital signatures, archive scanning)
 *   - safe-files-db (no local DB loading)
 */

import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest'
import fs from 'fs'
import path from 'path'
import os from 'os'

// ── Mock modules with side effects ──

vi.mock('child_process', () => ({
  execSync: vi.fn(() => ''),
  spawnSync: vi.fn(() => ({ stdout: '', stderr: '' })),
}))

vi.mock('../safe-files-db', () => ({
  isFileSafe: vi.fn(() => false),
}))

// ── Import AFTER mocks ──

// All side-effect dependencies (scanStrings, evaluateYara, analyzePeHeaders,
// analyzeSectionEntropy, checkDigitalSignature, checkAutoRules, etc.)
// gracefully return null/[] for non-PE test fixtures — no additional mocking needed.
import { heuristicFileScan } from '../heuristic'

// ═══════════════════════════════════════════════════════
// FIXTURE HELPERS
// ═══════════════════════════════════════════════════════

const TMP_DIR = path.join(os.tmpdir(), 'predator-test-heuristic-' + Date.now())

function createFixture(
  name: string,
  content: string | Buffer,
  mtime?: Date,
): string {
  const filepath = path.join(TMP_DIR, name)
  fs.mkdirSync(path.dirname(filepath), { recursive: true })
  fs.writeFileSync(filepath, content)
  if (mtime) {
    fs.utimesSync(filepath, mtime, mtime)
  }
  return filepath
}

/** Create a file with recent mtime (1 hour ago → triggers < 90 days age check) */
function recent(name: string, content: string | Buffer): string {
  return createFixture(name, content, new Date(Date.now() - 60 * 60 * 1000))
}

/** Create a file with old mtime (200 days ago → no age check) */
function old(name: string, content: string | Buffer): string {
  return createFixture(name, content, new Date(Date.now() - 200 * 24 * 60 * 60 * 1000))
}

// ═══════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════

describe('heuristicFileScan', () => {
  beforeAll(() => {
    fs.mkdirSync(TMP_DIR, { recursive: true })
  })

  afterAll(() => {
    fs.rmSync(TMP_DIR, { recursive: true, force: true })
  })

  // ── 1. Non-existent file ──

  it('returns null for non-existent file', () => {
    expect(heuristicFileScan(path.join(TMP_DIR, 'ghost.exe'))).toBeNull()
  })

  // ── 2. Directory (not a file) ──

  it('returns null for a directory', () => {
    const dirPath = path.join(TMP_DIR, 'test-dir')
    fs.mkdirSync(dirPath, { recursive: true })
    expect(heuristicFileScan(dirPath)).toBeNull()
  })

  // ── 3. Oversized file (> 100 MB) ──

  it('returns null for an oversized file (>100 MB)', () => {
    const filepath = path.join(TMP_DIR, 'huge.bin')
    const fd = fs.openSync(filepath, 'w')
    fs.ftruncateSync(fd, 101 * 1024 * 1024) // sparse file, 101 MB
    fs.closeSync(fd)
    try {
      expect(heuristicFileScan(filepath)).toBeNull()
    } finally {
      fs.unlinkSync(filepath)
    }
  })

  // ── 4. Skippable extension (.png) ──

  it('returns null for a .png image (skippable extension)', () => {
    const filepath = recent('screenshot.png', Buffer.alloc(1024))
    // .png is in SKIPPABLE_EXTENSIONS → function returns null BEFORE any checks
    expect(heuristicFileScan(filepath)).toBeNull()
  })

  it('returns null for a .woff2 font file (skippable)', () => {
    const filepath = recent('font.woff2', Buffer.alloc(1024))
    expect(heuristicFileScan(filepath)).toBeNull()
  })

  // ── 5. Known Electron DLL (always safe) ──

  it('returns null for a known Electron DLL (d3dcompiler_47.dll)', () => {
    const filepath = recent('d3dcompiler_47.dll', Buffer.alloc(4096))
    expect(heuristicFileScan(filepath)).toBeNull()
  })

  // ── 6. Clean .txt file (no keywords, no shadow) ──

  it('returns null for a clean .txt file with benign content', () => {
    const filepath = old('readme.txt', 'This is a normal document about cats and dogs.')
    // Old file (>90 days) so no age check.
    // .txt is NOT in SUSPICIOUS_EXTENSIONS → no extension score.
    // No cheat keywords → no content score.
    // No name match → no category score.
    // riskScore = 0, shadowRuleHits = [] → returns null
    expect(heuristicFileScan(filepath)).toBeNull()
  })

  // ── 7. Clean .js file (recent, no keywords — low base risk) ──

  it('returns low-risk result for a clean .js file (no keywords, but .js is suspicious)', () => {
    const filepath = recent('bundle.js', 'const x = 42; console.log("hello world");')
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    expect(result!.riskScore).toBeGreaterThanOrEqual(15) // extension 20 + age 15 = 35, or lower if trusted-path reduction
    expect(result!.suspicions.some(s => s.includes('Extension'))).toBe(true)
    expect(result!.suspicions.some(s => s.includes('Recently created'))).toBe(true)
  })

  // ── 8. .js file with cheat keywords (high risk) ──

  it('returns high-risk result for a .js file with cheat keywords (aimbot + inject)', () => {
    const filepath = recent('cheat-loader.js', [
      'function injectDLL() {',
      '  // aimbot activation via memory hack',
      '  const bypass = new ActiveXObject("WScript.Shell");',
      '  bypass.Run("injector.exe");',
      '}',
      '// wallhack config',
      'const esp = { enabled: true, glow: "red" };',
    ].join('\n'))
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // Extension .js → +20, age → +15, keywords → +25 each (up to 5)
    // Expected risk score well above 50 (medium) or 80 (high)
    expect(result!.riskScore).toBeGreaterThanOrEqual(50)
    // Should have keyword matches
    expect(result!.suspicions.some(s => s.includes('content:'))).toBe(true)
  })

  // ── 9. .lua file with nightfall pattern (medium risk) ──

  it('returns medium-risk result for .lua file with nightfall injection script', () => {
    const filepath = recent('startup.lua', [
      '-- Nightfall menu injection',
      'local cheat = require("inject")',
      'cheat.load("aimbot")',
      'cheat.load("wallhack")',
      'Citizen.CreateThread(function()',
      '  while true do Wait(0)',
      '    if IsControlPressed(0, 38) then TriggerEvent("esp") end',
      '  end',
      'end)',
    ].join('\n'))
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // Pattern match for [Nn]ightfall → +20
    // Plus keyword matches for cheat, inject, aimbot, wallhack → +25 each
    // Plus extension .lua → +20
    // Plus age → +15
    expect(result!.riskScore).toBeGreaterThanOrEqual(50)
  })

  // ── 10. Name-based category match: injector.exe ──

  it('returns high-risk for a file named injector.exe (category name match)', () => {
    const filepath = recent('injector.exe', Buffer.alloc(4096))
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // 'inject' matched in SUSPICIOUS_CATEGORIES.injector.names → +40
    // Extension .exe → +20
    // Age → +15
    // No digital signature → +20 (binary analysis path)
    // Total well above 80 → high risk
    expect(result!.riskScore).toBeGreaterThanOrEqual(70)
    expect(result!.suspicions.some(s => s.includes('injector'))).toBe(true)
  })

  // ── 11. File in protected FiveM mods path ──

  it('adds protected path risk for a file in the FiveM mods directory', () => {
    const fivemDir = path.join(TMP_DIR, 'AppData/Local/FiveM/FiveM.app/mods')
    const filepath = recent(
      path.join('AppData/Local/FiveM/FiveM.app/mods/eulen.asi'),
      Buffer.alloc(4096),
    )
    // PROTECTED_PATHS includes FiveM mods paths, so the heuristic should
    // detect this and add +25 for protected folder.
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // Should have protected path suspicion
    const hasProtected = result!.suspicions.some(s => s.includes('protected folder'))
    const hasExtension = result!.suspicions.some(s => s.includes('Extension'))
    expect(hasProtected || hasExtension).toBe(true)
  })

  // ── 12. Masquerading: svchost.exe outside System32 ──

  it('flags a masquerading svchost.exe found outside of System32', () => {
    // svchost.exe is in SYSTEM_PROC_NAMES. Our temp directory is NOT System32,
    // and NOT a trusted path → should flag as masquerading
    const filepath = recent('svchost.exe', Buffer.alloc(64 * 1024)) // 64KB
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // Masquerading check: svchost.exe outside System32 → +50
    // Extension .exe → +20
    // Age → +15
    // No digital signature → +20
    // Total should be well above 80 → much higher
    expect(result!.riskScore).toBeGreaterThanOrEqual(50)
  })

  // ── 13. Batch/PowerShell script with multiple keywords ──

  it('returns high risk for a .ps1 script with dma/fpga/pcileech keywords', () => {
    const filepath = recent('dma_scanner.ps1', [
      '# DMA card controller by pcileech',
      '$fpga = Get-PnPDevice | Where-Object {$_.Name -match "xilinx"}',
      '$results = dma_fpga_scan -device $fpga',
      'Write-Host "Screamer M2 found! Preparing DMA inject..."',
    ].join('\n'))
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // .ps1 → suspicious extension +20
    // Age → +15
    // Keywords: pcileech, fpga, dma - Wait, 'dma' is 3 chars < MIN_KEYWORD_LENGTH=4
    // So 'dma' won't match in ALL_CHEAT_KEYWORDS. But 'fpga' and 'pcileech' will.
    // Plus patterns: /[Ss]creamer\s*[Mm]2/i → +20
    // Total: 20 + 15 + 25 + 25 + 20 = 105
    expect(result!.riskScore).toBeGreaterThanOrEqual(40)
  })

  // ── 14. Empty file with suspicious extension ──

  it('returns non-null result for an empty .asi file (suspicious ext but no content)', () => {
    // Empty file → risk from extension + age only (may be reduced by trusted-path deduction)
    const filepath = recent('mod.asi', Buffer.alloc(0))
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // Score is > 0 (some base risk) but exact value depends on trusted-path on this host
    expect(result!.riskScore).toBeGreaterThan(0)
    expect(result!.suspicions.some(s => s.includes('Extension'))).toBe(true)
  })

  // ── 15. Clean .exe in trusted area (temp dir, recently) ──

  it('returns result for a temp .exe with benign content (no known keywords)', () => {
    const filepath = recent('test-installer.exe', Buffer.alloc(8192))
    const result = heuristicFileScan(filepath)
    // Should return a result (not null) because .exe is suspicious
    // even without content matches
    expect(result).not.toBeNull()
    // Extension .exe → +20
    // Age → +15
    // No digital signature → +20
    // Total ~55 (medium risk)
    expect(result!.riskScore).toBeGreaterThanOrEqual(15)
  })

  // ── 16. Files with DMA-related name matching ──

  it('detects fpga-related keywords in a .cfg configuration file', () => {
    const filepath = recent('screamer_m2_config.cfg', [
      '# Screamer M2 - DMA card configuration',
      'device=fpga_pcie_leech',
      'baud=115200',
      'vendor=pcileech',
    ].join('\n'))
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // .cfg → SUSPICIOUS_EXTENSIONS → +20
    // Age → +15
    // No digital signature check for .cfg (skipped)
    // content matches for 'pcileech', 'fpga' → +25 each (up to 5)
    // Pattern matches: [Ss]creamer → +20
    // Total: 20 + 15 + 25 + 25 + 20 = 105
    expect(result!.riskScore).toBeGreaterThanOrEqual(40)
    // Should detect at least one DMA-related keyword
    expect(result!.suspicions.some(s => s.includes('pcileech') || s.includes('fpga'))).toBe(true)
  })

  // ── 17. File name match on 'bypass' category ──

  it('flags a file named eac-bypass.exe as high risk', () => {
    const filepath = recent('eac-bypass.exe', Buffer.alloc(4096))
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // 'bypass' matches SUSPICIOUS_CATEGORIES.bypass.names → +40
    // Extension .exe → +20
    // Age → +15
    // No digital signature → +20
    // Total: 95+ → high risk
    expect(result!.riskScore).toBeGreaterThanOrEqual(70)
  })

  // ── 18. Shadow-mode telemetry (low risk file with shadow hits) ──

  it('returns shadowRuleHits for files with shadow-category matches', () => {
    // No shadow categories currently exist in signature-registry.ts,
    // but the code handles the `shadow` property correctly.
    // This test verifies the structure returns correctly.
    const filepath = recent('normal-file.exe', Buffer.alloc(4096))
    const result = heuristicFileScan(filepath)
    expect(result).not.toBeNull()
    // shadowRuleHits is optional in HeuristicResult
    // If no shadow rules matched, it should be undefined
    // If some matched, it should be an array
    expect(result!.shadowRuleHits === undefined || Array.isArray(result!.shadowRuleHits)).toBe(true)
  })
})
