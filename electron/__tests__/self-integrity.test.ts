/**
 * Predator — Self-Integrity Unit Tests
 *
 * Covers the security-critical baseline logic:
 *   1. compareVersions (semver comparison for update-vs-tamper detection)
 *   2. verifySelfExeIntegrity first-run (server match / mismatch / TOFU)
 *   3. Version-change branch (legit bump + server confirm → rebase;
 *      server mismatch → critical + tamper response; downgrade → high)
 *   4. TOFU re-verification on later runs (poisoned baseline self-heals)
 *   5. Repeated tampering escalation → criticalTamperResponse
 */

import { describe, it, expect, vi, beforeAll, beforeEach, afterAll } from 'vitest'
import fs from 'fs'
import http from 'http'
import path from 'path'
import crypto from 'crypto'

// ── Mockable state (vi.hoisted: usable inside hoisted vi.mock factories) ──
const MOCK = vi.hoisted(() => {
  // vi.hoisted runs before imports — only require() works here (Node builtins)
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const osMod = require('os')
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pathMod = require('path')
  const userData = pathMod.join(osMod.tmpdir(), 'predator-test-self-integrity')
  return {
    userData,
    exePath: pathMod.join(userData, 'Predator-test.exe'),
    version: '0.4.5',
    apiBase: 'http://127.0.0.1:3001',
    hashMap: {} as Record<string, string>, // version → sha256 (missing = 404)
    tamperResponse: vi.fn(),
  }
})

vi.mock('electron', () => ({
  app: {
    getPath: vi.fn((key: string) => (key === 'userData' ? MOCK.userData : MOCK.exePath)),
    getVersion: vi.fn(() => MOCK.version),
  },
}))

vi.mock('../config', () => ({
  getApiBase: () => MOCK.apiBase,
}))

vi.mock('../self-protect', () => ({
  criticalTamperResponse: MOCK.tamperResponse,
}))

// Module under test — import AFTER mocks are registered
import { compareVersions, verifySelfExeIntegrity } from '../self-integrity'

// ── Helpers ──────────────────────────────────────
const INTEGRITY_FILE = path.join(MOCK.userData, '.predator_integrity')
const MIN_EXE = 1024 * 1024 + 256 // > MIN_EXE_SIZE (1 MB)
const STALE = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString() // > 24h TOFU throttle

/** Write a fake exe of MIN_EXE bytes with a tunable filler byte → unique hash. */
function writeExe(filler: number): string {
  const buf = Buffer.alloc(MIN_EXE, filler)
  fs.writeFileSync(MOCK.exePath, buf)
  return crypto.createHash('sha256').update(buf).digest('hex')
}

function hashOfFile(filepath: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(filepath)).digest('hex')
}

function writeBaseline(state: Record<string, unknown>): void {
  fs.writeFileSync(INTEGRITY_FILE, JSON.stringify(state), 'utf-8')
}

function readBaseline(): Record<string, unknown> | null {
  try {
    return JSON.parse(fs.readFileSync(INTEGRITY_FILE, 'utf-8'))
  } catch { return null }
}

// ── Local hash server ─────────────────────────────
let server: http.Server

function serveHash(res: http.ServerResponse, version: string) {
  const hash = MOCK.hashMap[version]
  if (!hash) {
    res.writeHead(404)
    res.end()
    return
  }
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify({ data: { sha256: hash } }))
}

beforeAll(async () => {
  fs.mkdirSync(MOCK.userData, { recursive: true })
  server = http.createServer((req, res) => {
    if (req.url?.startsWith('/api/v1/client-hash')) {
      const u = new URL(req.url, MOCK.apiBase)
      serveHash(res, u.searchParams.get('version') || '')
    } else {
      res.writeHead(404)
      res.end()
    }
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  MOCK.apiBase = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 3001}`
})

afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
  fs.rmSync(MOCK.userData, { recursive: true, force: true })
})

beforeEach(() => {
  vi.clearAllMocks()
  MOCK.version = '0.4.5'
  MOCK.hashMap = {}
  try { fs.rmSync(INTEGRITY_FILE, { force: true }) } catch { /* noop */ }
})

// ═══════════════════════════════════════════════════
// compareVersions
// ═══════════════════════════════════════════════════

describe('compareVersions', () => {
  it('returns >0 when a is newer', () => {
    expect(compareVersions('0.4.5', '0.4.4')).toBeGreaterThan(0)
    expect(compareVersions('1.0.0', '0.9.9')).toBeGreaterThan(0)
    expect(compareVersions('0.4.10', '0.4.9')).toBeGreaterThan(0)
  })

  it('returns 0 when equal', () => {
    expect(compareVersions('0.4.5', '0.4.5')).toBe(0)
    expect(compareVersions('1.2.3', '1.2.3')).toBe(0)
  })

  it('returns <0 when a is older', () => {
    expect(compareVersions('0.4.4', '0.4.5')).toBeLessThan(0)
    expect(compareVersions('0.9.0', '1.0.0')).toBeLessThan(0)
  })

  it('handles non-numeric segments gracefully', () => {
    expect(compareVersions('dev', '0.4.5')).toBeLessThan(0)
    expect(compareVersions('0.4.5-beta', '0.4.5')).toBe(0)
  })
})

// ═══════════════════════════════════════════════════
// First run — server verification
// ═══════════════════════════════════════════════════

describe('verifySelfExeIntegrity — first run', () => {
  it('stores a server-verified baseline when the hash matches', async () => {
    const hash = writeExe(0x41)
    MOCK.hashMap[MOCK.version] = hash

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(0)
    const baseline = readBaseline()
    expect(baseline?.exeHash).toBe(hash)
    expect(baseline?.versionSeed).toBe('0.4.5')
    expect(baseline?.source).toBe('server')
    expect(MOCK.tamperResponse).not.toHaveBeenCalled()
  })

  it('flags CRITICAL + fires tamper response when the server hash mismatches', async () => {
    writeExe(0x41)
    MOCK.hashMap[MOCK.version] = 'a'.repeat(64) // official hash differs

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(1)
    expect(results[0].risk).toBe('critical')
    expect(results[0].fileName).toContain('server-verified')
    expect(results[0].matches.join(' ')).toContain('(server)')
    // Baseline stores the SERVER hash so the mismatch fires on every run
    expect(readBaseline()?.exeHash).toBe('a'.repeat(64))
    expect(MOCK.tamperResponse).toHaveBeenCalled()
  })

  it('falls back to TOFU baseline when the server has no hash (404)', async () => {
    const hash = writeExe(0x41)
    MOCK.hashMap = {} // no entry → 404

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(0)
    const baseline = readBaseline()
    expect(baseline?.exeHash).toBe(hash)
    expect(baseline?.source).toBe('tofu')
  })
})

// ═══════════════════════════════════════════════════
// Version-change branch (C4 — legit update vs tampering)
// ═══════════════════════════════════════════════════

describe('verifySelfExeIntegrity — version change', () => {
  it('rebases baseline on a legit version bump confirmed by the server', async () => {
    const oldHash = writeExe(0x41)
    writeBaseline({ exeHash: oldHash, exeSize: MIN_EXE, versionSeed: '0.4.4', lastVerified: new Date().toISOString(), tamperCount: 0, source: 'server' })

    MOCK.version = '0.4.6'
    const newHash = hashOfFile(MOCK.exePath)
    MOCK.hashMap['0.4.6'] = newHash

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(0)
    const baseline = readBaseline()
    expect(baseline?.versionSeed).toBe('0.4.6')
    expect(baseline?.exeHash).toBe(newHash)
    expect(baseline?.tamperCount).toBe(0)
    expect(MOCK.tamperResponse).not.toHaveBeenCalled()
  })

  it('rebases on a version bump even when the server is unreachable (update path)', async () => {
    const oldHash = writeExe(0x41)
    writeBaseline({ exeHash: oldHash, exeSize: MIN_EXE, versionSeed: '0.4.4', lastVerified: new Date().toISOString(), tamperCount: 0, source: 'server' })

    MOCK.version = '0.4.6'
    MOCK.hashMap = {} // server silent

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(0)
    const baseline = readBaseline()
    expect(baseline?.versionSeed).toBe('0.4.6')
    expect(baseline?.source).toBe('tofu') // server was unreachable → TOFU baseline
    expect(MOCK.tamperResponse).not.toHaveBeenCalled()
  })

  it('flags CRITICAL + fires tamper response when server knows the new version but hash differs', async () => {
    const oldHash = writeExe(0x41)
    writeBaseline({ exeHash: oldHash, exeSize: MIN_EXE, versionSeed: '0.4.4', lastVerified: new Date().toISOString(), tamperCount: 0, source: 'server' })

    MOCK.version = '0.4.6'
    MOCK.hashMap['0.4.6'] = 'b'.repeat(64) // official new hash differs from local

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(1)
    expect(results[0].risk).toBe('critical')
    expect(MOCK.tamperResponse).toHaveBeenCalled()
    expect(readBaseline()?.exeHash).toBe('b'.repeat(64))
  })

  it('flags HIGH (no tamper response) on a version DOWNGRADE', async () => {
    const oldHash = writeExe(0x41)
    writeBaseline({ exeHash: oldHash, exeSize: MIN_EXE, versionSeed: '0.4.6', lastVerified: new Date().toISOString(), tamperCount: 0, source: 'server' })

    MOCK.version = '0.4.5'
    MOCK.hashMap = {}

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(1)
    expect(results[0].risk).toBe('high')
    expect(MOCK.tamperResponse).not.toHaveBeenCalled() // first downgrade = finding only
  })

  it('escalates to CRITICAL + fires tamper response on a REPEATED downgrade', async () => {
    const oldHash = writeExe(0x41)
    writeBaseline({ exeHash: oldHash, exeSize: MIN_EXE, versionSeed: '0.4.6', lastVerified: new Date().toISOString(), tamperCount: 1, source: 'server' })

    MOCK.version = '0.4.5'
    MOCK.hashMap = {}

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(1)
    expect(results[0].risk).toBe('critical')
    expect(MOCK.tamperResponse).toHaveBeenCalled()
    expect(readBaseline()?.tamperCount).toBe(2)
  })
})

// ═══════════════════════════════════════════════════
// TOFU re-verification (closes the poisoned-baseline gap)
// ═══════════════════════════════════════════════════

describe('verifySelfExeIntegrity — TOFU re-verification', () => {
  it('upgrades a TOFU baseline to trusted when the server later confirms it', async () => {
    const hash = writeExe(0x41)
    writeBaseline({ exeHash: hash, exeSize: MIN_EXE, versionSeed: '0.4.5', lastVerified: STALE, tamperCount: 0, source: 'tofu' })
    MOCK.hashMap['0.4.5'] = hash // server now reachable + agrees

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(0)
    expect(readBaseline()?.source).toBe('server')
    expect(MOCK.tamperResponse).not.toHaveBeenCalled()
  })

  it('detects a poisoned TOFU baseline once the server is reachable', async () => {
    const tamperedHash = writeExe(0x42) // attacker-modified exe
    writeBaseline({ exeHash: tamperedHash, exeSize: MIN_EXE, versionSeed: '0.4.5', lastVerified: STALE, tamperCount: 0, source: 'tofu' })
    MOCK.hashMap['0.4.5'] = 'c'.repeat(64) // official hash differs

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(1)
    expect(results[0].risk).toBe('critical')
    expect(MOCK.tamperResponse).toHaveBeenCalled()
    expect(readBaseline()?.exeHash).toBe('c'.repeat(64)) // replaced with server truth
  })

  it('keeps checking locally when the server is still unreachable', async () => {
    const hash = writeExe(0x41)
    writeBaseline({ exeHash: hash, exeSize: MIN_EXE, versionSeed: '0.4.5', lastVerified: STALE, tamperCount: 0, source: 'tofu' })
    MOCK.hashMap = {} // still offline

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(0) // TOFU baseline intact → falls to local compare
    expect(readBaseline()?.source).toBe('tofu')
  })

  it('re-verifies TOFU baselines even when lastVerified is fresh (no starvation)', async () => {
    // Regression: the throttle must key on lastServerCheck, NOT lastVerified.
    // The 'all good' path refreshes lastVerified on every run, so keying on it
    // would starve re-verification for users who scan daily.
    const hash = writeExe(0x41)
    writeBaseline({ exeHash: hash, exeSize: MIN_EXE, versionSeed: '0.4.5', lastVerified: new Date().toISOString(), tamperCount: 0, source: 'tofu' })
    MOCK.hashMap['0.4.5'] = hash

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(0)
    expect(readBaseline()?.source).toBe('server') // upgraded despite fresh lastVerified
    expect(MOCK.tamperResponse).not.toHaveBeenCalled()
  })

  it('does not re-fetch within the 24h throttle window', async () => {
    const hash = writeExe(0x41)
    const recent = new Date(Date.now() - 60 * 60 * 1000).toISOString() // 1h ago
    writeBaseline({ exeHash: hash, exeSize: MIN_EXE, versionSeed: '0.4.5', lastVerified: STALE, tamperCount: 0, source: 'tofu', lastServerCheck: recent })
    MOCK.hashMap['0.4.5'] = 'd'.repeat(64) // would be a mismatch IF fetched

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(0) // fetch skipped → no critical
    expect(readBaseline()?.source).toBe('tofu')
    expect(MOCK.tamperResponse).not.toHaveBeenCalled()
  })
})

// ═══════════════════════════════════════════════════
// Same-version tampering + escalation
// ═══════════════════════════════════════════════════

describe('verifySelfExeIntegrity — same-version tampering', () => {
  it('flags HIGH on first hash mismatch (finding only, no shutdown)', async () => {
    const baselineHash = writeExe(0x41)
    writeBaseline({ exeHash: baselineHash, exeSize: MIN_EXE, versionSeed: '0.4.5', lastVerified: new Date().toISOString(), tamperCount: 0, source: 'server' })

    // exe replaced on disk with a different build
    writeExe(0x43)

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(1)
    expect(results[0].risk).toBe('high')
    expect(MOCK.tamperResponse).not.toHaveBeenCalled()
    expect(readBaseline()?.tamperCount).toBe(1)
  })

  it('escalates to CRITICAL + fires tamper response on repeated mismatch', async () => {
    const baselineHash = writeExe(0x41)
    writeBaseline({ exeHash: baselineHash, exeSize: MIN_EXE, versionSeed: '0.4.5', lastVerified: new Date().toISOString(), tamperCount: 1, source: 'server' })

    writeExe(0x43) // still modified

    const results = await verifySelfExeIntegrity()

    expect(results).toHaveLength(1)
    expect(results[0].risk).toBe('critical')
    expect(MOCK.tamperResponse).toHaveBeenCalled()
    expect(readBaseline()?.tamperCount).toBe(2)
  })
})
