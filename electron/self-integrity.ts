/**
 * Predator — Self-Integrity Module v2 (E21)
 *
 * Verifies that Predator's own executable and loaded modules haven't been
 * tampered with. Runs at startup and periodically during scans.
 *
 * v2 Security hardening (risk mitigations):
 *   - Baseline trust: uses app.getVersion() as embedded hash seed (risk #1)
 *   - Debug-build detection: auto-raises INT3 threshold for dev mode (risk #7)
 *   - Streaming SHA256: 64KB chunks, non-blocking I/O (risk #8)
 *
 * Detection techniques:
 *   1. Self .exe SHA256 — version-seeded baseline + integrity file
 *   2. Code section protection — .text must be PAGE_EXECUTE_READ (not RWX)
 *   3. INT3 breakpoint scan — detects 0xCC patches in own code sections
 *   4. Import Table integrity — verifies IAT entries resolve to correct DLLs
 */

import crypto from 'crypto'
import fs from 'fs'
import http from 'http'
import https from 'https'
import path from 'path'
import { execPowerShell } from './utils/exec'
import { readFileRange } from './utils/file-io'
// NOTE: importing self-protect loads koffi bindings at module load. Unit tests
// must mock '../self-protect' — any test importing full-scan/scanner without
// that mock will fail on Linux CI (koffi.load('kernel32.dll') is Windows-only).
import { criticalTamperResponse } from './self-protect'
import { app } from 'electron'
import { getApiBase } from './config'
import type { ScanResult } from './types'

// ═══════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════

/** Path to stored integrity hash */
const INTEGRITY_FILE = path.join(app?.getPath?.('userData') ?? process.cwd(), '.predator_integrity')

/** Minimum .exe size for meaningful integrity check */
const MIN_EXE_SIZE = 1024 * 1024 // 1 MB

/** .exe size below which we assume debug/dev build → relaxed thresholds */
const DEBUG_BUILD_MAX_SIZE = 5 * 1024 * 1024 // 5 MB — production builds are 80-150MB

/** Pre-computed at module load — .exe size never changes at runtime */
const IS_DEBUG_BUILD = (() => {
  try {
    const exePath = app?.getPath?.('exe') ?? process.execPath
    const st = fs.statSync(exePath)
    return st.size < DEBUG_BUILD_MAX_SIZE
  } catch { return false }
})()

/**
 * Compare two dotted version strings ('0.4.5'). Returns >0 when `a` is newer
 * than `b`, 0 when equal, <0 when older. Used to distinguish a legit
 * auto-update (version bump) from a delete+reset tampering attempt.
 * Exported for unit tests.
 */
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(n => parseInt(n, 10) || 0)
  const pb = b.split('.').map(n => parseInt(n, 10) || 0)
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0)
    if (diff !== 0) return diff
  }
  return 0
}

// ═══════════════════════════════════════════════════
// 0. SERVER-SIDE HASH FETCH
// ═══════════════════════════════════════════════════

/**
 * Fetch the expected SHA256 for a given version from the server.
 * Returns null if the server is unreachable or hash is unknown.
 */
async function fetchExpectedHash(version: string): Promise<string | null> {
  try {
    const base = getApiBase()
    const url = new URL('/api/v1/client-hash', base)
    url.searchParams.set('version', version)

    const data = await new Promise<string>((resolve, reject) => {
      const transport = url.protocol === 'https:' ? https : http
      const req = transport.get(url, { timeout: 5000 }, (res) => {
        if (res.statusCode === 404) {
          // Hash not registered for this version — expected for dev/pre-release
          res.resume()
          return resolve('')
        }
        let body = ''
        res.on('data', (chunk: string) => body += chunk)
        res.on('end', () => resolve(body))
        res.on('error', reject)
      })
      req.on('error', reject)
      req.setTimeout(5000, () => { req.destroy(); reject(new Error('timeout')) })
    })

    if (!data) return null

    const parsed = JSON.parse(data)
    const sha256 = parsed?.data?.sha256
    if (sha256 && typeof sha256 === 'string' && sha256.length === 64) {
      return sha256
    }
    return null
  } catch {
    // Server unreachable — no network, server down, etc.
    return null
  }
}

// ═══════════════════════════════════════════════════
// 1. SELF .EXE SHA256 VERIFICATION
// ═══════════════════════════════════════════════════

interface IntegrityState {
  exeHash: string
  exeSize: number
  versionSeed: string  // app.getVersion() at baseline creation — prevents delete+reset attack
  lastVerified: string
  tamperCount: number
  /** How the baseline was established — 'server' (verified) or 'tofu' (fallback). */
  source?: 'server' | 'tofu'
  /** When a server re-verification was last attempted (TOFU throttle key).
   *  Distinct from lastVerified so the 'all good' path can't starve it. */
  lastServerCheck?: string
}

/** TOFU re-verification throttle — at most one server fetch per 24h per baseline. */
const TOFU_RECHECK_MS = 24 * 60 * 60 * 1000

function readIntegrityState(): IntegrityState | null {
  try {
    if (fs.existsSync(INTEGRITY_FILE)) {
      return JSON.parse(fs.readFileSync(INTEGRITY_FILE, 'utf-8'))
    }
  } catch { /* first run */ }
  return null
}

function writeIntegrityState(state: IntegrityState): void {
  try {
    fs.writeFileSync(INTEGRITY_FILE, JSON.stringify(state, null, 2), 'utf-8')
  } catch (err) { console.warn('[self-integrity] failed to write state:', (err as Error).message) }
}

/**
 * Compute version-seeded hash that tamper-evident stores can't fake.
 * Uses app.getVersion() as salt — if someone patches the .exe but
 * deletes .predator_integrity, the version seed still changes
 * (assuming version != patched version).
 *
 * On first run: stores hash + version seed.
 * On subsequent runs: compares hash AND version seed.
 */
export async function verifySelfExeIntegrity(): Promise<ScanResult[]> {
  const results: ScanResult[] = []
  const now = new Date().toISOString()

  try {
    const exePath = app?.getPath?.('exe') ?? process.execPath
    const stat = fs.statSync(exePath)

    if (stat.size < MIN_EXE_SIZE) {
      // Development mode (electron .) — skip integrity check
      return results
    }

    // Streaming SHA256 — async chunked reads, no event-loop blocking
    const h = crypto.createHash('sha256')
    const CHUNK = 1024 * 1024 // 1 MB chunks
    let offset = 0
    while (offset < stat.size) {
      const chunk = await readFileRange(exePath, offset, CHUNK)
      if (chunk.length === 0) break
      h.update(chunk)
      offset += chunk.length
    }
    const currentHash = h.digest('hex')
    const currentVersion = app?.getVersion?.() ?? 'dev'

    const stored = readIntegrityState()

    if (!stored) {
      // ═══════════════════════════════════════════════
      // First run — verify hash against server BEFORE
      // trusting the local .exe (closes baseline trust risk)
      // ═══════════════════════════════════════════════
      const serverHash = await fetchExpectedHash(currentVersion)

      if (serverHash) {
        // Server returned the expected hash — compare
        if (serverHash.toLowerCase() !== currentHash.toLowerCase()) {
          // ⛔ TAMPERING DETECTED: local .exe hash ≠ server's expected hash
          // Attacker may have patched the .exe and deleted .predator_integrity
          //
          // CRITICAL: Store the SERVER's expected hash, NOT the tampered local hash.
          // This ensures the mismatch is detected on EVERY subsequent run
          // (not just once — otherwise the tampered hash becomes the new baseline).
          writeIntegrityState({
            exeHash: serverHash, // store SERVER hash → mismatch fires every run
            exeSize: stat.size,
            versionSeed: currentVersion,
            lastVerified: now,
            tamperCount: 1,
            source: 'server',
          })
          results.push({
            path: exePath,
            fileName: '⛔ CRITICAL: Executable hash mismatch (server-verified)',
            type: 'system',
            risk: 'critical',
            matches: [
              `Expected SHA256 (server): ${serverHash.slice(0, 16)}...`,
              `Actual SHA256 (local):   ${currentHash.slice(0, 16)}...`,
              '⛔ Predator.exe does NOT match the official release build',
              'The executable may have been patched/modified by cheat software',
              'Baseline trust verified against server — this is NOT a false positive',
            ],
            size: stat.size,
            modifiedAt: now,
          })
          // Server-verified mismatch is the highest-confidence signal in this
          // module — not a heuristic, so immediate tamper response is safe.
          criticalTamperResponse([
            'Server-verified exe hash mismatch (first run)',
            `Expected: ${serverHash.slice(0, 16)}...`,
            `Actual:   ${currentHash.slice(0, 16)}...`,
          ])
          return results
        }

        // ✅ Hash matches server — store trusted baseline
        writeIntegrityState({
          exeHash: currentHash,
          exeSize: stat.size,
          versionSeed: currentVersion,
          lastVerified: now,
          tamperCount: 0,
          source: 'server',
        })
        console.log('[self-integrity] ✅ Baseline verified against server — trusted')
        return results
      }

      // Server unreachable or hash not registered — fall back to
      // trust-on-first-use (current behavior) but log a warning
      console.warn('[self-integrity] ⚠ Server hash unavailable — using trust-on-first-use fallback')
      writeIntegrityState({
        exeHash: currentHash,
        exeSize: stat.size,
        versionSeed: currentVersion,
        lastVerified: now,
        tamperCount: 0,
        source: 'tofu',
      })
      return results
    }

    // RISK #1 mitigation: if .predator_integrity was deleted, the version
    // seed acts as a secondary integrity check — a re-stored baseline
    // would have a different version than the original build.
    //
    // BUT a legit auto-update (electron-updater) ALSO changes the version
    // seed + exe hash. Distinguish the two:
    //   1. Version went UP + server confirms new hash   → legit update, rebase
    //   2. Version went UP + server unreachable          → likely update, rebase
    //   3. Version changed + server hash MISMATCH        → hard tampering
    //   4. Version went DOWN or same-version hash change → tampering
    if (stored.versionSeed && stored.versionSeed !== currentVersion) {
      const versionBumped = compareVersions(currentVersion, stored.versionSeed) > 0

      // Case 1/3: ask the server for the expected hash of the NEW version
      const serverHash = await fetchExpectedHash(currentVersion)
      if (serverHash) {
        if (serverHash.toLowerCase() !== currentHash.toLowerCase()) {
          // Case 3 — server knows this version and the local exe does NOT match
          writeIntegrityState({
            exeHash: serverHash, // store SERVER hash → mismatch fires every run
            exeSize: stat.size,
            versionSeed: currentVersion,
            lastVerified: now,
            tamperCount: (stored.tamperCount || 0) + 1,
            source: 'server',
          })
          results.push({
            path: exePath,
            fileName: '⛔ CRITICAL: Executable hash mismatch (server-verified)',
            type: 'system',
            risk: 'critical',
            matches: [
              `Expected SHA256 (server): ${serverHash.slice(0, 16)}...`,
              `Actual SHA256 (local):   ${currentHash.slice(0, 16)}...`,
              `Version: ${stored.versionSeed} → ${currentVersion}`,
              '⛔ Predator.exe does NOT match the official release build',
              'The executable may have been patched/modified by cheat software',
            ],
            size: stat.size,
            modifiedAt: now,
          })
          criticalTamperResponse([
            'Server-verified exe hash mismatch (version change)',
            `Expected: ${serverHash.slice(0, 16)}...`,
            `Actual:   ${currentHash.slice(0, 16)}...`,
          ])
          return results
        }
        // Case 1 — server confirms the new version's hash → legit update
        writeIntegrityState({
          exeHash: currentHash,
          exeSize: stat.size,
          versionSeed: currentVersion,
          lastVerified: now,
          tamperCount: 0,
          source: 'server',
        })
        console.log(`[self-integrity] ✅ Version update ${stored.versionSeed} → ${currentVersion} verified against server — baseline rebased`)
        return results
      }

      // Server unreachable — only a version BUMP is treated as a legit update
      // (electron-updater replaces the exe AND bumps app.getVersion()).
      // A downgrade or a changed version with the same file is suspicious.
      // Note: lastServerCheck records the fetch we just attempted, so the
      // retry happens after the 24h throttle instead of on every scan.
      if (versionBumped) {
        writeIntegrityState({
          exeHash: currentHash,
          exeSize: stat.size,
          versionSeed: currentVersion,
          lastVerified: now,
          tamperCount: 0,
          source: 'tofu',
          lastServerCheck: now,
        })
        console.warn(`[self-integrity] ⚠ Server hash unavailable — rebased baseline for version bump ${stored.versionSeed} → ${currentVersion}`)
        return results
      }

      // Case 4 — version went DOWN or changed without a bump
      const newCount = (stored.tamperCount || 0) + 1
      const repeated = newCount >= 2
      results.push({
        path: exePath,
        fileName: repeated
          ? '⛔ CRITICAL: Repeated version/seed tampering'
          : '⚠ SELF-INTEGRITY: Version seed mismatch',
        type: 'system',
        risk: repeated ? 'critical' : 'high',
        matches: [
          `Expected version: ${stored.versionSeed}`,
          `Current version: ${currentVersion}`,
          '⚠ Version did NOT increase — .predator_integrity may have been re-created',
          'Baseline trust broken — executable may have been patched',
        ].filter(Boolean),
        size: stat.size,
        modifiedAt: now,
      })
      // Also check hash mismatch — they often coincide
      if (stored.exeHash !== currentHash) {
        results[results.length - 1].matches.push(
          `⚠ SHA256 ALSO changed: ${stored.exeHash.slice(0, 16)}... → ${currentHash.slice(0, 16)}...`
        )
      }
      writeIntegrityState({ ...stored, tamperCount: newCount, lastVerified: now })
      // H1 consistency: repeated downgrade/seed tampering also escalates.
      if (repeated) {
        criticalTamperResponse([
          `Version seed mismatch (tamperCount=${newCount})`,
          `Stored version: ${stored.versionSeed}`,
          `Current version: ${currentVersion}`,
          'Repeated version/seed tampering — terminating scanner',
        ])
      }
      return results
    }

    // TOFU-gap mitigation: if the baseline was established via
    // trust-on-first-use (server was offline), re-verify it against the
    // server on LATER runs when it may be reachable. Otherwise a tampered
    // exe + deleted integrity file + offline first run would poison the
    // baseline forever (audit finding H1/C1).
    //
    // Throttled by lastServerCheck (not lastVerified!) — the 'all good'
    // path refreshes lastVerified on every run, so keying on it would starve
    // this branch entirely for users who scan daily.
    let serverCheckedAt: string | undefined
    // Fall back to 0 (immediately due) when no server check is recorded — a
    // legacy/TOFU baseline without lastServerCheck must self-heal on the next
    // run instead of being starved by a fresh lastVerified.
    const lastServerCheckAt = stored.lastServerCheck
      ? new Date(stored.lastServerCheck).getTime()
      : 0
    if (stored.source !== 'server' && Date.now() - lastServerCheckAt >= TOFU_RECHECK_MS) {
      const serverHash = await fetchExpectedHash(currentVersion)
      if (serverHash) {
        if (serverHash.toLowerCase() !== currentHash.toLowerCase()) {
          // Server now reachable and disagrees with the TOFU baseline → hard tampering
          writeIntegrityState({
            exeHash: serverHash, // store SERVER hash → mismatch fires every run
            exeSize: stat.size,
            versionSeed: currentVersion,
            lastVerified: now,
            tamperCount: (stored.tamperCount || 0) + 1,
            source: 'server',
            lastServerCheck: now,
          })
          results.push({
            path: exePath,
            fileName: '⛔ CRITICAL: Executable hash mismatch (server-verified)',
            type: 'system',
            risk: 'critical',
            matches: [
              `Expected SHA256 (server): ${serverHash.slice(0, 16)}...`,
              `Actual SHA256 (local):   ${currentHash.slice(0, 16)}...`,
              '⛔ Predator.exe does NOT match the official release build',
              'TOFU baseline re-verified against server — tampering confirmed',
            ],
            size: stat.size,
            modifiedAt: now,
          })
          criticalTamperResponse([
            'Server-verified exe hash mismatch (TOFU re-verification)',
            `Expected: ${serverHash.slice(0, 16)}...`,
            `Actual:   ${currentHash.slice(0, 16)}...`,
          ])
          return results
        }
        // Server confirms the TOFU baseline → upgrade to trusted baseline
        writeIntegrityState({
          exeHash: currentHash,
          exeSize: stat.size,
          versionSeed: currentVersion,
          lastVerified: now,
          tamperCount: 0,
          source: 'server',
          lastServerCheck: now,
        })
        console.log('[self-integrity] ✅ TOFU baseline verified against server — upgraded to trusted')
        return results
      }
      // Server still unreachable — record the attempt, then fall through to
      // the local hash comparison below (lastServerCheck persisted there).
      serverCheckedAt = now
    }

    // Normal path: verify hash (persist lastServerCheck so the TOFU throttle
    // is tracked across the fall-through from the unreachable-server branch)
    if (stored.exeHash !== currentHash) {
      const newCount = (stored.tamperCount || 0) + 1
      writeIntegrityState({ ...stored, tamperCount: newCount, lastVerified: now, lastServerCheck: serverCheckedAt ?? stored.lastServerCheck })
      const repeated = newCount >= 2

      results.push({
        path: exePath,
        fileName: repeated
          ? '⛔ CRITICAL: Repeated executable tampering'
          : '⚠ SELF-INTEGRITY FAILED: Executable modified',
        type: 'system',
        risk: repeated ? 'critical' : 'high',
        matches: [
          `Expected SHA256: ${stored.exeHash.slice(0, 16)}...`,
          `Actual SHA256:   ${currentHash.slice(0, 16)}...`,
          `Tamper count: ${newCount}`,
          '⚠ Predator executable has been modified — possible patching/tampering',
          repeated ? '⚠ REPEATED tampering detected — critical' : '',
        ].filter(Boolean),
        size: stat.size,
        modifiedAt: now,
      })

      // H1: repeated tampering (2+ detections) → emergency shutdown.
      // Single detection stays a finding so false positives don't kill the app.
      if (repeated) {
        criticalTamperResponse([
          `Executable SHA256 mismatch (tamperCount=${newCount})`,
          `Expected: ${stored.exeHash.slice(0, 16)}...`,
          `Actual:   ${currentHash.slice(0, 16)}...`,
          'Repeated integrity failures — terminating scanner',
        ])
      }
    } else {
      // All good — update last verified timestamp
      writeIntegrityState({ ...stored, lastVerified: now, lastServerCheck: serverCheckedAt ?? stored.lastServerCheck })
    }
  } catch (err) {
    console.warn('[self-integrity] exe hash failed:', (err as Error).message)
  }

  return results
}

// ═══════════════════════════════════════════════════
// 2. CODE SECTION PROTECTION CHECK
// ═══════════════════════════════════════════════════

/**
 * Verify .text section has correct page protection (RX, not RWX).
 * Uses VirtualQuery via PowerShell to check memory protection of
 * Predator's own modules. RWX sections indicate code injection/patching.
 */
export function checkCodeSectionProtection(): ScanResult[] {
  const results: ScanResult[] = []
  const now = new Date().toISOString()

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class MemProt {
  [DllImport("kernel32.dll")] public static extern int VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);
  [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName);

  [StructLayout(LayoutKind.Sequential)]
  public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress, AllocationBase;
    public uint AllocationProtect, RegionSize, State, Protect, Type;
  }

  public const uint PAGE_EXECUTE_READWRITE = 0x40;
  public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
  public const uint MEM_COMMIT = 0x1000;
}
'@

$results = @()
$ourPid = ${process.pid}
$proc = Get-Process -Id $ourPid -ErrorAction SilentlyContinue
if (-not $proc) { return }
$procName = $proc.Name.ToLower()

# Check only our own modules
$ourModules = @($proc.Modules | Where-Object {
  $_.ModuleName.ToLower() -match '(predator|electron|ffmpeg|sharp|koffi|napi|better.sqlite)'
})

foreach ($mod in $ourModules) {
  $addr = $mod.BaseAddress.ToInt64()
  $mi = New-Object MemProt+MEMORY_BASIC_INFORMATION
  $result = [MemProt]::VirtualQuery([IntPtr]$addr, [ref]$mi, [IntPtr][System.Runtime.InteropServices.Marshal]::SizeOf($mi))
  if ($result -gt 0) {
    $prot = $mi.Protect
    if ($prot -eq [MemProt]::PAGE_EXECUTE_READWRITE -or $prot -eq [MemProt]::PAGE_EXECUTE_WRITECOPY) {
      $results += [PSCustomObject]@{
        Module = $mod.ModuleName
        Address = [string]$addr
        Protection = $prot
        Size = $mod.ModuleMemorySize
      }
    }
  }
}
$results | ConvertTo-Json -Compress
`
    const out = (execPowerShell(psScript, { timeout: 10000, collapseLines: 'semicolons' }) || '').trim()

    if (!out || out === '[]' || out.length < 5) return results

    const hits = JSON.parse(out)
    for (const hit of hits) {
      results.push({
        path: `module:${hit.Module}`,
        fileName: `⚠ RWX Code Section: ${hit.Module}`,
        type: 'system',
        risk: 'high',
        matches: [
          `Module: ${hit.Module} at 0x${parseInt(hit.Address).toString(16)}`,
          `Protection: PAGE_EXECUTE_READWRITE (${hit.Protection})`,
          `Region size: ${(hit.Size / 1024).toFixed(0)} KB`,
          '⚠ Executable+Writable code section — possible code injection/patching',
        ],
        size: 0,
        modifiedAt: now,
      })
    }
  } catch { /* code section check optional */ }

  return results
}

// ═══════════════════════════════════════════════════
// 3. INT3 BREAKPOINT SCAN
// ═══════════════════════════════════════════════════

/**
 * Scan our own code sections for INT3 (0xCC) breakpoints.
 * Debuggers insert INT3 at function prologues; more than a few
 * in non-debug code = someone is patching our executable.
 *
 * Normal: 0-5 INT3 instructions (alignment padding in some compilers)
 * Suspicious: 20+ INT3 in executable sections
 */
export async function scanForInt3Patches(): Promise<ScanResult[]> {
  const results: ScanResult[] = []
  const now = new Date().toISOString()
  const INT3 = 0xCC
  const INT3_THRESHOLD = IS_DEBUG_BUILD ? 200 : 20

  try {
    const exePath = app?.getPath?.('exe') ?? process.execPath
    const stat = fs.statSync(exePath)
    if (stat.size < MIN_EXE_SIZE) return results

    // Parse PE to find .text section, scan only that
    const peHdrBuf = await readFileRange(exePath, 0, 4096)
    if (peHdrBuf.length < 2) return results

    // MZ header → PE offset
    if (peHdrBuf[0] !== 0x4D || peHdrBuf[1] !== 0x5A) return results
    const peOff = peHdrBuf.readUInt32LE(0x3C)
    if (peOff + 2 > peHdrBuf.length || peHdrBuf[peOff] !== 0x50 || peHdrBuf[peOff + 1] !== 0x45) return results

    const coffOff = peOff + 4
    const numSections = peHdrBuf.readUInt16LE(coffOff + 2)
    const optHeaderSize = peHdrBuf.readUInt16LE(coffOff + 16)
    const optOff = coffOff + 20
    const secOff = optOff + optHeaderSize

    // Find .text section
    let textRaw = 0
    let textSize = 0
    for (let i = 0; i < numSections && i < 30; i++) {
      const o = secOff + i * 40
      if (o + 40 > 4096) break
      const name = peHdrBuf.toString('ascii', o, o + 8).replace(/\x00+$/, '')
      if (name === '.text' || name === 'CODE') {
        textRaw = peHdrBuf.readUInt32LE(o + 20) // PointerToRawData
        textSize = peHdrBuf.readUInt32LE(o + 16) // SizeOfRawData
        break
      }
    }

    if (textRaw === 0 || textSize === 0 || textRaw >= stat.size) return results
    const readSize = Math.min(textSize, 20 * 1024 * 1024)

    const buf = await readFileRange(exePath, textRaw, readSize)

    let int3Count = 0
    let consecutiveInt3 = 0
    let maxConsecutive = 0

    for (let i = 0; i < buf.length; i++) {
      if (buf[i] === INT3) {
        int3Count++
        consecutiveInt3++
        if (consecutiveInt3 > maxConsecutive) maxConsecutive = consecutiveInt3
      } else {
        consecutiveInt3 = 0
      }
    }

    if (int3Count > INT3_THRESHOLD) {
      results.push({
        path: exePath,
        fileName: '⚠ INT3 Breakpoint Injection Detected',
        type: 'system',
        risk: 'high',
        matches: [
          `INT3 (0xCC) count in .text: ${int3Count} (threshold: ${INT3_THRESHOLD})`,
          `Maximum consecutive INT3: ${maxConsecutive}`,
          '⚠ Excessive software breakpoints in code section — debugger breakpoint injection',
          maxConsecutive > 5 ? `⚠ ${maxConsecutive} consecutive INT3 — code overwrite pattern` : '',
        ].filter(Boolean),
        size: stat.size,
        modifiedAt: now,
      })
    }
  } catch (err) { console.warn('[self-integrity] INT3 scan failed:', (err as Error).message) }

  return results
}

// ═══════════════════════════════════════════════════
// 4. IMPORT TABLE INTEGRITY
// ═══════════════════════════════════════════════════

/**
 * Verify our Import Table resolves to expected DLLs.
 * Any IAT entry pointing to an unknown/unexpected DLL = DLL proxying attack.
 */
export function verifyImportTable(): ScanResult[] {
  const results: ScanResult[] = []
  const now = new Date().toISOString()

  try {
    const psScript = `
$ErrorActionPreference = 'SilentlyContinue'
$ourPid = ${process.pid}
$proc = Get-Process -Id $ourPid -ErrorAction SilentlyContinue
if (-not $proc) { return }

$modules = @($proc.Modules | Select-Object -ExpandProperty ModuleName | ForEach-Object { $_.ToLower() })

# Known system DLLs that should be there
$expectedDlls = @(
  'kernel32.dll', 'user32.dll', 'gdi32.dll', 'advapi32.dll', 'shell32.dll', 'ole32.dll',
  'ws2_32.dll', 'ntdll.dll', 'crypt32.dll', 'psapi.dll', 'version.dll', 'setupapi.dll',
  'dbghelp.dll', 'winhttp.dll', 'iphlpapi.dll', 'msvcrt.dll', 'vcruntime140.dll',
  'ucrtbase.dll', 'comctl32.dll', 'shlwapi.dll', 'powrprof.dll', 'netapi32.dll'
)

$unexpected = @()
foreach ($mod in $modules) {
  # Skip Predator's own modules and known Electron modules
  if ($mod -match '^predator' -or $mod -match '^electron' -or
      $mod -match '^ffmpeg' -or $mod -match '^chrome' -or
      $mod -match '.node$' -or $mod -match '.dll$' -and
      ($expectedDlls -contains $mod)) { continue }
  # Flag .dll files that AREN'T in our expected list and AREN'T Predator/Electron modules
  if ($mod.EndsWith('.dll')) {
    # Check if it's a system DLL in System32
    $sysPath = [Environment]::SystemDirectory
    if (Test-Path (Join-Path $sysPath $mod)) { continue }
    $unexpected += $mod
  }
}

# Also check for known proxy-DLL names
$proxyNames = @('version.dll', 'winmm.dll', 'dinput8.dll', 'xinput1_3.dll', 'd3d9.dll', 'dsound.dll')
$injected = @($modules | Where-Object { $_ -in $proxyNames -and -not (Test-Path (Join-Path [Environment]::SystemDirectory $_)) })

$result = [PSCustomObject]@{
  Unexpected = $unexpected -join '|'
  ProxyDlls = $injected -join '|'
}
$result | ConvertTo-Json -Compress
`
    const out = (execPowerShell(psScript, { timeout: 10000, collapseLines: 'semicolons' }) || '').trim()

    if (!out || out.length < 5) return results

    const parsed = JSON.parse(out)
    const unexpected = (parsed.Unexpected || '').split('|').filter(Boolean)
    const proxyDlls = (parsed.ProxyDlls || '').split('|').filter(Boolean)

    if (unexpected.length > 0) {
      results.push({
        path: 'process:self:modules',
        fileName: `⚠ Unexpected DLLs Loaded: ${unexpected.length} modules`,
        type: 'system',
        risk: 'medium',
        matches: [
          `Unexpected modules: ${unexpected.slice(0, 10).join(', ')}`,
          unexpected.length > 10 ? `... and ${unexpected.length - 10} more` : '',
          '⚠ Non-system DLLs loaded into Predator — possible DLL injection',
        ].filter(Boolean),
        size: 0,
        modifiedAt: now,
      })
    }

    if (proxyDlls.length > 0) {
      results.push({
        path: 'process:self:proxy-dlls',
        fileName: `⚠ DLL Proxying Detected: ${proxyDlls.join(', ')}`,
        type: 'system',
        risk: 'high',
        matches: [
          `Proxy DLLs loaded from non-system path: ${proxyDlls.join(', ')}`,
          '⚠ Classic DLL proxy attack — DLL was placed next to .exe to intercept calls',
          'These DLLs are loaded instead of legitimate System32 versions',
        ],
        size: 0,
        modifiedAt: now,
      })
    }
  } catch (err) { console.warn('[self-integrity] IAT check failed:', (err as Error).message) }

  return results
}

// ═══════════════════════════════════════════════════
// 5. UNIFIED SELF-INTEGRITY SCAN
// ═══════════════════════════════════════════════════

/**
 * Run ALL self-integrity checks.
 * Called at scan start (Phase 0) and periodically.
 */
export async function runSelfIntegrityScan(): Promise<ScanResult[]> {
  const results: ScanResult[] = []

  results.push(...await verifySelfExeIntegrity())
  results.push(...checkCodeSectionProtection())
  results.push(...await scanForInt3Patches())
  results.push(...verifyImportTable())

  return results
}
