/**
 * Predator — API v1 Routes
 *
 * Versioned API with backward compatibility.
 * All v1 routes mirror the existing routes but with:
 *   - X-API-Version: 1 response header
 *   - Structured error format
 *   - Response envelope: { data, meta }
 */

import express from 'express'
import type { Request, Response } from 'express'
import { query } from '../config/database'
import { verifyToken } from '../middleware/auth'

const router = express.Router()

// ── Version middleware ─────────────────────────
router.use((_req: Request, res: Response, next) => {
  res.setHeader('X-API-Version', '1')
  next()
})

// ═══════════════════════════════════════════════════
// GET /api/v1/signatures — Hot-reload cheat sigs
// ═══════════════════════════════════════════════════

let _sigVersion = 1
let _sigUpdateTime = new Date().toISOString()

// Keywords sourced from confirmed cheat hashes + manual additions
const SERVER_KEYWORDS: string[] = [
  // Latest discovered cheat terms (from hash reviews)
  'vmprotect packed', 'themida packed', 'enigma protector',
  'obsidium packed', 'armadillo packed',
  'loadlibrary injector', 'reflective loader',
  'kernel callback', 'driver object', 'device io control',
  'ntloaddriver', 'ntunloaddriver', 'iocreatedriver',
  'psloadedmodulelist', 'pscreatesystemthread',
  'zwmapviewofsection', 'zwunmapviewofsection',
  'zwprotectvirtualmemory', 'zwqueryvirtualmemory',
  'ldrloaddll', 'ldrunloaddll', 'manualmap inject',
  'veh hook', 'vectored exception', 'top level exception',
  'setwindowshookex inject', 'getmsg hook', 'sendmsg hook',
  'cbt hook', 'keyboard hook', 'mouse hook',
  'dll proxy', 'dll sideload', 'dll hijack', 'phantom dll',
  'search order hijack', 'path hijack', 'binary planting',
  'unhook windows apis', 'rehook ntdll', 'fresh ntdll',
  'direct syscall', 'indirect syscall', 'hells gate',
  'halos gate', 'tartarus gate', 'syswhispers', 'syswhispers2',
  'syswhispers3', 'parallel syscalls', 'inline syscall',
  'early bird apc', 'queue user apc', 'ntqueueapcthread',
  'setthreadcontext', 'getthreadcontext', 'rtlcopycontext',
  'process hollowing', 'process doppelganging', 'process herpaderping',
  'process ghosting', 'transacted hollowing', 'atom bombing',
  'dll hollowing', 'module overwrite', 'module stomping',
  'image section', 'section mapping', 'shared section',
  'memory section', 'file mapping', 'ntcreatesection',
  'memory patching', 'hot patching', 'detour patching',
  'iat hook', 'eat hook', 'ssdt hook', 'idt hook',
  'irp hook', 'object hook', 'callback hook',
  'com hook', 'window hook', 'message hook',
  'etw patch', 'etw bypass', 'etw provider', 'etw session',
  'etw providertraits', 'amsi bypass', 'amsi patch',
  'amsi dll hijack', 'amsi scanbuffer', 'amsi initialize',
  'wldp bypass', 'wldp query', 'ci policy', 'code integrity',
  'patchguard bypass', 'dse bypass', 'dsefix', 'testsigning',
  'nointegritychecks', 'debuggermode', 'kernel debugger',
]

const SERVER_PATTERNS: string[] = [
  // Latest discovered cheat patterns (from hash reviews)
  '[Vv][Mm][Pp]rotect',
  '[Tt][Hh][Ee][Mm][Ii][Dd][Aa]',
  '[Ee][Nn][Ii][Gg][Mm][Aa]\\s*[Pp]rotect',
  '[Ss][Yy][Ss]whisper',
  '[Hh][Ee][Ll][Ll][Ss]\\s*[Gg]ate',
  '[Hh][Aa][Ll][Oo][Ss]\\s*[Gg]ate',
  '[Dd]irect\\s*[Ss]yscall',
  '[Ii]ndirect\\s*[Ss]yscall',
  '[Pp]rocess\\s*[Hh]ollow',
  '[Pp]rocess\\s*[Do]ppelg',
  '[Pp]rocess\\s*[Hh]erpa',
  '[Pp]rocess\\s*[Gg]host',
  '[Ee]arly\\s*[Bb]ird\\s*[Aa][Pp][Cc]',
  '[Qq]ueue\\s*[Uu]ser\\s*[Aa][Pp][Cc]',
  '[Ss]et[Tt]hread[Cc]ontext',
  '[Gg]et[Tt]hread[Cc]ontext',
  '[Mm]emory\\s*[Pp]atch',
  '[Hh]ot\\s*[Pp]atch',
  '[Ii][Aa][Tt]\\s*[Hh]ook',
  '[Ee][Aa][Tt]\\s*[Hh]ook',
  '[Ss][Ss][Dd][Tt]\\s*[Hh]ook',
  '[Ii][Rr][Pp]\\s*[Hh]ook',
  '[Ee][Tt][Ww]\\s*([Pp]atch|[Bb]ypass)',
  '[Aa][Mm][Ss][Ii]\\s*([Pp]atch|[Bb]ypass|[Dd]ll)',
  '[Ww][Ll][Dd][Pp]\\s*([Bb]ypass|[Qq]uery)',
  '[Pp]atch[Gg]uard\\s*([Bb]ypass|[Dd]isable)',
  '[Dd][Ss][Ee]\\s*([Bb]ypass|[Ff]ix)',
  '[Tt]est[Ss]igning',
  '[Dd][Ll][Ll]\\s*([Pp]roxy|[Ss]ideload|[Hh]ijack|[Hh]ollow)',
  '[Pp]hantom\\s*[Dd][Ll][Ll]',
  '[Ss]earch\\s*[Oo]rder\\s*[Hh]ijack',
  '[Uu]nhook\\s*[Ww]indows',
  '[Rr]ehook\\s*[Nn][Tt][Dd][Ll][Ll]',
  '[Ff]resh\\s*[Nn][Tt][Dd][Ll][Ll]',
  '[Tt]artarus\\s*[Gg]ate',
  '[Aa]tom\\s*[Bb]omb',
  '[Mm]odule\\s*([Oo]verwrite|[Ss]tomp)',
  '[Ii]mage\\s*[Ss]ection',
  '[Ss]ection\\s*[Mm]ap',
  '[Cc]ode\\s*[Ii]ntegrity\\s*([Bb]ypass|[Dd]isable)',
  '[Kk]ernel\\s*[Dd]ebug',
]

// ── GET /api/v1/signatures ──────────────────────
router.get('/signatures', (req: Request, res: Response) => {
  const sinceVersion = parseInt(req.query.since_version as string) || 0

  // If client already has the latest version, return 304
  if (sinceVersion >= _sigVersion) {
    return res.status(304).end()
  }

  return res.json({
    data: {
      version: _sigVersion,
      updatedAt: _sigUpdateTime,
      keywords: SERVER_KEYWORDS,
      patterns: SERVER_PATTERNS,
    },
    meta: {
      totalKeywords: SERVER_KEYWORDS.length,
      totalPatterns: SERVER_PATTERNS.length,
    },
  })
})

// ── POST /api/v1/signatures/refresh ────────────
// Admin-only (JWT required): force version bump to trigger client reloads
router.post('/signatures/refresh', verifyToken, (_req: Request, res: Response) => {
  _sigVersion++
  _sigUpdateTime = new Date().toISOString()
  console.log(`  🔄 Signature version bumped to ${_sigVersion} at ${_sigUpdateTime}`)

  return res.json({
    data: { version: _sigVersion, updatedAt: _sigUpdateTime },
    meta: {},
  })
})

// ═══════════════════════════════════════════════════
// GET /api/v1/client-hash — Server-side .exe integrity
// ═══════════════════════════════════════════════════
//
// Closes the baseline-trust attack vector (risk #1):
//   Attacker patches Predator.exe → deletes .predator_integrity →
//   first run stores tampered hash as baseline.
//
// With this endpoint, the client fetches the EXPECTED hash from
// the server on first run. If the local hash doesn't match —
// tampering is detected BEFORE the baseline is stored.
//
// Populate this map during release.

/**
 * Map of version → expected SHA256 of Predator.exe
 * Populated after each release build.
 *
 * To add a new version hash:
 *   1. Build the release .exe
 *   2. Run: certutil -hashfile release/Predator-0.4.0.exe SHA256
 *   3. Add entry below
 */
const CLIENT_HASHES: Record<string, string> = {
  // '0.4.0': 'abc123def456...', // ← add after release build
}

router.get('/client-hash', async (req: Request, res: Response) => {
  const version = req.query.version as string | undefined

  if (!version) {
    return res.status(400).json({
      data: null,
      error: { code: 'MISSING_VERSION', message: 'Query parameter "version" is required' },
    })
  }

  // 1. Check static map first (fast path)
  if (CLIENT_HASHES[version]) {
    return res.json({
      data: {
        version,
        sha256: CLIENT_HASHES[version],
        source: 'static',
      },
      meta: {},
    })
  }

  // 2. Check DB (dynamic fallback — populate via admin or release script)
  try {
    const rows = await query<{ sha256: string }[]>(
      'SELECT sha256 FROM client_hashes WHERE version = ? LIMIT 1',
      [version],
    )
    if (rows.length > 0) {
      return res.json({
        data: {
          version,
          sha256: rows[0].sha256,
          source: 'database',
        },
        meta: {},
      })
    }
  } catch {
    // DB query failed — table may not exist yet, continue to 404
  }

  // 3. Not found — hash for this version hasn't been registered yet
  return res.status(404).json({
    data: null,
    error: {
      code: 'HASH_NOT_FOUND',
      message: `No hash registered for version "${version}". Has the release been published?`,
    },
  })
})

// ── GET /api/v1/health ─────────────────────────
router.get('/health', (_req: Request, res: Response) => {
  return res.json({
    data: {
      status: 'ok',
      version: '3.0.0',
      apiVersion: 'v1',
    },
    meta: {
      timestamp: new Date().toISOString(),
    },
  })
})

// ── GET /api/v1/stats ──────────────────────────
router.get('/stats', async (_req: Request, res: Response) => {
  try {
    const totalScans = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM scan_results')
    const totalHashes = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM suspicious_hashes')
    const totalTokens = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM tokens')
    const totalSafeFiles = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM safe_files')

    return res.json({
      data: {
        totalScans: totalScans[0]?.cnt || 0,
        totalHashes: totalHashes[0]?.cnt || 0,
        totalTokens: totalTokens[0]?.cnt || 0,
        totalSafeFiles: totalSafeFiles[0]?.cnt || 0,
        signatureVersion: _sigVersion,
      },
      meta: {},
    })
  } catch (err: any) {
    console.error('v1 stats error:', err)
    return res.status(500).json({
      data: null,
      error: { code: 'INTERNAL_ERROR', message: 'Internal server error' },
    })
  }
})

export = router
