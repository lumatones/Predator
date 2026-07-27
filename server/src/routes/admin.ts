import express from 'express'
import type { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import crypto from 'crypto'
import { query } from '../config/database'
import { generateToken, verifyToken } from '../middleware/auth'
import {
  adminLoginSchema,
  tokensGenerateSchema,
  hashConfirmFromScanSchema,
  validate,
} from '../shared-types'
import type { TokenRow, RequestRow, AdminRow, ScanResultRow, SuspiciousHashRow } from '../shared-types'

const router = express.Router()

// ── POST /api/admin/login ─────────────────────
router.post('/login', validate(adminLoginSchema), async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body

    const rows = await query<AdminRow[]>('SELECT * FROM admins WHERE username = ?', [username])
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' })
    }

    const admin = rows[0]
    const match = await bcrypt.compare(password, admin.password_hash)
    if (!match) {
      return res.status(401).json({ error: 'Invalid username or password' })
    }

    const token = generateToken(admin)
    return res.json({ token, admin: { id: admin.id, username: admin.username, role: admin.role } })
  } catch (err: any) {
    console.error('Login error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── All routes below require auth ─────────────
router.use(verifyToken)

// ── GET /api/admin/pending ────────────────────
router.get('/pending', async (req: Request, res: Response) => {
  try {
    const rows = await query<RequestRow[]>(
      'SELECT id, pc_username, status, created_at, expires_at FROM requests WHERE status = ? AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY created_at DESC',
      ['pending']
    )
    return res.json(rows)
  } catch (err: any) {
    console.error('Pending error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/admin/approve/:id ───────────────
router.post('/approve/:id', async (req: Request, res: Response) => {
  try {
    const rows = await query<RequestRow[]>(
      'SELECT * FROM requests WHERE id = ? AND status = ?',
      [req.params.id, 'pending']
    )
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Request not found or already processed' })
    }

    const requestId = String(req.params.id)
    await query(
      'UPDATE requests SET status = ?, approved_by = ?, approved_at = NOW() WHERE id = ?',
      ['approved', (req as any).admin.id, requestId]
    )

    const io = req.app.get('io')
    io?.to('admin').emit('request-update', {
      type: 'approved',
      requestId: parseInt(requestId),
      pcUsername: rows[0].pc_username,
      admin: (req as any).admin.username,
      timestamp: new Date().toISOString(),
    })

    return res.json({ success: true, message: 'Request approved' })
  } catch (err: any) {
    console.error('Approve error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/admin/reject/:id ────────────────
router.post('/reject/:id', async (req: Request, res: Response) => {
  try {
    const rows = await query<RequestRow[]>(
      'SELECT * FROM requests WHERE id = ? AND status = ?',
      [req.params.id, 'pending']
    )
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Request not found or already processed' })
    }

    const rejectId = String(req.params.id)
    await query(
      'UPDATE requests SET status = ?, approved_by = ?, approved_at = NOW() WHERE id = ?',
      ['rejected', (req as any).admin.id, rejectId]
    )

    const io = req.app.get('io')
    io?.to('admin').emit('request-update', {
      type: 'rejected',
      requestId: parseInt(rejectId),
      pcUsername: rows[0].pc_username,
      admin: (req as any).admin.username,
      timestamp: new Date().toISOString(),
    })

    return res.json({ success: true, message: 'Request rejected' })
  } catch (err: any) {
    console.error('Reject error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/admin/tokens/generate ───────────
router.post('/tokens/generate', validate(tokensGenerateSchema), async (req: Request, res: Response) => {
  try {
    const { count } = req.body
    const tokens: string[] = []

    for (let i = 0; i < Math.min(count, 10); i++) {
      const code = crypto.randomBytes(16).toString('hex').toUpperCase()

      await query(
        'INSERT INTO tokens (code, created_by) VALUES (?, ?)',
        [code, (req as any).admin.id]
      )

      const formatted = code.match(/.{1,8}/g)!.join('-')
      tokens.push(formatted)
    }

    const io = req.app.get('io')
    io?.to('admin').emit('token-generated', {
      count: tokens.length,
      admin: (req as any).admin.username,
      timestamp: new Date().toISOString(),
    })

    return res.json({ success: true, tokens })
  } catch (err: any) {
    console.error('Generate token error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/admin/tokens ─────────────────────
router.get('/tokens', async (req: Request, res: Response) => {
  try {
    const rows = await query<(TokenRow & { created_by_name: string | null })[]>(`
      SELECT t.id, t.code, t.is_active, t.used_by, t.used_at, t.created_at, a.username AS created_by_name
      FROM tokens t
      LEFT JOIN admins a ON t.created_by = a.id
      ORDER BY t.created_at DESC
      LIMIT 50
    `)

    const formatted = rows.map(r => ({
      id: r.id,
      is_active: r.is_active,
      used_by: r.used_by,
      used_at: r.used_at,
      created_at: r.created_at,
      created_by_name: r.created_by_name,
      code_display: r.code ? r.code.match(/.{1,8}/g)!.join('-') : '',
    }))

    return res.json(formatted)
  } catch (err: any) {
    console.error('Tokens list error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/admin/tokens/revoke/:id ─────────
router.post('/tokens/revoke/:id', async (req: Request, res: Response) => {
  try {
    const tokenId = String(req.params.id)
    await query(
      'UPDATE tokens SET is_active = FALSE, revoked_at = NOW() WHERE id = ? AND is_active = TRUE',
      [tokenId]
    )
    return res.json({ success: true, message: 'Token revoked' })
  } catch (err: any) {
    console.error('Revoke error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/admin/history ────────────────────
router.get('/history', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(parseInt((req.query.limit as string) || '100'), 200)

    const usedTokens = await query<(TokenRow & { created_by_name: string | null; event_type: string; event_date: string })[]>(`
      SELECT
        t.id, t.code, t.used_by, t.used_at, t.created_at,
        a.username AS created_by_name,
        'token_used' AS event_type,
        t.used_at AS event_date
      FROM tokens t
      LEFT JOIN admins a ON t.created_by = a.id
      WHERE t.used_by IS NOT NULL
      ORDER BY t.used_at DESC
      LIMIT ?
    `, [limit])

    const processedRequests = await query<(RequestRow & { approved_by_name: string | null; event_type: string; event_date: string })[]>(`
      SELECT
        r.id, r.pc_username, r.status, r.created_at, r.approved_at,
        a.username AS approved_by_name,
        CONCAT('request_', r.status) AS event_type,
        COALESCE(r.approved_at, r.created_at) AS event_date
      FROM requests r
      LEFT JOIN admins a ON r.approved_by = a.id
      WHERE r.status IN ('approved', 'rejected')
      ORDER BY event_date DESC
      LIMIT ?
    `, [limit])

    const formattedTokens = usedTokens.map(t => ({
      id: t.id,
      used_by: t.used_by,
      used_at: t.used_at,
      created_at: t.created_at,
      created_by_name: t.created_by_name,
      event_type: t.event_type,
      event_date: t.event_date,
      code_display: t.code?.match(/.{1,8}/g)?.join('-') || '',
    }))

    const merged: any[] = [
      ...formattedTokens.map(t => ({
        id: `tok-${t.id}`,
        date: t.event_date,
        type: 'token',
        subType: 'used',
        description: t.used_by || '—',
        detail: t.code_display,
        created_at: t.created_at,
        actor: t.created_by_name || '—',
      })),
      ...processedRequests.map(r => ({
        id: `req-${r.id}`,
        date: r.event_date,
        type: 'request',
        subType: r.status,
        description: r.pc_username,
        detail: r.status === 'approved' ? 'Approved' : 'Rejected',
        created_at: r.created_at,
        actor: r.approved_by_name || '—',
      })),
    ]

    merged.sort((a: any, b: any) => new Date(b.date).getTime() - new Date(a.date).getTime())

    return res.json({
      total: merged.length,
      items: merged.slice(0, limit),
      stats: {
        totalTokensUsed: formattedTokens.length,
        totalRequestsProcessed: processedRequests.length,
      },
    })
  } catch (err: any) {
    console.error('History error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/admin/scan-stats ──────────────────
router.get('/scan-stats', async (req: Request, res: Response) => {
  try {
    const totalScans = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM scan_results')
    const totalScanned = await query<{ cnt: number }[]>('SELECT SUM(total_scanned) AS cnt FROM scan_results')
    const totalSuspicious = await query<{ cnt: number }[]>('SELECT SUM(suspicious_files) AS cnt FROM scan_results')

    const byMode = await query<{ mode: string; cnt: number; threats: number }[]>(`
      SELECT mode, COUNT(*) AS cnt, SUM(suspicious_files) AS threats
      FROM scan_results
      GROUP BY mode
      ORDER BY cnt DESC
    `)

    const byDay = await query<{ day: string; cnt: number; threats: number }[]>(`
      SELECT DATE(created_at) AS day, COUNT(*) AS cnt, SUM(suspicious_files) AS threats
      FROM scan_results
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 14 DAY)
      GROUP BY DATE(created_at)
      ORDER BY day ASC
    `)

    const recent = await query<ScanResultRow[]>(`
      SELECT id, pc_username, mode, total_scanned, suspicious_files, high_risk_count, created_at
      FROM scan_results
      ORDER BY created_at DESC
      LIMIT 20
    `)

    return res.json({
      totalScans: totalScans[0]?.cnt || 0,
      totalScanned: totalScanned[0]?.cnt || 0,
      totalSuspicious: totalSuspicious[0]?.cnt || 0,
      byMode: byMode || [],
      byDay: byDay || [],
      recent: recent || [],
    })
  } catch (err: any) {
    console.error('Scan stats error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/admin/suspicious-hashes ──────────
router.get('/suspicious-hashes', async (req: Request, res: Response) => {
  try {
    const status = (req.query.status as string) || 'pending'
    const rows = await query<(SuspiciousHashRow & { reviewed_by_name: string | null })[]>(`
      SELECT sh.*, a.username AS reviewed_by_name
      FROM suspicious_hashes sh
      LEFT JOIN admins a ON sh.reviewed_by = a.id
      WHERE sh.status = ?
      ORDER BY sh.created_at DESC
      LIMIT 100
    `, [status])
    return res.json(rows)
  } catch (err: any) {
    console.error('Suspicious hashes error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/admin/hashes/approve/:id ────────
router.post('/hashes/approve/:id', async (req: Request, res: Response) => {
  try {
    const hashId = String(req.params.id)
    await query(
      'UPDATE suspicious_hashes SET status = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ? AND status = ?',
      ['confirmed', (req as any).admin.id, hashId, 'pending']
    )

    const io = req.app.get('io')
    io?.to('admin').emit('hash-update', {
      type: 'confirmed',
      hashId: parseInt(hashId),
      admin: (req as any).admin.username,
      timestamp: new Date().toISOString(),
    })

    return res.json({ success: true, message: 'Hash confirmed' })
  } catch (err: any) {
    console.error('Hash approve error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/admin/hashes/reject/:id ─────────
router.post('/hashes/reject/:id', async (req: Request, res: Response) => {
  try {
    const hashId = String(req.params.id)
    await query(
      'UPDATE suspicious_hashes SET status = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ? AND status = ?',
      ['false_positive', (req as any).admin.id, hashId, 'pending']
    )

    const io = req.app.get('io')
    io?.to('admin').emit('hash-update', {
      type: 'false_positive',
      hashId: parseInt(hashId),
      admin: (req as any).admin.username,
      timestamp: new Date().toISOString(),
    })

    return res.json({ success: true, message: 'Hash rejected' })
  } catch (err: any) {
    console.error('Hash reject error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/admin/scan-result-hashes ──────────
router.get('/scan-result-hashes', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(parseInt((req.query.limit as string) || '100'), 500)

    const rows = await query<(ScanResultRow & { results_json: string | null })[]>(`
      SELECT sr.id, sr.pc_username, sr.mode, sr.results_json, sr.created_at
      FROM scan_results sr
      WHERE sr.results_json IS NOT NULL
        AND sr.results_json != '[]'
        AND sr.results_json != ''
      ORDER BY sr.created_at DESC
      LIMIT ?
    `, [limit])

    const hashMap = new Map<string, any>()

    for (const row of rows) {
      try {
        const parsed = typeof row.results_json === 'string'
          ? JSON.parse(row.results_json)
          : row.results_json

        if (!Array.isArray(parsed)) continue

        for (const item of parsed) {
          let sha256 = ''
          let fileName = item.file_name || item.fileName || 'unknown'
          let fileSize = item.size || item.file_size || 0

          if (item.hash && typeof item.hash === 'string' && item.hash.length === 64) {
            sha256 = item.hash.toLowerCase()
          } else if (item.sha256 && typeof item.sha256 === 'string' && item.sha256.length === 64) {
            sha256 = item.sha256.toLowerCase()
          } else if (Array.isArray(item.matches)) {
            for (const m of item.matches) {
              const mStr = String(m)
              const hashMatch = mStr.match(/(?:sha256|hash):([a-f0-9]{64})/i)
              if (hashMatch) {
                sha256 = hashMatch[1].toLowerCase()
                break
              }
            }
          }

          if (!sha256 || sha256.length !== 64) continue

          const existing = hashMap.get(sha256) || {
            sha256,
            file_name: fileName,
            file_size: fileSize,
            pc_usernames: new Set<string>(),
            first_seen: row.created_at,
            last_seen: row.created_at,
            occurrences: 0,
          }

          existing.pc_usernames.add(row.pc_username || 'unknown')
          existing.occurrences++
          if (row.created_at < existing.first_seen) existing.first_seen = row.created_at
          if (row.created_at > existing.last_seen) existing.last_seen = row.created_at
          if (fileName !== 'unknown') existing.file_name = fileName
          if (fileSize > 0) existing.file_size = fileSize

          hashMap.set(sha256, existing)
        }
      } catch { /* skip malformed JSON */ }
    }

    const allHashes = Array.from(hashMap.keys())
    const existingStatuses = new Map<string, string>()

    if (allHashes.length > 0) {
      const placeholders = allHashes.map(() => '?').join(',')
      const existingRows = await query<{ sha256: string; status: string }[]>(
        `SELECT sha256, status FROM suspicious_hashes WHERE sha256 IN (${placeholders})`,
        allHashes
      )
      for (const r of existingRows) {
        existingStatuses.set(r.sha256, r.status)
      }
    }

    const result = Array.from(hashMap.values()).map(h => ({
      sha256: h.sha256,
      file_name: h.file_name,
      file_size: h.file_size,
      pc_usernames: Array.from(h.pc_usernames),
      first_seen: h.first_seen,
      last_seen: h.last_seen,
      occurrences: h.occurrences,
      status: existingStatuses.get(h.sha256) || 'new',
    }))

    result.sort((a, b) => b.occurrences - a.occurrences || new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime())

    return res.json({
      total: result.length,
      hashes: result.slice(0, 100),
    })
  } catch (err: any) {
    console.error('Scan result hashes error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/admin/hashes/confirm-from-scan ───
router.post('/hashes/confirm-from-scan', validate(hashConfirmFromScanSchema), async (req: Request, res: Response) => {
  try {
    const { sha256, file_name, file_size } = req.body

    await query(
      `INSERT IGNORE INTO suspicious_hashes (sha256, file_name, file_size, risk_score, status, reviewed_by, reviewed_at)
       VALUES (?, ?, ?, ?, 'confirmed', ?, NOW())`,
      [sha256.toLowerCase(), file_name || 'unknown', file_size || 0, 80, (req as any).admin.id]
    )

    await query(
      'UPDATE suspicious_hashes SET status = ?, reviewed_by = ?, reviewed_at = NOW() WHERE sha256 = ? AND status = ?',
      ['confirmed', (req as any).admin.id, sha256.toLowerCase(), 'pending']
    )

    const io = req.app.get('io')
    io?.to('admin').emit('hash-update', {
      type: 'confirmed',
      sha256: sha256.toLowerCase().slice(0, 16),
      admin: (req as any).admin.username,
      timestamp: new Date().toISOString(),
    })

    return res.json({ success: true, message: 'Hash confirmed as cheat and added to database' })
  } catch (err: any) {
    console.error('Confirm from scan error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/admin/safe-files-stats ──────────────
router.get('/safe-files-stats', async (req: Request, res: Response) => {
  try {
    const total = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM safe_files')
    const totalConfirm50 = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM safe_files WHERE confirm_count >= 50')
    const totalConfirm10 = await query<{ cnt: number }[]>('SELECT COUNT(*) AS cnt FROM safe_files WHERE confirm_count >= 10')

    const recent = await query<any[]>(`
      SELECT partial_hash AS partialHash, file_name AS fileName, file_size AS fileSize,
             confirm_count AS confirmCount, created_at AS createdAt, last_seen AS lastSeen
      FROM safe_files
      ORDER BY last_seen DESC
      LIMIT 30
    `)

    const topConfirmed = await query<any[]>(`
      SELECT partial_hash AS partialHash, file_name AS fileName, file_size AS fileSize,
             confirm_count AS confirmCount, last_seen AS lastSeen
      FROM safe_files
      ORDER BY confirm_count DESC
      LIMIT 10
    `)

    return res.json({
      totalFiles: total[0]?.cnt || 0,
      highConfidence: totalConfirm50[0]?.cnt || 0,
      mediumConfidence: totalConfirm10[0]?.cnt || 0,
      recent,
      topConfirmed,
    })
  } catch (err: any) {
    console.error('Safe files stats error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

export = router
