import express from 'express'
import type { Request, Response } from 'express'
import { query } from '../config/database'
import { paginate, setPaginationHeaders } from '../helpers/pagination'
import {
  checkTokenSchema,
  useTokenSchema,
  requestAccessSchema,
  submitScanSchema,
  submitHashesSchema,
  submitSafeFilesSchema,
  submitShadowSchema,
  validate,
} from '../shared-types'
import type { TokenRow, RequestRow, SuspiciousHashRow } from '../shared-types'
import { classifyBatch, autoPromoteShadowRules } from '../services/classifier'

const router = express.Router()

// ── POST /api/auth/token ──────────────────────
router.post('/token', validate(checkTokenSchema), async (req: Request, res: Response) => {
  try {
    const { token } = req.body

    const clean = token.replace(/[-\s]/g, '').toUpperCase()
    if (clean.length !== 32) {
      return res.status(400).json({ valid: false, error: 'Invalid token format' })
    }

    const rows = await query<TokenRow[]>(
      'SELECT id, code, is_active, used_by FROM tokens WHERE code = ?',
      [clean]
    )

    if (rows.length === 0) {
      return res.status(404).json({ valid: false, error: 'Token not found' })
    }

    const tok = rows[0]

    if (!tok.is_active) {
      return res.status(403).json({ valid: false, error: 'Token revoked' })
    }

    if (tok.used_by) {
      return res.status(403).json({ valid: false, error: 'Token already used' })
    }

    return res.json({ valid: true, token_id: tok.id })
  } catch (err: any) {
    console.error('Token check error:', err)
    return res.status(500).json({ valid: false, error: 'Internal server error' })
  }
})

// ── POST /api/auth/token/use ───────────────────
router.post('/token/use', validate(useTokenSchema), async (req: Request, res: Response) => {
  try {
    const { token, pc_username } = req.body

    const clean = token.replace(/[-\s]/g, '').toUpperCase()
    if (clean.length !== 32) {
      return res.status(400).json({ valid: false, error: 'Invalid token format' })
    }

    const rows = await query<TokenRow[]>(
      'SELECT id, code, is_active, used_by FROM tokens WHERE code = ?',
      [clean]
    )

    if (rows.length === 0) {
      return res.status(404).json({ valid: false, error: 'Token not found' })
    }

    const tok = rows[0]

    if (!tok.is_active) {
      return res.status(403).json({ valid: false, error: 'Token revoked' })
    }

    if (tok.used_by) {
      return res.status(403).json({ valid: false, error: 'Token already used' })
    }

    // Keep the claim atomic: a concurrent request can pass the SELECT too,
    // but only one request may update an active, unused token.
    const updateResult = await query<{ affectedRows?: number }>(
      'UPDATE tokens SET used_by = ?, used_at = NOW(), is_active = FALSE WHERE id = ? AND is_active = TRUE AND used_by IS NULL',
      [pc_username || 'unknown', tok.id]
    )

    if (updateResult?.affectedRows !== 1) {
      return res.status(403).json({ valid: false, error: 'Token already used' })
    }

    return res.json({ valid: true, token_id: tok.id, message: 'Token activated' })
  } catch (err: any) {
    console.error('Token use error:', err)
    return res.status(500).json({ valid: false, error: 'Internal server error' })
  }
})

// ── POST /api/auth/request ────────────────────
router.post('/request', validate(requestAccessSchema), async (req: Request, res: Response) => {
  try {
    const { pc_username } = req.body

    const expiryMinutes = parseInt(process.env.REQUEST_EXPIRY_MINUTES || '30')
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000)

    const result = await query<{ insertId: number }>(
      'INSERT INTO requests (pc_username, expires_at) VALUES (?, ?)',
      [pc_username.trim(), expiresAt]
    )

    try {
      const io = req.app.get('io')
      io?.to('admin').emit('new-request', {
        requestId: result.insertId,
        pcUsername: pc_username.trim(),
        timestamp: new Date().toISOString(),
      })
    } catch { /* ws event optional */ }

    return res.json({
      success: true,
      request_id: result.insertId,
      message: 'Request sent. Awaiting admin approval.',
    })
  } catch (err: any) {
    console.error('Request error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/auth/status/:id ──────────────────
router.get('/status/:id', async (req: Request, res: Response) => {
  try {
    const rows = await query<RequestRow[]>(
      'SELECT id, pc_username, status, created_at FROM requests WHERE id = ?',
      [req.params.id]
    )

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' })
    }

    return res.json(rows[0])
  } catch (err: any) {
    console.error('Status error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/auth/submit-scan ─────────────────
router.post('/submit-scan', validate(submitScanSchema), async (req: Request, res: Response) => {
  try {
    const { token_id, pc_username, mode, total_scanned, suspicious_files, high_risk_count, scan_time_ms, results } = req.body

    const tokRows = await query<TokenRow[]>(
      'SELECT id, code, is_active, used_by FROM tokens WHERE id = ?',
      [token_id]
    )

    if (tokRows.length === 0) {
      return res.status(403).json({ error: 'Token not found' })
    }

    const tok = tokRows[0]

    if (tok.is_active) {
      return res.status(403).json({ error: 'Token not activated. Use token via authorization screen.' })
    }

    if (!tok.used_by) {
      return res.status(403).json({ error: 'Token not used' })
    }

    const result = await query<{ insertId: number }>(
      `INSERT INTO scan_results (token_id, pc_username, mode, total_scanned, suspicious_files, high_risk_count, scan_time_ms, results_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        token_id,
        pc_username || 'unknown',
        mode || 'unknown',
        total_scanned || 0,
        suspicious_files || 0,
        high_risk_count || 0,
        scan_time_ms || 0,
        Array.isArray(results) ? JSON.stringify(results.slice(0, 100)) : '[]',
      ]
    )

    // ── Auto-classify scan results (fire-and-forget — don't block response) ──
    if (Array.isArray(results) && results.length > 0) {
      const scanId = result.insertId
      const pUsername = pc_username || 'unknown'
      const classifierInputs = results.map(r => ({
        sha256: r.sha256,
        partialHash: r.partialHash,
        tlsh: r.tlsh,
        filePath: r.path,
        fileName: r.fileName,
        fileType: r.type,
        risk: r.risk,
        matches: r.matches,
        findingKind: r.findingKind || (r.type === 'hardware' ? 'dma' : r.type),
        size: r.size,
        pcUsername: pUsername,
      }))

      // Fire-and-forget: classify in background, update scan_results when done
      classifyBatch(classifierInputs).then(async (classificationResult) => {
        try {
          await query(
            `UPDATE scan_results SET auto_safe_count = ?, auto_malicious_count = ?, pending_count = ?, classified_at = NOW() WHERE id = ?`,
            [classificationResult.stats.autoSafe, classificationResult.stats.autoMalicious, classificationResult.stats.pending, scanId]
          )
          console.log(`  🤖 Auto-classified scan #${scanId}: ${classificationResult.stats.autoSafe} safe, ${classificationResult.stats.autoMalicious} malicious, ${classificationResult.stats.pending} pending`)
        } catch (err) {
          console.error('Failed to update classification stats:', err)
        }
      }).catch(err => {
        console.error('Auto-classification error:', err)
      })
    }

    // ── Auto-promote shadow rules periodically ──
    autoPromoteShadowRules().catch(() => {})

    return res.json({ success: true, message: 'Results saved' })
  } catch (err: any) {
    console.error('Submit scan error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/auth/submit-hashes ──────────────
router.post('/submit-hashes', validate(submitHashesSchema), async (req: Request, res: Response) => {
  try {
    const { token_id, pc_username, hashes } = req.body

    const tokRows = await query<TokenRow[]>(
      'SELECT id, is_active, used_by FROM tokens WHERE id = ?',
      [token_id]
    )

    if (tokRows.length === 0) {
      return res.status(403).json({ error: 'Token not found' })
    }

    const tok = tokRows[0]
    if (tok.is_active) {
      return res.status(403).json({ error: 'Token not activated. Use token via authorization screen.' })
    }
    if (!tok.used_by) {
      return res.status(403).json({ error: 'Token not used' })
    }

    let inserted = 0
    let updated = 0
    for (const h of hashes) {
      // Use sha256 if available, otherwise fall back to partialHash
      // (partialHash is a valid SHA256 of first 64KB — works as lookup key)
      const hashKey = h.sha256?.toLowerCase() || h.partialHash?.toLowerCase()
      if (!hashKey || hashKey.length !== 64) continue

      const sha256 = hashKey
      const partialHash = h.partialHash?.toLowerCase() || null
      const matches = h.matches ? JSON.stringify(h.matches.slice(0, 10)) : null

      try {
        // Try to INSERT — if duplicate, UPDATE with new info
        const result = await query<any>(
          `INSERT INTO suspicious_hashes (sha256, partial_hash, tlsh, file_name, file_path, pc_username, token_id, file_size, risk_score, risk, matches, has_valid_signature)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE
             file_name = COALESCE(VALUES(file_name), file_name),
             file_size = GREATEST(VALUES(file_size), file_size),
             risk_score = GREATEST(VALUES(risk_score), risk_score)`,
          [
            sha256,
            partialHash,
            h.tlsh || null,
            h.file_name || 'unknown',
            h.file_path || null,
            pc_username || 'unknown',
            token_id,
            h.file_size || 0,
            h.risk_score || 0,
            h.risk || 'high',
            matches,
            h.has_valid_signature ?? null,
          ]
        )
        if (result.affectedRows === 1) inserted++
        else updated++
      } catch (err) { console.warn('[auth] failed:', (err as Error).message) }
    }

    try {
      const io = req.app.get('io')
      io?.to('admin').emit('new-hashes', {
        count: inserted,
        updated,
        pc_username: pc_username || 'unknown',
        timestamp: new Date().toISOString(),
      })
    } catch { /* ws event optional */ }

    return res.json({ success: true, inserted, updated, total: hashes.length })
  } catch (err: any) {
    console.error('Submit hashes error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/auth/fetch-hashes ────────────────
router.get('/fetch-hashes', async (req: Request, res: Response) => {
  try {
    const after = (req.query.after as string) || '2000-01-01'
    const { offset, limit, page } = paginate(req.query)

    const rows = await query<(SuspiciousHashRow & { file_size: number; created_at: string; tlsh: string | null })[]>(
      'SELECT sha256, tlsh, file_name, file_size, created_at FROM suspicious_hashes WHERE status = ? AND created_at > ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
      ['confirmed', after, limit, offset]
    )

    setPaginationHeaders(res, page, limit)
    return res.json({
      count: rows.length,
      hashes: rows.map(r => ({
        sha256: r.sha256,
        file_name: r.file_name,
        file_size: r.file_size,
        added_at: r.created_at,
        tlsh: r.tlsh || undefined,
      })),
      tlsh: rows.filter(r => r.tlsh).map(r => r.tlsh! as string),
    })
  } catch (err: any) {
    console.error('Fetch hashes error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/auth/safe-hashes ─────────────────
router.get('/safe-hashes', async (req: Request, res: Response) => {
  try {
    const after = (req.query.after as string) || '2000-01-01'
    const { offset, limit, page } = paginate(req.query)

    const rows = await query<(SuspiciousHashRow & { sha256: string })[]>(
      'SELECT sha256, file_name AS fileName, file_size AS fileSize, created_at AS addedAt FROM suspicious_hashes WHERE status = ? AND created_at > ? ORDER BY created_at DESC LIMIT ? OFFSET ?',
      ['confirmed', after, limit, offset]
    )

    setPaginationHeaders(res, page, limit)
    return res.json(rows.map(r => r.sha256))
  } catch (err: any) {
    console.error('Safe hashes error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/auth/submit-safe-files ───────────
router.post('/submit-safe-files', validate(submitSafeFilesSchema), async (req: Request, res: Response) => {
  try {
    const { entries } = req.body

    let updated = 0
    let inserted = 0

    for (const entry of entries) {
      if (!entry.partialHash || typeof entry.partialHash !== 'string' || entry.partialHash.length !== 64) continue
      if (!entry.size || typeof entry.size !== 'number') continue

      try {
        const existing = await query<{ id: number; confirm_count: number }[]>(
          'SELECT id, confirm_count FROM safe_files WHERE partial_hash = ? AND file_size = ?',
          [entry.partialHash, entry.size]
        )

        if (existing.length > 0) {
          await query(
            'UPDATE safe_files SET confirm_count = confirm_count + ?, last_seen = NOW() WHERE partial_hash = ? AND file_size = ?',
            [entry.confirmCount || 1, entry.partialHash, entry.size]
          )
          updated++
        } else {
          await query(
            'INSERT INTO safe_files (partial_hash, file_name, file_size, confirm_count) VALUES (?, ?, ?, ?)',
            [entry.partialHash, entry.fileName || 'unknown', entry.size, entry.confirmCount || 1]
          )
          inserted++
        }
      } catch (err) { console.warn('[auth] failed:', (err as Error).message) }
    }

    return res.json({ success: true, inserted, updated })
  } catch (err: any) {
    console.error('Submit safe files error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── POST /api/auth/submit-shadow ──────────────
router.post('/submit-shadow', validate(submitShadowSchema), async (req: Request, res: Response) => {
  try {
    const { token_id, pc_username, findings } = req.body

    let inserted = 0
    let deduped = 0
    for (const f of findings) {
      if (!f.fileName) continue
      try {
        const sha256 = f.sha256 || null
        // Dedup: same sha256 + rule_name = update count instead of duplicate
        if (sha256 && f.ruleName) {
          const existing = await query<{ id: number }[]>(
            'SELECT id FROM shadow_findings WHERE sha256 = ? AND rule_name = ? AND status = ?',
            [sha256, f.ruleName, 'shadow']
          )
          if (existing.length > 0) {
            await query(
              'UPDATE shadow_findings SET occurrence_count = occurrence_count + 1, unique_pcs = unique_pcs + 1 WHERE id = ?',
              [existing[0].id]
            )
            deduped++
            continue
          }
        }
        await query(
          `INSERT INTO shadow_findings (token_id, pc_username, file_path, file_name, file_type, rule_name, matches, sha256, tlsh)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            token_id || null,
            pc_username || 'unknown',
            f.path || null,
            f.fileName,
            f.type || 'file',
            f.ruleName || null,
            f.matches ? JSON.stringify(f.matches.slice(0, 10)) : null,
            sha256,
            f.tlsh || null,
          ]
        )
        inserted++
      } catch (err) { console.warn('[auth] failed: duplicate:', (err as Error).message) }
    }

    return res.json({ success: true, inserted, deduped, total: findings.length })
  } catch (err: any) {
    console.error('Submit shadow error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// ── GET /api/auth/safe-files (community whitelist) ──
router.get('/safe-files', async (req: Request, res: Response) => {
  try {
    const since = (req.query.since as string) || '2000-01-01'
    const { offset, limit, page } = paginate(req.query)

    const rows = await query<any[]>(
      'SELECT partial_hash AS partialHash, file_name AS fileName, file_size AS size, confirm_count AS confirmCount, last_seen AS lastSeen FROM safe_files WHERE last_seen > ? AND confirm_count >= 2 ORDER BY confirm_count DESC LIMIT ? OFFSET ?',
      [since, limit, offset]
    )

    setPaginationHeaders(res, page, limit)
    return res.json(rows)
  } catch (err: any) {
    console.error('Safe files error:', err)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

export = router
