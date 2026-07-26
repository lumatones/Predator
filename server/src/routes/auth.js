const express = require('express')
const { query } = require('../config/database')
const router = express.Router()

// ── POST /api/auth/token ──────────────────────
router.post('/token', async (req, res) => {
  try {
    const { token } = req.body
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ valid: false, error: 'Токен не указан' })
    }

    const clean = token.replace(/[-\s]/g, '').toUpperCase()
    if (clean.length !== 32) {
      return res.status(400).json({ valid: false, error: 'Неверный формат токена' })
    }

    const rows = await query(
      'SELECT id, code, is_active, used_by FROM tokens WHERE code = ?',
      [clean]
    )

    if (rows.length === 0) {
      return res.status(404).json({ valid: false, error: 'Токен не найден' })
    }

    const tok = rows[0]

    if (!tok.is_active) {
      return res.status(403).json({ valid: false, error: 'Токен отозван' })
    }

    if (tok.used_by) {
      return res.status(403).json({ valid: false, error: 'Токен уже использован' })
    }

    return res.json({ valid: true, token_id: tok.id })
  } catch (err) {
    console.error('Token check error:', err)
    return res.status(500).json({ valid: false, error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/auth/token/use ───────────────────
router.post('/token/use', async (req, res) => {
  try {
    const { token, pc_username } = req.body
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ valid: false, error: 'Токен не указан' })
    }

    const clean = token.replace(/[-\s]/g, '').toUpperCase()
    if (clean.length !== 32) {
      return res.status(400).json({ valid: false, error: 'Неверный формат токена' })
    }

    const rows = await query(
      'SELECT id, code, is_active, used_by FROM tokens WHERE code = ?',
      [clean]
    )

    if (rows.length === 0) {
      return res.status(404).json({ valid: false, error: 'Токен не найден' })
    }

    const tok = rows[0]

    if (!tok.is_active) {
      return res.status(403).json({ valid: false, error: 'Токен отозван' })
    }

    if (tok.used_by) {
      return res.status(403).json({ valid: false, error: 'Токен уже использован' })
    }

    await query(
      'UPDATE tokens SET used_by = ?, used_at = NOW(), is_active = FALSE WHERE id = ?',
      [pc_username || 'unknown', tok.id]
    )

    return res.json({ valid: true, token_id: tok.id, message: 'Токен активирован' })
  } catch (err) {
    console.error('Token use error:', err)
    return res.status(500).json({ valid: false, error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/auth/request ────────────────────
router.post('/request', async (req, res) => {
  try {
    const { pc_username } = req.body
    if (!pc_username || typeof pc_username !== 'string') {
      return res.status(400).json({ error: 'Имя ПК не указано' })
    }

    const expiryMinutes = parseInt(process.env.REQUEST_EXPIRY_MINUTES) || 30
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000)

    const result = await query(
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
      message: 'Запрос отправлен. Ожидайте подтверждения администратора.',
    })
  } catch (err) {
    console.error('Request error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── GET /api/auth/status/:id ──────────────────
router.get('/status/:id', async (req, res) => {
  try {
    const rows = await query(
      'SELECT id, pc_username, status, created_at FROM requests WHERE id = ?',
      [req.params.id]
    )

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Запрос не найден' })
    }

    return res.json(rows[0])
  } catch (err) {
    console.error('Status error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/auth/submit-scan ─────────────────
router.post('/submit-scan', async (req, res) => {
  try {
    const { token_id, pc_username, mode, total_scanned, suspicious_files, high_risk_count, scan_time_ms, results } = req.body

    // token_id обязателен — нельзя обойти авторизацию через pc_username
    if (!token_id || !Number.isInteger(token_id) || token_id <= 0) {
      return res.status(400).json({ error: 'token_id обязателен и должен быть положительным числом' })
    }

    const tokRows = await query(
      'SELECT id, code, is_active, used_by FROM tokens WHERE id = ?',
      [token_id]
    )

    if (tokRows.length === 0) {
      return res.status(403).json({ error: 'Токен не найден' })
    }

    const tok = tokRows[0]

    if (tok.is_active) {
      return res.status(403).json({ error: 'Токен не был активирован. Используйте токен через экран авторизации.' })
    }

    if (!tok.used_by) {
      return res.status(403).json({ error: 'Токен не был использован' })
    }

    const result = await query(
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

    try {
      const io = req.app.get('io')
      io?.to('admin').emit('scan-result', {
        id: result.insertId,
        pc_username,
        mode,
        total_scanned,
        suspicious_files,
        high_risk_count,
        timestamp: new Date().toISOString(),
      })
    } catch { /* ws event optional */ }

    return res.json({ success: true, message: 'Результаты сохранены' })
  } catch (err) {
    console.error('Submit scan error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/auth/submit-hashes ──────────────
router.post('/submit-hashes', async (req, res) => {
  try {
    const { token_id, pc_username, hashes } = req.body

    if (!hashes || !Array.isArray(hashes) || hashes.length === 0) {
      return res.status(400).json({ error: 'Не указаны хеши' })
    }

    // token_id обязателен
    if (!token_id || !Number.isInteger(token_id) || token_id <= 0) {
      return res.status(400).json({ error: 'token_id обязателен и должен быть положительным числом' })
    }

    const tokRows = await query(
      'SELECT id, is_active, used_by FROM tokens WHERE id = ?',
      [token_id]
    )

    if (tokRows.length === 0) {
      return res.status(403).json({ error: 'Токен не найден' })
    }

    const tok = tokRows[0]
    if (tok.is_active) {
      return res.status(403).json({ error: 'Токен не был активирован. Используйте токен через экран авторизации.' })
    }
    if (!tok.used_by) {
      return res.status(403).json({ error: 'Токен не был использован' })
    }

    let inserted = 0
    for (const h of hashes) {
      if (!h.sha256 || typeof h.sha256 !== 'string' || h.sha256.length !== 64) continue
      try {
        await query(
          `INSERT IGNORE INTO suspicious_hashes (sha256, file_name, pc_username, token_id, file_size, risk_score)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [h.sha256.toLowerCase(), h.file_name || 'unknown', pc_username || 'unknown', token_id, h.file_size || 0, h.risk_score || 0]
        )
        inserted++
      } catch { /* duplicate — skip */ }
    }

    try {
      const io = req.app.get('io')
      io?.to('admin').emit('new-hashes', {
        count: inserted,
        pc_username: pc_username || 'unknown',
        timestamp: new Date().toISOString(),
      })
    } catch { /* ws event optional */ }

    return res.json({ success: true, inserted, total: hashes.length })
  } catch (err) {
    console.error('Submit hashes error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── GET /api/auth/fetch-hashes ────────────────
router.get('/fetch-hashes', async (req, res) => {
  try {
    const after = req.query.after || '2000-01-01'
    const rows = await query(
      'SELECT sha256, file_name, file_size, created_at FROM suspicious_hashes WHERE status = ? AND created_at > ? ORDER BY created_at DESC LIMIT 500',
      ['confirmed', after]
    )
    return res.json({
      count: rows.length,
      hashes: rows.map(r => ({
        sha256: r.sha256,
        file_name: r.file_name,
        file_size: r.file_size,
        added_at: r.created_at,
      })),
    })
  } catch (err) {
    console.error('Fetch hashes error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── GET /api/auth/safe-hashes ─────────────────
router.get('/safe-hashes', async (req, res) => {
  try {
    const after = req.query.after || '2000-01-01'
    const rows = await query(
      'SELECT sha256, file_name AS fileName, file_size AS fileSize, created_at AS addedAt FROM suspicious_hashes WHERE status = ? AND created_at > ? ORDER BY created_at DESC LIMIT 500',
      ['confirmed', after]
    )
    return res.json(rows.map(r => r.sha256))
  } catch (err) {
    console.error('Safe hashes error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/auth/submit-safe-files ───────────
router.post('/submit-safe-files', async (req, res) => {
  try {
    const { entries } = req.body
    if (!Array.isArray(entries) || entries.length === 0) {
      return res.status(400).json({ error: 'Не указаны safe-файлы' })
    }

    let updated = 0
    let inserted = 0

    for (const entry of entries) {
      if (!entry.partialHash || typeof entry.partialHash !== 'string' || entry.partialHash.length !== 64) continue
      if (!entry.size || typeof entry.size !== 'number') continue

      try {
        const existing = await query(
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
      } catch { /* skip */ }
    }

    return res.json({ success: true, inserted, updated })
  } catch (err) {
    console.error('Submit safe files error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── GET /api/auth/safe-files (community whitelist) ──
router.get('/safe-files', async (req, res) => {
  try {
    const since = req.query.since || '2000-01-01'
    const rows = await query(
      'SELECT partial_hash AS partialHash, file_name AS fileName, file_size AS size, confirm_count AS confirmCount, last_seen AS lastSeen FROM safe_files WHERE last_seen > ? AND confirm_count >= 2 ORDER BY confirm_count DESC LIMIT 2000',
      [since]
    )
    return res.json(rows)
  } catch (err) {
    console.error('Safe files error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

module.exports = router
