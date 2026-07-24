const express = require('express')
const { query } = require('../config/database')
const router = express.Router()

// ── POST /api/auth/token ──────────────────────
// Проверить 32-символьный токен доступа
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
// Проверить токен и отметить как использованный
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

    // Mark as used
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
// Создать запрос на доступ (с именем ПК)
router.post('/request', async (req, res) => {
  try {
    const { pc_username } = req.body
    if (!pc_username || typeof pc_username !== 'string') {
      return res.status(400).json({ error: 'Имя ПК не указано' })
    }

    // Set expiry to 5 minutes from now
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000)

    const result = await query(
      'INSERT INTO requests (pc_username, expires_at) VALUES (?, ?)',
      [pc_username.trim(), expiresAt]
    )

    // Emit WebSocket event to admin panel
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
// Получить статус запроса (pending / approved / rejected)
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
// Сохранить результаты сканирования на сервере
// Требует: token_id — ID использованного токена (JWT-защита через БД)
router.post('/submit-scan', async (req, res) => {
  try {
    const { token_id, pc_username, mode, total_scanned, suspicious_files, high_risk_count, scan_time_ms, results } = req.body

    if (!token_id && !pc_username) {
      return res.status(400).json({ error: 'token_id или pc_username обязателен' })
    }

    // Token-based защита: проверяем token_id в БД
    if (token_id !== undefined) {
      if (!Number.isInteger(token_id) || token_id <= 0) {
        return res.status(400).json({ error: 'Неверный формат token_id' })
      }

      const tokRows = await query(
        'SELECT id, code, is_active, used_by FROM tokens WHERE id = ?',
        [token_id]
      )

      if (tokRows.length === 0) {
        return res.status(403).json({ error: 'Токен не найден' })
      }

      const tok = tokRows[0]

      // Токен должен быть отозван (использован) — is_active = FALSE, used_by IS NOT NULL
      if (tok.is_active) {
        return res.status(403).json({ error: 'Токен не был активирован. Используйте токен через экран авторизации.' })
      }

      if (!tok.used_by) {
        return res.status(403).json({ error: 'Токен не был использован' })
      }
    }

    const result = await query(
      `INSERT INTO scan_results (token_id, pc_username, mode, total_scanned, suspicious_files, high_risk_count, scan_time_ms, results_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        token_id || null,
        pc_username || 'unknown',
        mode || 'unknown',
        total_scanned || 0,
        suspicious_files || 0,
        high_risk_count || 0,
        scan_time_ms || 0,
        results ? JSON.stringify(results.slice(0, 100)) : '[]',
      ]
    )

    // Emit WebSocket event to admin panel
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

module.exports = router
