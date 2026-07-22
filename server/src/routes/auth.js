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

module.exports = router
