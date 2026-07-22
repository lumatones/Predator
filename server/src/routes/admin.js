const express = require('express')
const bcrypt = require('bcryptjs')
const crypto = require('crypto')
const { query } = require('../config/database')
const { generateToken, verifyToken } = require('../middleware/auth')
const router = express.Router()

// ── POST /api/admin/login ─────────────────────
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body
    if (!username || !password) {
      return res.status(400).json({ error: 'Введите логин и пароль' })
    }

    const rows = await query('SELECT * FROM admins WHERE username = ?', [username])
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Неверный логин или пароль' })
    }

    const admin = rows[0]
    const match = await bcrypt.compare(password, admin.password_hash)
    if (!match) {
      return res.status(401).json({ error: 'Неверный логин или пароль' })
    }

    const token = generateToken(admin)
    return res.json({ token, admin: { id: admin.id, username: admin.username, role: admin.role } })
  } catch (err) {
    console.error('Login error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── All routes below require auth ─────────────
router.use(verifyToken)

// ── GET /api/admin/pending ────────────────────
router.get('/pending', async (req, res) => {
  try {
    const rows = await query(
      'SELECT id, pc_username, status, created_at, expires_at FROM requests WHERE status = ? AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY created_at DESC',
      ['pending']
    )
    return res.json(rows)
  } catch (err) {
    console.error('Pending error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/admin/approve/:id ───────────────
router.post('/approve/:id', async (req, res) => {
  try {
    const rows = await query('SELECT * FROM requests WHERE id = ? AND status = ?', [req.params.id, 'pending'])
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Запрос не найден или уже обработан' })
    }

    await query(
      'UPDATE requests SET status = ?, approved_by = ?, approved_at = NOW() WHERE id = ?',
      ['approved', req.admin.id, req.params.id]
    )

    return res.json({ success: true, message: 'Запрос одобрен' })
  } catch (err) {
    console.error('Approve error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/admin/reject/:id ────────────────
router.post('/reject/:id', async (req, res) => {
  try {
    const rows = await query('SELECT * FROM requests WHERE id = ? AND status = ?', [req.params.id, 'pending'])
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Запрос не найден или уже обработан' })
    }

    await query(
      'UPDATE requests SET status = ?, approved_by = ?, approved_at = NOW() WHERE id = ?',
      ['rejected', req.admin.id, req.params.id]
    )

    return res.json({ success: true, message: 'Запрос отклонён' })
  } catch (err) {
    console.error('Reject error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/admin/tokens/generate ───────────
router.post('/tokens/generate', async (req, res) => {
  try {
    const { count = 1 } = req.body
    const tokens = []

    for (let i = 0; i < Math.min(count, 10); i++) {
      const code = crypto.randomBytes(16).toString('hex').toUpperCase()

      await query(
        'INSERT INTO tokens (code, created_by) VALUES (?, ?)',
        [code, req.admin.id]
      )

      // Format: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
      const formatted = code.match(/.{1,8}/g).join('-')
      tokens.push(formatted)
    }

    return res.json({ success: true, tokens })
  } catch (err) {
    console.error('Generate token error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── GET /api/admin/tokens ─────────────────────
router.get('/tokens', async (req, res) => {
  try {
    const rows = await query(`
      SELECT t.id, t.code, t.is_active, t.used_by, t.used_at, t.created_at, a.username AS created_by_name
      FROM tokens t
      LEFT JOIN admins a ON t.created_by = a.id
      ORDER BY t.created_at DESC
      LIMIT 50
    `)

    // Format codes for display
    const formatted = rows.map(r => ({
      ...r,
      code_display: r.code.match(/.{1,8}/g).join('-'),
    }))

    return res.json(formatted)
  } catch (err) {
    console.error('Tokens list error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── POST /api/admin/tokens/revoke/:id ─────────
router.post('/tokens/revoke/:id', async (req, res) => {
  try {
    await query(
      'UPDATE tokens SET is_active = FALSE, revoked_at = NOW() WHERE id = ? AND is_active = TRUE',
      [req.params.id]
    )
    return res.json({ success: true, message: 'Токен отозван' })
  } catch (err) {
    console.error('Revoke error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

// ── GET /api/admin/history ────────────────────
// Полная история: использованные токены + обработанные запросы
router.get('/history', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 200)

    // Used tokens history
    const usedTokens = await query(`
      SELECT
        t.id,
        t.code,
        t.used_by,
        t.used_at,
        t.created_at,
        a.username AS created_by_name,
        'token_used' AS event_type,
        t.used_at AS event_date
      FROM tokens t
      LEFT JOIN admins a ON t.created_by = a.id
      WHERE t.used_by IS NOT NULL
      ORDER BY t.used_at DESC
      LIMIT ?
    `, [limit])

    // Processed requests history (approved/rejected)
    const processedRequests = await query(`
      SELECT
        r.id,
        r.pc_username,
        r.status,
        r.created_at,
        r.approved_at,
        a.username AS approved_by_name,
        CONCAT('request_', r.status) AS event_type,
        COALESCE(r.approved_at, r.created_at) AS event_date
      FROM requests r
      LEFT JOIN admins a ON r.approved_by = a.id
      WHERE r.status IN ('approved', 'rejected')
      ORDER BY event_date DESC
      LIMIT ?
    `, [limit])

    // Format tokens with display codes
    const formattedTokens = usedTokens.map(t => ({
      ...t,
      code_display: t.code?.match(/.{1,8}/g)?.join('-') || '',
    }))

    // Merge and sort by date
    const merged = [
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
        detail: r.status === 'approved' ? 'Одобрен' : 'Отклонён',
        created_at: r.created_at,
        actor: r.approved_by_name || '—',
      })),
    ]

    // Sort by date descending
    merged.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())

    return res.json({
      total: merged.length,
      items: merged.slice(0, limit),
      stats: {
        totalTokensUsed: formattedTokens.length,
        totalRequestsProcessed: processedRequests.length,
      },
    })
  } catch (err) {
    console.error('History error:', err)
    return res.status(500).json({ error: 'Внутренняя ошибка сервера' })
  }
})

module.exports = router
