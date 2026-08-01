/**
 * Predator — Website API Routes
 *
 * Endpoints for the public website:
 *   POST /api/website/auth/register    — Register new user
 *   POST /api/website/auth/login       — Login
 *   GET  /api/website/auth/me          — Current user profile
 *   GET  /api/website/players          — Public players DB
 *   GET  /api/website/players/:id      — Player detail
 *   GET  /api/website/news             — News list
 *   POST /api/website/check-request    — Create check request (Discord bot or web)
 *   GET  /api/website/check-requests   — User's check requests
 *   POST /api/website/linked-servers   — Link Discord server
 *   GET  /api/website/linked-servers   — List linked servers
 *   POST /api/website/socials/connect  — Connect Discord/Telegram
 *   GET  /api/website/notifications    — User notifications
 */

import { Router } from 'express'
import bcrypt from 'bcryptjs'
import { query } from '../config/database'

const router = Router()

// ═══════════════════════════════════════════════
// PUBLIC: Players DB
// ═══════════════════════════════════════════════

router.get('/players', async (req, res) => {
  try {
    const search = req.query.search as string | undefined
    const risk = req.query.risk as string | undefined
    const page = Number(req.query.page) || 1
    const limit = Number(req.query.limit) || 20
    const offset = (page - 1) * limit

    let where = 'WHERE 1=1'
    const params: any[] = []

    if (search) {
      where += ' AND (display_name LIKE ? OR server_name LIKE ?)'
      params.push('%' + search + '%', '%' + search + '%')
    }
    if (risk && risk !== 'all') {
      where += ' AND risk_level = ?'
      params.push(risk)
    }

    const sql = 'SELECT * FROM player_profiles ' + where + ' ORDER BY last_scan_at DESC LIMIT ? OFFSET ?'
    const rows = await query<any[]>(sql, params.concat([limit, offset]))

    const countSql = 'SELECT COUNT(*) as total FROM player_profiles ' + where
    const [countRow] = await query<any[]>(countSql, params)

    res.json({ players: rows, total: (countRow as any)?.total || 0 })
  } catch (err) {
    console.error('[website:players]', err)
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Failed to load players' } })
  }
})

router.get('/players/:id', async (req, res) => {
  try {
    const rows = await query<any[]>(
      'SELECT * FROM player_profiles WHERE id = ?',
      [req.params.id],
    )
    if (rows.length === 0) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Player not found' } })
    res.json(rows[0])
  } catch (err) {
    console.error('[website:player]', err)
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Failed to load player' } })
  }
})

// ═══════════════════════════════════════════════
// PUBLIC: News
// ═══════════════════════════════════════════════

router.get('/news', async (_req, res) => {
  try {
    const rows = await query<any[]>(
      'SELECT id, title, excerpt, tag, tag_color, created_at FROM news_articles WHERE is_published = TRUE ORDER BY created_at DESC LIMIT 20',
    )
    res.json(rows)
  } catch (err) {
    console.error('[website:news]', err)
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Failed to load news' } })
  }
})

router.get('/news/:id', async (req, res) => {
  try {
    const rows = await query<any[]>(
      'SELECT * FROM news_articles WHERE id = ? AND is_published = TRUE',
      [req.params.id],
    )
    if (rows.length === 0) return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Article not found' } })
    res.json(rows[0])
  } catch (err) {
    console.error('[website:news]', err)
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Failed to load article' } })
  }
})

// ═══════════════════════════════════════════════
// AUTH: Register / Login
// ═══════════════════════════════════════════════

router.post('/auth/register', async (req, res) => {
  try {
    const { email, password, display_name } = req.body
    if (!email || !password || !display_name) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'email, password, display_name required' } })
    }

    // Check existing
    const existing = await query<any[]>('SELECT id FROM website_users WHERE email = ?', [email])
    if (existing.length > 0) {
      return res.status(409).json({ error: { code: 'CONFLICT', message: 'Email already registered' } })
    }

    const password_hash = await bcrypt.hash(password, 10)

    const result = await query<any>(
      'INSERT INTO website_users (email, password_hash, display_name) VALUES (?, ?, ?)',
      [email, password_hash, display_name],
    )

    res.json({ userId: result.insertId, message: 'Registration successful' })
  } catch (err) {
    console.error('[website:register]', err)
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Registration failed' } })
  }
})

router.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'email and password required' } })
    }

    const rows = await query<any[]>(
      'SELECT id, password_hash, display_name, avatar_url, subscription FROM website_users WHERE email = ?',
      [email],
    )
    if (rows.length === 0) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } })
    }

    const valid = await bcrypt.compare(password, rows[0].password_hash)
    if (!valid) {
      return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } })
    }

    // Generate JWT (simplified)
    const jwt = await import('jsonwebtoken')
    const token = jwt.sign(
      { userId: rows[0].id, email },
      process.env.JWT_SECRET || 'predator-website-secret',
      { expiresIn: '7d' },
    )

    res.json({
      token,
      user: {
        id: rows[0].id,
        display_name: rows[0].display_name,
        avatar_url: rows[0].avatar_url,
        subscription: rows[0].subscription,
      },
    })
  } catch (err) {
    console.error('[website:login]', err)
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Login failed' } })
  }
})

// ═══════════════════════════════════════════════
// AUTH: Middleware
// ═══════════════════════════════════════════════

async function requireWebsiteAuth(req: any, res: any, next: any) {
  const auth = req.headers.authorization
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Bearer token required' } })
  }
  try {
    const jwt = await import('jsonwebtoken')
    const payload = jwt.verify(auth.slice(7), process.env.JWT_SECRET || 'predator-website-secret') as any
    req.user = payload
    next()
  } catch {
    return res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid token' } })
  }
}

// ═══════════════════════════════════════════════
// AUTHENTICATED: Profile
// ═══════════════════════════════════════════════

router.get('/auth/me', requireWebsiteAuth, async (req: any, res) => {
  try {
    const rows = await query<any[]>(
      'SELECT id, email, display_name, avatar_url, subscription, created_at FROM website_users WHERE id = ?',
      [req.user.userId],
    )
    if (rows.length === 0) return res.status(404).json({ error: { code: 'NOT_FOUND' } })

    // Get linked socials
    const socials = await query<any[]>(
      'SELECT provider, provider_name, avatar_url, notify_checks, notify_results FROM linked_socials WHERE user_id = ?',
      [req.user.userId],
    )

    // Get linked servers
    const servers = await query<any[]>(
      'SELECT * FROM linked_servers WHERE user_id = ?',
      [req.user.userId],
    )

    res.json({ ...rows[0], socials, servers })
  } catch (err) {
    console.error('[website:me]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

// ═══════════════════════════════════════════════
// AUTHENTICATED: Check Requests
// ═══════════════════════════════════════════════

router.get('/check-requests', requireWebsiteAuth, async (req: any, res) => {
  try {
    const rows = await query<any[]>(
      'SELECT cr.*, ls.guild_name FROM check_requests cr LEFT JOIN linked_servers ls ON cr.server_id = ls.id WHERE ls.user_id = ? ORDER BY cr.created_at DESC LIMIT 50',
      [req.user.userId],
    )
    res.json(rows)
  } catch (err) {
    console.error('[website:check-requests]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

router.post('/check-request', requireWebsiteAuth, async (req: any, res) => {
  try {
    const { server_id, player_name, player_steam_id } = req.body
    if (!server_id || !player_name) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'server_id and player_name required' } })
    }

    // Check subscription limits
    const serverRows = await query<any[]>(
      'SELECT * FROM linked_servers WHERE id = ? AND user_id = ?',
      [server_id, req.user.userId],
    )
    if (serverRows.length === 0) {
      return res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Server not linked' } })
    }

    // Check weekly limit for free users
    const userRows = await query<any[]>(
      'SELECT subscription FROM website_users WHERE id = ?',
      [req.user.userId],
    )
    if (userRows[0]?.subscription === 'free') {
      const weekStart = new Date()
      weekStart.setDate(weekStart.getDate() - weekStart.getDay())
      weekStart.setHours(0, 0, 0, 0)

      const [countRow] = await query<any[]>(
        'SELECT COUNT(*) as cnt FROM check_requests cr JOIN linked_servers ls ON cr.server_id = ls.id WHERE ls.user_id = ? AND cr.created_at >= ?',
        [req.user.userId, weekStart.toISOString()],
      )
      if ((countRow?.cnt || 0) >= 3) {
        return res.status(429).json({ error: { code: 'LIMIT_EXCEEDED', message: 'Weekly limit reached (3 checks). Upgrade to Pro for unlimited.' } })
      }
    }

    const result = await query<any>(
      'INSERT INTO check_requests (server_id, requester_name, player_name, player_steam_id) VALUES (?, (SELECT display_name FROM website_users WHERE id = ?), ?, ?)',
      [server_id, req.user.userId, player_name, player_steam_id || null],
    )

    res.json({ requestId: result.insertId, status: 'pending' })
  } catch (err) {
    console.error('[website:create-request]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

// ═══════════════════════════════════════════════
// AUTHENTICATED: Linked Servers
// ═══════════════════════════════════════════════

router.get('/linked-servers', requireWebsiteAuth, async (req: any, res) => {
  try {
    const rows = await query<any[]>(
      'SELECT * FROM linked_servers WHERE user_id = ?',
      [req.user.userId],
    )
    res.json(rows)
  } catch (err) {
    console.error('[website:servers]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

router.post('/linked-servers', requireWebsiteAuth, async (req: any, res) => {
  try {
    const { discord_guild_id, guild_name, guild_icon } = req.body
    if (!discord_guild_id || !guild_name) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'discord_guild_id and guild_name required' } })
    }

    // Check free user limit (1 server)
    const userRows = await query<any[]>('SELECT subscription FROM website_users WHERE id = ?', [req.user.userId])
    if (userRows[0]?.subscription === 'free') {
      const [srvCount] = await query<any[]>(
        'SELECT COUNT(*) as cnt FROM linked_servers WHERE user_id = ?',
        [req.user.userId],
      )
      if ((srvCount?.cnt || 0) >= 1) {
        return res.status(429).json({ error: { code: 'LIMIT_EXCEEDED', message: 'Free plan: 1 server. Upgrade to Pro.' } })
      }
    }

    const result = await query<any>(
      'INSERT INTO linked_servers (user_id, discord_guild_id, guild_name, guild_icon) VALUES (?, ?, ?, ?)',
      [req.user.userId, discord_guild_id, guild_name, guild_icon || null],
    )

    res.json({ serverId: result.insertId })
  } catch (err) {
    console.error('[website:add-server]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

// ═══════════════════════════════════════════════
// AUTHENTICATED: Social Connections
// ═══════════════════════════════════════════════

router.get('/socials', requireWebsiteAuth, async (req: any, res) => {
  try {
    const rows = await query<any[]>(
      'SELECT provider, provider_name, avatar_url, notify_checks, notify_results FROM linked_socials WHERE user_id = ?',
      [req.user.userId],
    )
    res.json(rows)
  } catch (err) {
    console.error('[website:socials]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

router.post('/socials/connect', requireWebsiteAuth, async (req: any, res) => {
  try {
    const { provider, provider_id, provider_name, avatar_url } = req.body
    if (!provider || !provider_id) {
      return res.status(400).json({ error: { code: 'VALIDATION', message: 'provider and provider_id required' } })
    }

    await query<any>(
      'INSERT INTO linked_socials (user_id, provider, provider_id, provider_name, avatar_url) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE provider_name = VALUES(provider_name), avatar_url = VALUES(avatar_url)',
      [req.user.userId, provider, provider_id, provider_name || '', avatar_url || ''],
    )

    res.json({ connected: true })
  } catch (err) {
    console.error('[website:connect-social]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

// ═══════════════════════════════════════════════
// AUTHENTICATED: Notifications
// ═══════════════════════════════════════════════

router.get('/notifications', requireWebsiteAuth, async (req: any, res) => {
  try {
    const rows = await query<any[]>(
      'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 30',
      [req.user.userId],
    )
    res.json(rows)
  } catch (err) {
    console.error('[website:notifications]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

// ═══════════════════════════════════════════════
// DISCORD BOT: Webhook for check results
// ═══════════════════════════════════════════════

router.post('/webhook/check-result', async (req, res) => {
  try {
    const { request_id, risk_level, scan_token_id, result_summary } = req.body
    if (!request_id || !risk_level) {
      return res.status(400).json({ error: { code: 'VALIDATION' } })
    }

    await query<any>(
      "UPDATE check_requests SET status = 'completed', risk_level = ?, scan_token_id = ?, result_summary = ?, completed_at = NOW() WHERE id = ?",
      [risk_level, scan_token_id || null, JSON.stringify(result_summary || {}), request_id],
    )

    // Update player profile
    const [request] = await query<any[]>('SELECT player_name, server_id FROM check_requests WHERE id = ?', [request_id])
    if (request) {
      const [server] = await query<any[]>('SELECT guild_name FROM linked_servers WHERE id = ?', [request.server_id])
      await query<any>(
        'INSERT INTO player_profiles (display_name, server_name, risk_level, total_scans, cheat_traces, last_scan_at) VALUES (?, ?, ?, 1, ?, NOW()) ON DUPLICATE KEY UPDATE risk_level = CASE WHEN VALUES(risk_level) = \'high\' THEN \'high\' ELSE VALUES(risk_level) END, total_scans = total_scans + 1, cheat_traces = cheat_traces + VALUES(cheat_traces), last_scan_at = NOW()',
        [request.player_name, server?.guild_name || 'Unknown', risk_level, risk_level === 'high' ? 1 : 0],
      )
    }

    res.json({ updated: true })
  } catch (err) {
    console.error('[website:webhook]', err)
    res.status(500).json({ error: { code: 'INTERNAL' } })
  }
})

export default router
