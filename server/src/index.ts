import dotenv from 'dotenv'
dotenv.config({ override: true })
import express from 'express'
import cors from 'cors'
import http from 'http'
import { Server } from 'socket.io'
import rateLimit from 'express-rate-limit'
import helmet from 'helmet'

import { testConnection, query } from './config/database'
import authRoutes from './routes/auth'
import adminRoutes from './routes/admin'
import v1Routes from './routes/v1'
import { metricsMiddleware, metricsRouter, startMetricsUpdater, stopMetricsUpdater, trackScan, trackHashSubmission, trackHashConfirmed, trackTokenUsed } from './middleware/metrics'
import { wsAuthMiddleware, requireAdmin, getAdmin } from './middleware/ws-auth'
import { requestIdMiddleware } from './middleware/request-id'
import { initAuditLog } from './middleware/audit-log'
import { stopLoginRateLimitCleanup } from './middleware/rate-limit-login'
import { startAutoClassifier, stopAutoClassifier } from './services/classifier'
import { ErrorCode } from './helpers/errors'

const app = express()
const PORT = parseInt(process.env.PORT || '3001')

// ── CORS configuration ─────────────────────────
const ALLOWED_ORIGINS = (process.env.CLIENT_URL || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean)

const corsOptions: cors.CorsOptions = {
  origin: ALLOWED_ORIGINS.length > 0
    ? ALLOWED_ORIGINS
    : '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}

// ── Rate limiting ─────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many requests, try again later' } },
})

// Rate limiting — only on mutation endpoints
const authWriteLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 auth attempts per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many auth attempts' } },
})

// ── HTTP + Socket.IO ──────────────────────────
const server = http.createServer(app)
const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS.length > 0 ? ALLOWED_ORIGINS : '*',
    methods: ['GET', 'POST'],
  },
  pingInterval: 25000,
  pingTimeout: 20000,
  // ── Connection limits ──
  maxHttpBufferSize: 1e6, // 1 MB max payload per message
  connectTimeout: 10000,   // 10s handshake timeout
  // max connections handled via IP tracking below
})

// ── Middleware ─────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}))
app.use(cors(corsOptions))
app.use(express.json({ limit: '5mb' }))
app.use(requestIdMiddleware)
app.use(metricsMiddleware)
app.use(generalLimiter)

// Apply stricter rate limiting to auth POST endpoints only
app.use('/api/auth/token', authWriteLimiter)
app.use('/api/auth/token/use', authWriteLimiter)
app.use('/api/auth/request', authWriteLimiter)
app.use('/api/auth/submit-scan', authWriteLimiter)
app.use('/api/auth/submit-hashes', authWriteLimiter)

app.set('io', io)

// ── Metrics tracking hooks (BEFORE routes — must run first) ──
app.use('/api/auth/submit-scan', (req, _res, next) => {
  if (req.body?.mode) {
    trackScan(req.body.mode, req.body.pc_username || 'unknown', req.body.high_risk_count || 0)
  }
  next()
})
app.use('/api/auth/submit-hashes', (req, _res, next) => {
  if (req.body?.hashes) {
    trackHashSubmission(req.body.pc_username || 'unknown', req.body.hashes.length)
  }
  next()
})
app.use('/api/admin/hashes/approve', (_req, _res, next) => { trackHashConfirmed(); next() })
app.use('/api/admin/hashes/confirm-from-scan', (_req, _res, next) => { trackHashConfirmed(); next() })
app.use('/api/auth/token/use', (_req, _res, next) => { trackTokenUsed(); next() })

// ── Routes ────────────────────────────────────
app.use('/api/auth', authRoutes)
app.use('/api/admin', adminRoutes)
// API v1 — versioned routes (same handlers, maintained separately)
app.use('/api/v1', v1Routes)
// Metrics endpoint (Prometheus)
app.use(metricsRouter)

// ── Health check ──────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '2.0.0', timestamp: new Date().toISOString() })
})

// ── Socket.IO Auth Middleware (runs on EVERY connection) ──
io.use(wsAuthMiddleware)

// ── WebSocket Connection Rate Limiting ──
const WS_MAX_CONNECTIONS_TOTAL = 200
const WS_MAX_CONNECTIONS_PER_IP = 10 // max concurrent sockets per IP
const WS_IP_WINDOW_MS = 60_000 // 1 minute rolling window per IP
const WS_MAX_CONNECTIONS_PER_IP_WINDOW = 5 // max new connections per IP per minute

const wsIpTracker = new Map<string, { connCount: number; windowCount: number; windowStart: number }>()

function getClientIp(socket: import('socket.io').Socket): string {
  const fwd = socket.handshake.headers['x-forwarded-for']
  if (typeof fwd === 'string') return fwd.split(',')[0].trim()
  return socket.handshake.address || 'unknown'
}

function checkWsConnectionLimit(ip: string): boolean {
  const totalClients = io.engine?.clientsCount ?? 0
  if (totalClients >= WS_MAX_CONNECTIONS_TOTAL) return false

  const now = Date.now()
  let entry = wsIpTracker.get(ip)

  if (!entry || now - entry.windowStart > WS_IP_WINDOW_MS) {
    entry = { connCount: 1, windowCount: 1, windowStart: now }
    wsIpTracker.set(ip, entry)
  } else {
    if (entry.connCount >= WS_MAX_CONNECTIONS_PER_IP) return false
    if (entry.windowCount >= WS_MAX_CONNECTIONS_PER_IP_WINDOW) return false
    entry.connCount++
    entry.windowCount++
  }
  return true
}

function releaseIpSlot(ip: string): void {
  const entry = wsIpTracker.get(ip)
  if (!entry) return
  entry.connCount = Math.max(0, entry.connCount - 1)
  if (entry.connCount === 0 && Date.now() - entry.windowStart > WS_IP_WINDOW_MS) {
    wsIpTracker.delete(ip)
  }
}

// Clean up stale IP entries every 2 minutes
let _ttlCleanupTimer: ReturnType<typeof setInterval> | null = null

const _wsCleanupTimer: ReturnType<typeof setInterval> = setInterval(() => {
  const cutoff = Date.now() - WS_IP_WINDOW_MS * 2
  for (const [ip, entry] of wsIpTracker) {
    if (entry.windowStart < cutoff) wsIpTracker.delete(ip)
  }
}, 120_000)

// ── Socket.IO Connection ──────────────────────
const _adminSockets = new Map<string, number>() // socket.id → JWT exp (seconds)

io.on('connection', (socket) => {
  const ip = getClientIp(socket)

  if (!checkWsConnectionLimit(ip)) {
    console.log(`  WS rejected: ${socket.id} (${ip}) — rate limit exceeded`)
    socket.emit('error', { code: 'RATE_LIMITED', message: 'Too many connections' })
    socket.disconnect(true)
    return
  }

  const admin = getAdmin(socket)
  const isAdmin = !!admin

  // Track admin socket for server-side JWT expiry check
  // Decode JWT payload (already verified by middleware) to extract exp
  if (isAdmin) {
    try {
      const token = socket.handshake.auth?.token
      if (typeof token === 'string' && token.split('.').length >= 2) {
        // JWT uses base64url (RFC 7519), Node only understands base64
        const payloadB64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'))
        if (payload.exp && typeof payload.exp === 'number') {
          _adminSockets.set(socket.id, payload.exp)
        }
      }
    } catch { /* token decode optional */ }
  }

  const label = isAdmin ? `admin:${admin!.username}` : 'scanner:guest'
  console.log(`  WS connected: ${socket.id} (${label}) [${ip}]`)

  socket.on('join-admin', () => {
    if (!requireAdmin(socket)) return
    socket.join('admin')
    console.log(`  ${socket.id} (${admin!.username}) joined admin room`)
  })

  socket.on('join-scanner', () => {
    socket.join('scanner')
    console.log(`  ${socket.id} joined scanner room (${io.sockets.adapter.rooms.get('scanner')?.size || 0} clients)`)
  })

  socket.on('disconnect', (reason) => {
    releaseIpSlot(ip)
    _adminSockets.delete(socket.id)
    console.log(`  WS disconnected: ${socket.id} (${label}, reason: ${reason})`)
  })
})

// ── Periodic JWT expiry check for admin WS sockets ──
const _wsExpiryTimer = setInterval(() => {
  const nowSec = Math.floor(Date.now() / 1000)
  for (const [socketId, exp] of _adminSockets) {
    if (exp <= nowSec) {
      const sock = io.sockets.sockets.get(socketId)
      if (sock) {
        console.log(`  WS expired: ${socketId} (token expired at ${new Date(exp * 1000).toISOString()})`)
        sock.emit('error', { code: 'TOKEN_EXPIRED', message: 'Session expired — please re-login' })
        sock.disconnect(true)
      }
      _adminSockets.delete(socketId)
    }
  }
}, 60_000) // check every 60 seconds

// ── Global error handler ──────────────────────
app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(`[${req.requestId || '???'}] Unhandled error:`, err)
  res.status(err.status || 500).json({
    error: {
      code: err.code || ErrorCode.INTERNAL,
      message: err.message || 'An unexpected error occurred',
      requestId: req.requestId,
    },
  })
})

// ── Start ─────────────────────────────────────
async function start() {
  console.log('\n  Predator API Server v3 (TypeScript + WebSocket + Metrics)\n')

  const dbOk = await testConnection()

  // Start periodic metrics updates (active users gauge)
  startMetricsUpdater(query)

  if (!dbOk) {
    console.log('\n  Running without DB. API will work,\n'
      + '  but DB endpoints will return errors.\n'
      + '  Start WAMP and run: npm run db:init\n')
  }

  // ── TTL Cleanup: delete scan_results older than 90 days (S7) ──
  _ttlCleanupTimer = setInterval(async () => {
    try {
      const result = await query<{ affectedRows: number }>(
        'DELETE FROM scan_results WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)'
      )
      if (result.affectedRows > 0) {
        console.log(`  🧹 TTL cleanup: removed ${result.affectedRows} old scan results (>90 days)`)
      }
    } catch { /* cleanup is best-effort */ }
  }, 6 * 60 * 60 * 1000)

  server.listen(PORT, '0.0.0.0', () => {
    // ── Initialize audit log table (S4) ──
    if (dbOk) initAuditLog().catch(() => {})

    // ── Ensure performance indexes exist (S8) ──
    if (dbOk) {
      (async () => {
        try {
          await query('CREATE INDEX IF NOT EXISTS idx_sr_token ON scan_results(token_id)')
          await query('CREATE INDEX IF NOT EXISTS idx_req_username ON requests(pc_username)')
          console.log('  📊 Performance indexes verified')
        } catch { /* indexes may already exist */ }
      })().catch(() => {})
    }

    console.log(`  Server: http://localhost:${PORT}\n`)
    console.log('  Endpoints:')
    console.log(`  POST /api/auth/token           Check token`)
    console.log(`  POST /api/auth/token/use       Use token`)
    console.log(`  POST /api/auth/request         Request access`)
    console.log(`  GET  /api/auth/status/:id      Request status`)
    console.log(`  POST /api/auth/submit-scan     Submit scan results`)
    console.log(`  POST /api/auth/submit-hashes   Submit suspicious hashes`)
    console.log(`  GET  /api/auth/fetch-hashes    Fetch confirmed hashes`)
    console.log(`  GET  /api/auth/safe-files      Community whitelist`)
    console.log(`  GET  /api/health               Health check`)
    console.log(`  Admin (JWT required):`)
    console.log(`  POST /api/admin/login          Admin login`)
    console.log(`  GET  /api/admin/pending        Pending requests`)
    console.log(`  POST /api/admin/approve/:id    Approve`)
    console.log(`  POST /api/admin/reject/:id     Reject`)
    console.log(`  POST /api/admin/tokens/generate  Generate tokens`)
    console.log(`  GET  /api/admin/tokens         List tokens`)
    console.log(`  POST /api/admin/tokens/revoke/:id  Revoke token`)
    console.log(`  GET  /api/admin/scan-stats      Scan statistics`)
    console.log(`  GET  /api/admin/suspicious-hashes  Pending hashes`)
    console.log(`  POST /api/admin/hashes/approve/:id  Confirm hash`)
    console.log(`  POST /api/admin/hashes/reject/:id   Reject hash`)
    console.log(`  ──────────────────────────────────────────`)
    console.log(`  API v1 (recommended):`)
    console.log(`  GET  /api/v1/health              Health check`)
    console.log(`  GET  /api/v1/signatures          Hot-reload cheat sigs`)
    console.log(`  GET  /api/v1/stats              Public stats`)
    console.log(`  POST /api/v1/signatures/refresh  Force sig version bump`)
    console.log(`  ──────────────────────────────────────────`)
    console.log(`  GET  /metrics                    Prometheus metrics`)
    console.log(`  WebSocket on same port           Real-time admin updates`)
    console.log(`  🤖 Auto-classifier               Rule engine + crowdsourcing`)
    console.log('')

    // ── Start auto-classifier (background) ──
    startAutoClassifier()
  })
}

start().catch(console.error)

// ── Graceful shutdown ──
function gracefulShutdown(signal: string) {
  console.log(`\n  Received ${signal} — shutting down gracefully...`)
  stopAutoClassifier()
  stopMetricsUpdater()
  clearInterval(_wsCleanupTimer)
  clearInterval(_wsExpiryTimer)
  if (_ttlCleanupTimer) clearInterval(_ttlCleanupTimer)
  stopLoginRateLimitCleanup()
  io.close(() => {
    server.close(() => {
      console.log('  Server closed\n')
      process.exit(0)
    })
  })
  // Force exit after 10s if graceful close hangs
  setTimeout(() => process.exit(1), 10000)
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
process.on('SIGINT', () => gracefulShutdown('SIGINT'))
