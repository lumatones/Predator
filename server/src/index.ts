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
import { metricsMiddleware, metricsRouter, startMetricsUpdater, trackScan, trackHashSubmission, trackHashConfirmed, trackTokenUsed } from './middleware/metrics'

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
})

// ── Middleware ─────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for simplicity (API only)
  crossOriginEmbedderPolicy: false,
}))
app.use(cors(corsOptions))
app.use(express.json({ limit: '5mb' }))
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

// ── Socket.IO Connection ──────────────────────
io.on('connection', (socket) => {
  console.log(`  WS connected: ${socket.id}`)

  socket.on('join-admin', () => {
    socket.join('admin')
    console.log(`  ${socket.id} joined admin room`)
  })

  socket.on('join-scanner', () => {
    socket.join('scanner')
    console.log(`  ${socket.id} joined scanner room (${io.sockets.adapter.rooms.get('scanner')?.size || 0} clients)`)
  })

  socket.on('disconnect', (reason) => {
    console.log(`  WS disconnected: ${socket.id} (${reason})`)
  })
})

// ── Global error handler ──────────────────────
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('Unhandled error:', err)
  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
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

  server.listen(PORT, '0.0.0.0', () => {
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
    console.log(`  WebSocket on same port           Real-time admin updates\n`)
  })
}

start().catch(console.error)
