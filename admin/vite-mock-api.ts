import type { Plugin } from 'vite'

const MOCK_TOKEN = 'mock-jwt-token'

const admin = { id: 1, username: 'admin', role: 'admin' }

const pending = [
  { id: 1, pc_username: 'PC-ALPHA', status: 'pending', created_at: new Date().toISOString(), expires_at: null },
  { id: 2, pc_username: 'PC-BETA', status: 'pending', created_at: new Date().toISOString(), expires_at: null },
]

const tokens = [
  { id: 1, code: '1234567890ABCDEF1234567890ABCDEF', code_display: '12345678-90ABCDEF-12345678-90ABCDEF', is_active: true, used_by: null, used_at: null, created_at: new Date().toISOString(), created_by_name: 'admin' },
  { id: 2, code: 'FEDCBA0987654321FEDCBA0987654321', code_display: 'FEDCBA09-87654321-FEDCBA09-87654321', is_active: false, used_by: 'PC-ALPHA', used_at: new Date().toISOString(), created_at: new Date().toISOString(), created_by_name: 'admin' },
]

const history = {
  total: 2,
  items: [
    { id: 'tok-1', date: new Date().toISOString(), type: 'token', subType: 'used', description: 'PC-ALPHA', detail: '12345678-90ABCDEF', created_at: new Date().toISOString(), actor: 'admin' },
    { id: 'req-1', date: new Date().toISOString(), type: 'request', subType: 'approved', description: 'PC-BETA', detail: 'Одобрен', created_at: new Date().toISOString(), actor: 'admin' },
  ],
  stats: { totalTokensUsed: 1, totalRequestsProcessed: 1 },
}

const scanStats = {
  totalScans: 12,
  totalScanned: 3450,
  totalSuspicious: 7,
  byMode: [
    { mode: 'full', cnt: 8, threats: 5 },
    { mode: 'quick', cnt: 4, threats: 2 },
  ],
  byDay: [
    { day: '2024-01-01', cnt: 2, threats: 0 },
    { day: '2024-01-02', cnt: 5, threats: 1 },
  ],
  recent: [
    { id: 1, pc_username: 'PC-ALPHA', mode: 'full', total_scanned: 300, suspicious_files: 2, high_risk_count: 1, created_at: new Date().toISOString() },
  ],
}

const suspiciousHashes = [
  { id: 1, sha256: 'a'.repeat(64), file_name: 'suspicious.dll', pc_username: 'PC-ALPHA', file_size: 1024, risk_score: 85, status: 'pending', reviewed_by: null, reviewed_by_name: '', reviewed_at: null, created_at: new Date().toISOString() },
]

const scanResultHashes = {
  total: 1,
  hashes: [
    { sha256: 'b'.repeat(64), file_name: 'scan.dll', file_size: 2048, pc_usernames: ['PC-ALPHA'], first_seen: new Date().toISOString(), last_seen: new Date().toISOString(), occurrences: 3, status: 'new' },
  ],
}

export default function mockAdminApi(): Plugin {
  return {
    name: 'mock-admin-api',
    configureServer(server) {
      server.middlewares.use('/api/admin/login', (req, res, next) => {
        if (req.method !== 'POST') return next()
        let body = ''
        req.on('data', (chunk) => { body += chunk })
        req.on('end', () => {
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({ token: MOCK_TOKEN, admin }))
        })
      })

      const mocks: Record<string, unknown> = {
        '/api/admin/pending': pending,
        '/api/admin/tokens': tokens,
        '/api/admin/history': history,
        '/api/admin/scan-stats': scanStats,
        '/api/admin/suspicious-hashes': suspiciousHashes,
        '/api/admin/scan-result-hashes': scanResultHashes,
      }

      for (const [path, data] of Object.entries(mocks)) {
        server.middlewares.use(path, (req, res, next) => {
          if (req.method !== 'GET') return next()
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(data))
        })
      }

      // Mutations
      server.middlewares.use('/api/admin/approve', (req, res, next) => {
        if (req.method !== 'POST') return next()
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ success: true, message: 'Запрос одобрен' }))
      })
      server.middlewares.use('/api/admin/reject', (req, res, next) => {
        if (req.method !== 'POST') return next()
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ success: true, message: 'Запрос отклонён' }))
      })
      server.middlewares.use('/api/admin/tokens/generate', (req, res, next) => {
        if (req.method !== 'POST') return next()
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ success: true, tokens: ['11111111-22222222-33333333-44444444'] }))
      })
      server.middlewares.use('/api/admin/tokens/revoke', (req, res, next) => {
        if (req.method !== 'POST') return next()
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ success: true, message: 'Токен отозван' }))
      })
      server.middlewares.use('/api/admin/hashes/approve', (req, res, next) => {
        if (req.method !== 'POST') return next()
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ success: true, message: 'Хеш подтверждён' }))
      })
      server.middlewares.use('/api/admin/hashes/reject', (req, res, next) => {
        if (req.method !== 'POST') return next()
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ success: true, message: 'Хеш отклонён' }))
      })
      server.middlewares.use('/api/admin/hashes/confirm-from-scan', (req, res, next) => {
        if (req.method !== 'POST') return next()
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ success: true, message: 'Хеш подтверждён как чит и добавлен в базу' }))
      })
    },
  }
}
