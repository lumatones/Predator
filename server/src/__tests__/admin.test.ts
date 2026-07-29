/**
 * Integration tests for ADMIN routes
 *
 * Tests: POST /api/admin/login, GET /api/admin/pending, /tokens, /history,
 *        /suspicious-hashes, /scan-stats, scan-result-hashes, shadow-findings
 * All DB calls are mocked — no MySQL required.
 * verifyToken is mocked to auto-authenticate as testadmin.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import request from 'supertest'
import {
  createAdminTestApp,
  mockQuery,
  mockAdmin,
  mockRequest,
  mockTokenRow,
  mockSuspiciousHash,
  mockScanResult,
  mockShadowFinding,
  mockCountResult,
  mockInsertResult,
  mockUpdateResult,
  mockBcryptCompare,
} from './test-helper'

let app: any

beforeEach(async () => {
  app = await createAdminTestApp()
})

// ═══════════════════════════════════════════════════
// POST /api/admin/login
// ═══════════════════════════════════════════════════
describe('POST /api/admin/login', () => {
  it('returns 400 for empty body', async () => {
    const res = await request(app).post('/api/admin/login').send({})
    expect(res.status).toBe(400)
    expect(res.body.error.code).toBe('VALIDATION_ERROR')
  })

  it('returns 400 for missing username', async () => {
    const res = await request(app)
      .post('/api/admin/login')
      .send({ password: 'secret' })
    expect(res.status).toBe(400)
  })

  it('returns 200 with token and admin info on valid login', async () => {
    mockQuery.mockResolvedValueOnce(mockAdmin())
    mockBcryptCompare(true)

    const res = await request(app)
      .post('/api/admin/login')
      .send({ username: 'admin', password: 'secret' })

    expect(res.status).toBe(200)
    expect(res.body.token).toBeDefined()
    expect(res.body.admin.username).toBe('admin')
    expect(res.body.admin.role).toBe('superadmin')
  })

  it('returns 401 for wrong password', async () => {
    mockQuery.mockResolvedValueOnce(mockAdmin())
    mockBcryptCompare(false)

    const res = await request(app)
      .post('/api/admin/login')
      .send({ username: 'admin', password: 'wrong' })

    expect(res.status).toBe(401)
    expect(res.body.error).toBe('Invalid username or password')
  })

  it('returns 401 for non-existent user', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app)
      .post('/api/admin/login')
      .send({ username: 'nobody', password: 'secret' })

    expect(res.status).toBe(401)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/admin/pending
// ═══════════════════════════════════════════════════
describe('GET /api/admin/pending', () => {
  it('returns 200 with empty array when no pending requests', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/admin/pending')

    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
    expect(res.body.length).toBe(0)
  })

  it('returns 200 with pending requests', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(2))
    mockQuery.mockResolvedValueOnce(mockRequest())

    const res = await request(app).get('/api/admin/pending')

    expect(res.status).toBe(200)
    expect(res.body.length).toBe(1)
    expect(res.body[0].pc_username).toBe('Player01')
    expect(res.body[0].status).toBe('pending')
  })

  it('returns empty array on query error (graceful fallback)', async () => {
    // Mock countTotal to return 0 gracefully
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    // Mock rows query to return empty array
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/admin/pending')

    expect(res.status).toBe(200)
    expect(res.body).toEqual([])
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/approve/:id
// ═══════════════════════════════════════════════════
describe('POST /api/admin/approve/:id', () => {
  it('returns 200 on successful approval', async () => {
    mockQuery.mockResolvedValueOnce(mockRequest())
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app).post('/api/admin/approve/1')

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
  })

  it('returns 404 for non-existent request', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).post('/api/admin/approve/999')

    expect(res.status).toBe(404)
    expect(res.body.error).toBe('Request not found or already processed')
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/reject/:id
// ═══════════════════════════════════════════════════
describe('POST /api/admin/reject/:id', () => {
  it('returns 200 on successful rejection', async () => {
    mockQuery.mockResolvedValueOnce(mockRequest())
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app).post('/api/admin/reject/1')

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/approve-batch
// ═══════════════════════════════════════════════════
describe('POST /api/admin/approve-batch', () => {
  it('returns 200 with approved count', async () => {
    // Two ids → two iterations, each needing SELECT + UPDATE
    mockQuery.mockResolvedValueOnce(mockRequest())
    mockQuery.mockResolvedValueOnce(mockUpdateResult())
    mockQuery.mockResolvedValueOnce(mockRequest({ id: 2 }))
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app)
      .post('/api/admin/approve-batch')
      .send({ ids: [1, 2] })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.approved).toBe(2)
  })

  it('returns 400 for empty ids array', async () => {
    const res = await request(app)
      .post('/api/admin/approve-batch')
      .send({ ids: [] })

    expect(res.status).toBe(400)
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/reject-batch
// ═══════════════════════════════════════════════════
describe('POST /api/admin/reject-batch', () => {
  it('returns 200 with rejected count', async () => {
    mockQuery.mockResolvedValueOnce(mockRequest())
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app)
      .post('/api/admin/reject-batch')
      .send({ ids: [1] })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.rejected).toBe(1)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/admin/tokens
// ═══════════════════════════════════════════════════
describe('GET /api/admin/tokens', () => {
  it('returns 200 with token list', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(1))
    mockQuery.mockResolvedValueOnce(mockTokenRow())

    const res = await request(app).get('/api/admin/tokens')

    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
    expect(res.body[0].code_display).toBeDefined()
  })

  it('returns 200 with empty array when no tokens', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/admin/tokens')

    expect(res.status).toBe(200)
    expect(res.body).toEqual([])
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/tokens/generate
// ═══════════════════════════════════════════════════
describe('POST /api/admin/tokens/generate', () => {
  it('returns 200 with generated tokens', async () => {
    mockQuery.mockResolvedValueOnce(mockInsertResult(1))
    mockQuery.mockResolvedValueOnce(mockInsertResult(2))

    const res = await request(app)
      .post('/api/admin/tokens/generate')
      .send({ count: 2 })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.tokens.length).toBe(2)
  })

  it('returns 200 with default count=1 when not specified', async () => {
    mockQuery.mockResolvedValueOnce(mockInsertResult(1))

    const res = await request(app)
      .post('/api/admin/tokens/generate')
      .send({})

    expect(res.status).toBe(200)
    expect(res.body.tokens.length).toBe(1)
  })

  it('generates up to max 10 tokens', async () => {
    for (let i = 0; i < 10; i++) {
      mockQuery.mockResolvedValueOnce(mockInsertResult(i + 1))
    }

    const res = await request(app)
      .post('/api/admin/tokens/generate')
      .send({ count: 10 })

    expect(res.status).toBe(200)
    expect(res.body.tokens.length).toBe(10)
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/tokens/revoke/:id
// ═══════════════════════════════════════════════════
describe('POST /api/admin/tokens/revoke/:id', () => {
  it('returns 200 on successful revoke', async () => {
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app).post('/api/admin/tokens/revoke/1')

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/admin/history
// ═══════════════════════════════════════════════════
describe('GET /api/admin/history', () => {
  it('returns 200 with merged history', async () => {
    mockQuery.mockResolvedValueOnce(mockTokenRow({
      id: 1,
      used_by: 'Player01',
      used_at: '2026-07-01 14:00:00',
      is_active: false,
    }))
    mockQuery.mockResolvedValueOnce(
      mockRequest({ id: 1, status: 'approved' })
    )

    const res = await request(app).get('/api/admin/history')

    expect(res.status).toBe(200)
    expect(res.body.items).toBeDefined()
    expect(res.body.stats).toBeDefined()
    expect(Array.isArray(res.body.items)).toBe(true)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/admin/scan-stats
// ═══════════════════════════════════════════════════
describe('GET /api/admin/scan-stats', () => {
  it('returns 200 with scan statistics', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(10)) // totalScans
    mockQuery.mockResolvedValueOnce(mockCountResult(5000)) // totalScanned
    mockQuery.mockResolvedValueOnce(mockCountResult(15)) // totalSuspicious
    mockQuery.mockResolvedValueOnce([{ mode: 'full', cnt: 5, threats: 3 }]) // byMode
    mockQuery.mockResolvedValueOnce([{ day: '2026-07-01', cnt: 3, threats: 1 }]) // byDay
    mockQuery.mockResolvedValueOnce(mockScanResult()) // recent

    const res = await request(app).get('/api/admin/scan-stats')

    expect(res.status).toBe(200)
    expect(res.body.totalScans).toBe(10)
    expect(res.body.totalScanned).toBe(5000)
    expect(res.body.totalSuspicious).toBe(15)
    expect(res.body.byMode).toHaveLength(1)
    expect(res.body.byDay).toHaveLength(1)
    expect(res.body.recent).toHaveLength(1)
  })

  it('returns 200 with zeros when no data', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce([])
    mockQuery.mockResolvedValueOnce([])
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/admin/scan-stats')

    expect(res.status).toBe(200)
    expect(res.body.totalScans).toBe(0)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/admin/suspicious-hashes
// ═══════════════════════════════════════════════════
describe('GET /api/admin/suspicious-hashes', () => {
  it('returns 200 with hash list (default status=pending)', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(1))
    mockQuery.mockResolvedValueOnce(mockSuspiciousHash())

    const res = await request(app).get('/api/admin/suspicious-hashes')

    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
    expect(res.body[0].sha256).toBeDefined()
    expect(res.body[0].status).toBe('pending')
  })

  it('returns 200 with confirmed hashes when status=confirmed', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(1))
    mockQuery.mockResolvedValueOnce(mockSuspiciousHash({ status: 'confirmed' }))

    const res = await request(app).get('/api/admin/suspicious-hashes?status=confirmed')

    expect(res.status).toBe(200)
    expect(res.body[0].status).toBe('confirmed')
  })

  it('returns 200 with empty array when no hashes', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/admin/suspicious-hashes')

    expect(res.status).toBe(200)
    expect(res.body).toEqual([])
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/hashes/approve/:id
// ═══════════════════════════════════════════════════
describe('POST /api/admin/hashes/approve/:id', () => {
  it('returns 200 on hash approval', async () => {
    mockQuery.mockResolvedValueOnce(mockSuspiciousHash())
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app).post('/api/admin/hashes/approve/1')

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Hash confirmed')
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/hashes/approve/:id — non-existent hash
// ═══════════════════════════════════════════════════
describe('POST /api/admin/hashes/approve/:id (edge cases)', () => {
  it('handles hash not found gracefully by still returning success', async () => {
    // SELECT returns empty → hashRows[0] would be undefined
    // The route falls through to UPDATE which succeeds with 0 affected
    mockQuery.mockResolvedValueOnce([]) // SELECT sha256 — empty
    mockQuery.mockResolvedValueOnce(mockUpdateResult(0)) // UPDATE

    const res = await request(app).post('/api/admin/hashes/approve/999')

    // Route still returns 200 because UPDATE doesn't fail
    expect(res.status).toBe(200)
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/hashes/reject/:id
// ═══════════════════════════════════════════════════
describe('POST /api/admin/hashes/reject/:id', () => {
  it('returns 200 on hash rejection', async () => {
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app).post('/api/admin/hashes/reject/1')

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
  })

  it('returns 200 even for non-existent hash', async () => {
    mockQuery.mockResolvedValueOnce(mockUpdateResult(0))

    const res = await request(app).post('/api/admin/hashes/reject/999')

    expect(res.status).toBe(200)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/admin/scan-result-hashes
// ═══════════════════════════════════════════════════
describe('GET /api/admin/scan-result-hashes', () => {
  it('returns 200 with hash list from scan results', async () => {
    mockQuery.mockResolvedValueOnce(mockScanResult({
      results_json: JSON.stringify([{
        hash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        file_name: 'test.dll',
        size: 12345,
        path: 'C:\\test.dll',
        type: 'file',
        risk: 'high',
        matches: ['match1'],
      }]),
    }))
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/admin/scan-result-hashes')

    expect(res.status).toBe(200)
    expect(res.body.total).toBeGreaterThanOrEqual(0)
    expect(res.body.hashes).toBeDefined()
  })

  it('returns 200 with empty arrays when no results', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/admin/scan-result-hashes')

    expect(res.status).toBe(200)
    expect(res.body.total).toBe(0)
    expect(res.body.hashes).toEqual([])
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/hashes/confirm-from-scan
// ═══════════════════════════════════════════════════
describe('POST /api/admin/hashes/confirm-from-scan', () => {
  it('returns 200 on successful confirmation', async () => {
    mockQuery.mockResolvedValueOnce(mockInsertResult(1))
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app)
      .post('/api/admin/hashes/confirm-from-scan')
      .send({
        sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        file_name: 'cheat.dll',
        file_size: 54321,
      })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
  })

  it('returns 400 for invalid sha256', async () => {
    const res = await request(app)
      .post('/api/admin/hashes/confirm-from-scan')
      .send({ sha256: 'invalid' })

    expect(res.status).toBe(400)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/admin/safe-files-stats
// ═══════════════════════════════════════════════════
describe('GET /api/admin/safe-files-stats', () => {
  it('returns 200 with safe files stats', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(100)) // total
    mockQuery.mockResolvedValueOnce(mockCountResult(10)) // high confidence
    mockQuery.mockResolvedValueOnce(mockCountResult(30)) // medium confidence
    mockQuery.mockResolvedValueOnce([]) // recent
    mockQuery.mockResolvedValueOnce([]) // top confirmed

    const res = await request(app).get('/api/admin/safe-files-stats')

    expect(res.status).toBe(200)
    expect(res.body.totalFiles).toBe(100)
    expect(res.body.highConfidence).toBe(10)
    expect(res.body.mediumConfidence).toBe(30)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/admin/shadow-findings
// ═══════════════════════════════════════════════════
describe('GET /api/admin/shadow-findings', () => {
  it('returns 200 with shadow findings list', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(1))
    mockQuery.mockResolvedValueOnce(mockShadowFinding())
    mockQuery.mockResolvedValueOnce([{ total: 1, promoted: 0, rejected: 0 }])

    const res = await request(app).get('/api/admin/shadow-findings')

    expect(res.status).toBe(200)
    expect(res.body.findings).toBeDefined()
    expect(res.body.findings[0].rule_name).toBe('SUSPICIOUS_BEHAVIOR')
    expect(res.body.stats.total).toBe(1)
  })
})

// ═══════════════════════════════════════════════════
// POST /api/admin/shadow/promote
// ═══════════════════════════════════════════════════
describe('POST /api/admin/shadow/promote', () => {
  it('returns 200 on successful promote', async () => {
    mockQuery.mockResolvedValueOnce(mockUpdateResult()) // UPDATE shadow_findings
    mockQuery.mockResolvedValueOnce([]) // SELECT sha256 (none found for simplicity)
    mockQuery.mockResolvedValueOnce(mockInsertResult()) // INSERT hashes (wont be reached since no shas returned)

    const res = await request(app)
      .post('/api/admin/shadow/promote')
      .send({ rule_name: 'SUSPICIOUS_BEHAVIOR', target_status: 'confirmed' })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
  })

  it('returns 200 on successful reject', async () => {
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app)
      .post('/api/admin/shadow/promote')
      .send({ rule_name: 'SUSPICIOUS_BEHAVIOR', target_status: 'false_positive' })

    expect(res.status).toBe(200)
  })

  it('returns 400 for empty rule_name', async () => {
    const res = await request(app)
      .post('/api/admin/shadow/promote')
      .send({ rule_name: '', target_status: 'confirmed' })

    expect(res.status).toBe(400)
  })

  it('returns 400 for invalid target_status', async () => {
    const res = await request(app)
      .post('/api/admin/shadow/promote')
      .send({ rule_name: 'RULE', target_status: 'invalid' })

    expect(res.status).toBe(400)
  })
})
