/**
 * Integration tests for AUTH routes
 *
 * Tests: POST /api/auth/token, /token/use, /request, /submit-scan
 * All DB calls are mocked — no MySQL required.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import request from 'supertest'
import {
  createTestApp,
  mockQuery,
  mockToken,
  mockInsertResult,
  mockUpdateResult,
  VALID_TOKEN,
  VALID_TOKEN_CLEAN,
} from './test-helper'

let app: ReturnType<typeof createTestApp> extends Promise<infer T> ? T : never

beforeEach(async () => {
  app = await createTestApp()
})

// ═══════════════════════════════════════════════════
// POST /api/auth/token
// ═══════════════════════════════════════════════════
describe('POST /api/auth/token', () => {
  it('returns 400 for empty body', async () => {
    const res = await request(app).post('/api/auth/token').send({})
    expect(res.status).toBe(400)
    expect(res.body.error.code).toBe('VALIDATION_ERROR')
  })

  it('returns 400 for too-short token (length != 32 after clean)', async () => {
    const res = await request(app)
      .post('/api/auth/token')
      .send({ token: 'AABBCCDD' })
    expect(res.status).toBe(400)
    expect(res.body.valid).toBe(false)
    expect(res.body.error).toBe('Invalid token format')
  })

  it('returns 200 with token_id for valid unused token', async () => {
    mockQuery.mockResolvedValueOnce(mockToken({ id: 42 }))

    const res = await request(app)
      .post('/api/auth/token')
      .send({ token: VALID_TOKEN })

    expect(res.status).toBe(200)
    expect(res.body.valid).toBe(true)
    expect(res.body.token_id).toBe(42)
  })

  it('returns 404 for non-existent token', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app)
      .post('/api/auth/token')
      .send({ token: VALID_TOKEN })

    expect(res.status).toBe(404)
    expect(res.body.valid).toBe(false)
    expect(res.body.error).toBe('Token not found')
  })

  it('returns 403 for revoked token (is_active=false)', async () => {
    mockQuery.mockResolvedValueOnce(mockToken({ is_active: false }))

    const res = await request(app)
      .post('/api/auth/token')
      .send({ token: VALID_TOKEN })

    expect(res.status).toBe(403)
    expect(res.body.valid).toBe(false)
    expect(res.body.error).toBe('Token revoked')
  })

  it('returns 403 for already-used token', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: true, used_by: 'Player123' }),
    )

    const res = await request(app)
      .post('/api/auth/token')
      .send({ token: VALID_TOKEN })

    expect(res.status).toBe(403)
    expect(res.body.valid).toBe(false)
    expect(res.body.error).toBe('Token already used')
  })

  it('transforms dashed+lowercase token to uppercase hex', async () => {
    mockQuery.mockResolvedValueOnce(mockToken({ id: 1 }))

    const res = await request(app)
      .post('/api/auth/token')
      .send({ token: 'aabbccdd-eeff0011-22334455-66778899' })

    expect(res.status).toBe(200)
    // Verify the query was called with the cleaned token
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('SELECT'),
      [VALID_TOKEN_CLEAN],
    )
  })
})

// ═══════════════════════════════════════════════════
// POST /api/auth/token/use
// ═══════════════════════════════════════════════════
describe('POST /api/auth/token/use', () => {
  it('returns 400 for empty body', async () => {
    const res = await request(app).post('/api/auth/token/use').send({})
    expect(res.status).toBe(400)
  })

  it('activates token with pc_username and returns 200', async () => {
    mockQuery.mockResolvedValueOnce(mockToken({ id: 7 }))
    // Second call: conditional UPDATE tokens SET used_by
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app)
      .post('/api/auth/token/use')
      .send({ token: VALID_TOKEN, pc_username: 'Player42' })

    expect(res.status).toBe(200)
    expect(res.body.valid).toBe(true)
    expect(res.body.token_id).toBe(7)
    expect(res.body.message).toBe('Token activated')
    expect(mockQuery).toHaveBeenLastCalledWith(
      expect.stringContaining('is_active = TRUE AND used_by IS NULL'),
      ['Player42', 7],
    )
  })

  it('rejects a token lost to a concurrent activation', async () => {
    mockQuery.mockResolvedValueOnce(mockToken({ id: 8 }))
    mockQuery.mockResolvedValueOnce({ affectedRows: 0 })

    const res = await request(app)
      .post('/api/auth/token/use')
      .send({ token: VALID_TOKEN, pc_username: 'Player42' })

    expect(res.status).toBe(403)
    expect(res.body.error).toBe('Token already used')
  })

  it('activates token without pc_username (defaults to "unknown")', async () => {
    mockQuery.mockResolvedValueOnce(mockToken({ id: 3 }))
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app)
      .post('/api/auth/token/use')
      .send({ token: VALID_TOKEN })

    expect(res.status).toBe(200)
  })

  it('returns 404 for non-existent token', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app)
      .post('/api/auth/token/use')
      .send({ token: VALID_TOKEN })

    expect(res.status).toBe(404)
  })

  it('returns 403 for already-used token', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: true, used_by: 'Someone' }),
    )

    const res = await request(app)
      .post('/api/auth/token/use')
      .send({ token: VALID_TOKEN })

    expect(res.status).toBe(403)
    expect(res.body.error).toBe('Token already used')
  })

  it('returns 403 for revoked token', async () => {
    mockQuery.mockResolvedValueOnce(mockToken({ is_active: false }))

    const res = await request(app)
      .post('/api/auth/token/use')
      .send({ token: VALID_TOKEN })

    expect(res.status).toBe(403)
    expect(res.body.error).toBe('Token revoked')
  })
})

// ═══════════════════════════════════════════════════
// POST /api/auth/request
// ═══════════════════════════════════════════════════
describe('POST /api/auth/request', () => {
  it('returns 400 for empty body', async () => {
    const res = await request(app).post('/api/auth/request').send({})
    expect(res.status).toBe(400)
  })

  it('returns 400 for missing pc_username', async () => {
    const res = await request(app)
      .post('/api/auth/request')
      .send({ pc_username: '' })

    expect(res.status).toBe(400)
  })

  it('returns 200 with request_id on success', async () => {
    mockQuery.mockResolvedValueOnce(mockInsertResult(15))

    const res = await request(app)
      .post('/api/auth/request')
      .send({ pc_username: 'PlayerTest' })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.request_id).toBe(15)
    expect(res.body.message).toContain('Request sent')
  })

  it('trims pc_username', async () => {
    mockQuery.mockResolvedValueOnce(mockInsertResult(1))

    await request(app)
      .post('/api/auth/request')
      .send({ pc_username: '  PlayerTest  ' })

    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('INSERT'),
      ['PlayerTest', expect.any(Date)],
    )
  })
})

// ═══════════════════════════════════════════════════
// POST /api/auth/submit-scan
// ═══════════════════════════════════════════════════
describe('POST /api/auth/submit-scan', () => {
  const validScanBody = {
    token_id: 1,
    pc_username: 'PlayerTest',
    mode: 'full',
    total_scanned: 1000,
    suspicious_files: 3,
    high_risk_count: 1,
    scan_time_ms: 5000,
    results: [
      {
        path: '/some/file.dll',
        fileName: 'file.dll',
        type: 'file',
        risk: 'high' as const,
        matches: ['match1', 'match2'],
        size: 12345,
      },
    ],
  }

  it('returns 400 for empty body', async () => {
    const res = await request(app).post('/api/auth/submit-scan').send({})
    expect(res.status).toBe(400)
  })

  it('returns 400 for missing token_id', async () => {
    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send({ pc_username: 'Test' })

    expect(res.status).toBe(400)
    expect(res.body.error.code).toBe('VALIDATION_ERROR')
  })

  it('returns 400 for negative token_id', async () => {
    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send({ ...validScanBody, token_id: -1 })

    expect(res.status).toBe(400)
  })

  it('returns 400 for zero token_id', async () => {
    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send({ ...validScanBody, token_id: 0 })

    expect(res.status).toBe(400)
  })

  it('returns 403 when token not found', async () => {
    // Token lookup returns empty
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send(validScanBody)

    expect(res.status).toBe(403)
    expect(res.body.error).toBe('Token not found')
  })

  it('returns 403 when token is still active (not yet used)', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: true, used_by: null }),
    )

    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send(validScanBody)

    expect(res.status).toBe(403)
    expect(res.body.error).toContain('not activated')
  })

  it('returns 403 when token is inactive but never used (is_active=false, used_by=null)', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: null }),
    )

    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send(validScanBody)

    expect(res.status).toBe(403)
    expect(res.body.error).toBe('Token not used')
  })

  it('persists inconclusive status and diagnostics', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: 'PlayerTest' }),
    )
    mockQuery.mockResolvedValueOnce(mockInsertResult(101))

    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send({
        ...validScanBody,
        status: 'inconclusive',
        diagnostics: [{
          detectorId: 'behavioral-process-scanner',
          status: 'unsupported',
          errorCode: 'PLATFORM_UNSUPPORTED',
          errorMessage: 'Windows only',
        }],
      })

    expect(res.status).toBe(200)
    expect(mockQuery.mock.calls).toContainEqual([
      expect.stringContaining('scan_status'),
      expect.arrayContaining([
        'inconclusive',
        JSON.stringify([{
          detectorId: 'behavioral-process-scanner',
          status: 'unsupported',
          errorCode: 'PLATFORM_UNSUPPORTED',
          errorMessage: 'Windows only',
        }]),
      ]),
    ])
  })

  it('returns 200 on successful submission with used token', async () => {
    // Token lookup: used token
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: 'PlayerTest' }),
    )
    // Insert scan_results
    mockQuery.mockResolvedValueOnce(mockInsertResult(100))

    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send(validScanBody)

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.message).toBe('Results saved')
  })

  it('handles submission with minimal fields', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: 'PlayerTest' }),
    )
    mockQuery.mockResolvedValueOnce(mockInsertResult(99))

    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send({ token_id: 1 })

    expect(res.status).toBe(200)
  })

  it('returns 500 on DB error', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: 'PlayerTest' }),
    )
    mockQuery.mockRejectedValueOnce(new Error('DB connection lost'))

    const res = await request(app)
      .post('/api/auth/submit-scan')
      .send(validScanBody)

    expect(res.status).toBe(500)
    expect(res.body.error).toBe('Internal server error')
  })
})

// ═══════════════════════════════════════════════════
// GET /api/auth/status/:id
// ═══════════════════════════════════════════════════
describe('GET /api/auth/status/:id', () => {
  it('returns 200 with request data', async () => {
    mockQuery.mockResolvedValueOnce([
      {
        id: 5,
        pc_username: 'PlayerTest',
        status: 'pending',
        created_at: '2026-07-01T00:00:00Z',
      },
    ])

    const res = await request(app).get('/api/auth/status/5')

    expect(res.status).toBe(200)
    expect(res.body.pc_username).toBe('PlayerTest')
    expect(res.body.status).toBe('pending')
  })

  it('returns 404 for non-existent request', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/auth/status/999')

    expect(res.status).toBe(404)
    expect(res.body.error).toBe('Request not found')
  })
})
