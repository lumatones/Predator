/**
 * Integration tests for additional AUTH routes
 *
 * Tests: POST /api/auth/submit-hashes, /submit-safe-files, /submit-shadow,
 *        GET /api/auth/fetch-hashes, /safe-hashes, /safe-files
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
  mockSuspiciousHash,
  VALID_TOKEN_CLEAN,
  VALID_SHA256,
} from './test-helper'

let app: any

beforeEach(async () => {
  app = await createTestApp()
})

// ═══════════════════════════════════════════════════
// POST /api/auth/submit-hashes
// ═══════════════════════════════════════════════════
describe('POST /api/auth/submit-hashes', () => {
  const validBody = {
    token_id: 1,
    pc_username: 'Player01',
    hashes: [{
      sha256: VALID_SHA256,
      file_name: 'cheat.dll',
      file_size: 12345,
      risk: 'high' as const,
      risk_score: 80,
      matches: ['match1', 'match2'],
    }],
  }

  it('returns 400 for empty body', async () => {
    const res = await request(app).post('/api/auth/submit-hashes').send({})
    expect(res.status).toBe(400)
    expect(res.body.error.code).toBe('VALIDATION_ERROR')
  })

  it('returns 400 for missing token_id', async () => {
    const res = await request(app)
      .post('/api/auth/submit-hashes')
      .send({ hashes: [{ sha256: VALID_SHA256 }] })
    expect(res.status).toBe(400)
  })

  it('returns 403 when token not found', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app)
      .post('/api/auth/submit-hashes')
      .send(validBody)

    expect(res.status).toBe(403)
    expect(res.body.error).toBe('Token not found')
  })

  it('returns 403 when token still active', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: true, used_by: null })
    )

    const res = await request(app)
      .post('/api/auth/submit-hashes')
      .send(validBody)

    expect(res.status).toBe(403)
    expect(res.body.error).toContain('not activated')
  })

  it('returns 200 on successful hash submission', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: 'Player01' })
    )
    mockQuery.mockResolvedValueOnce(mockInsertResult(1))

    const res = await request(app)
      .post('/api/auth/submit-hashes')
      .send(validBody)

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.inserted).toBe(1)
    expect(res.body.updated).toBe(0)
  })

  it('returns 200 with inserted=0 for hashes without sha256/partialHash', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: 'Player01' })
    )

    const res = await request(app)
      .post('/api/auth/submit-hashes')
      .send({ token_id: 1, hashes: [{}] })

    expect(res.status).toBe(200)
    expect(res.body.inserted).toBe(0)
  })

  it('handles partialHash fallback (no sha256)', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: 'Player01' })
    )
    mockQuery.mockResolvedValueOnce(mockInsertResult(1))

    const res = await request(app)
      .post('/api/auth/submit-hashes')
      .send({
        token_id: 1,
        hashes: [{
          partialHash: VALID_SHA256,
          file_name: 'cheat.dll',
          risk: 'high' as const,
        }],
      })

    expect(res.status).toBe(200)
    expect(res.body.inserted).toBe(1)
  })

  it('handles DB insert error gracefully (caught silently per-hash)', async () => {
    mockQuery.mockResolvedValueOnce(
      mockToken({ is_active: false, used_by: 'Player01' })
    )
    // INSERT throws but is caught in the try/catch within the loop
    mockQuery.mockRejectedValueOnce(new Error('DB insert error'))

    const res = await request(app)
      .post('/api/auth/submit-hashes')
      .send(validBody)

    expect(res.status).toBe(200)
    expect(res.body.inserted).toBe(0) // caught silently
  })
})

// ═══════════════════════════════════════════════════
// POST /api/auth/submit-safe-files
// ═══════════════════════════════════════════════════
describe('POST /api/auth/submit-safe-files', () => {
  it('returns 400 for empty body', async () => {
    const res = await request(app).post('/api/auth/submit-safe-files').send({})
    expect(res.status).toBe(400)
  })

  it('returns 400 for missing entries', async () => {
    const res = await request(app)
      .post('/api/auth/submit-safe-files')
      .send({ entries: [] })
    expect(res.status).toBe(400)
  })

  it('returns 200 with inserted count', async () => {
    mockQuery.mockResolvedValueOnce([]) // SELECT existing → none found → INSERT

    const res = await request(app)
      .post('/api/auth/submit-safe-files')
      .send({
        entries: [{
          partialHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          size: 12345,
          fileName: 'safe.dll',
          confirmCount: 1,
        }],
      })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
  })

  it('updates existing safe file on duplicate', async () => {
    mockQuery.mockResolvedValueOnce([{ id: 1, confirm_count: 3 }]) // existing
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app)
      .post('/api/auth/submit-safe-files')
      .send({
        entries: [{
          partialHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          size: 12345,
          confirmCount: 2,
        }],
      })

    expect(res.status).toBe(200)
    expect(res.body.updated).toBe(1)
  })
})

// ═══════════════════════════════════════════════════
// POST /api/auth/submit-shadow
// ═══════════════════════════════════════════════════
describe('POST /api/auth/submit-shadow', () => {
  const validBody = {
    type: 'shadow-findings' as const,
    token_id: 1,
    pc_username: 'Player01',
    findings: [{
      path: 'C:\\file.dll',
      fileName: 'suspicious.dll',
      type: 'file',
      ruleName: 'SUSPICIOUS_BEHAVIOR',
      matches: ['api_call_1'],
      sha256: VALID_SHA256,
    }],
  }

  it('returns 400 for empty body', async () => {
    const res = await request(app).post('/api/auth/submit-shadow').send({})
    expect(res.status).toBe(400)
  })

  it('returns 400 for missing type field', async () => {
    const res = await request(app)
      .post('/api/auth/submit-shadow')
      .send({ findings: [{ fileName: 'test.dll' }] })
    expect(res.status).toBe(400)
  })

  it('returns 200 on successful submission', async () => {
    mockQuery.mockResolvedValueOnce([]) // SELECT dedup check → no existing
    mockQuery.mockResolvedValueOnce(mockInsertResult(1))

    const res = await request(app)
      .post('/api/auth/submit-shadow')
      .send(validBody)

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.inserted).toBe(1)
  })

  it('deduplicates by sha256 + rule_name', async () => {
    mockQuery.mockResolvedValueOnce([{ id: 1 }]) // existing entry → UPDATE
    mockQuery.mockResolvedValueOnce(mockUpdateResult())

    const res = await request(app)
      .post('/api/auth/submit-shadow')
      .send(validBody)

    expect(res.status).toBe(200)
    expect(res.body.deduped).toBe(1)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/auth/fetch-hashes
// ═══════════════════════════════════════════════════
describe('GET /api/auth/fetch-hashes', () => {
  it('returns 200 with hash list', async () => {
    mockQuery.mockResolvedValueOnce(mockSuspiciousHash({
      status: 'confirmed',
      sha256: VALID_SHA256,
    }))

    const res = await request(app).get('/api/auth/fetch-hashes')

    expect(res.status).toBe(200)
    expect(res.body.count).toBe(1)
    expect(res.body.hashes[0].sha256).toBe(VALID_SHA256)
    expect(res.body.hashes[0].tlsh).toBeUndefined()
  })

  it('returns 200 with empty array when no hashes', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/auth/fetch-hashes')

    expect(res.status).toBe(200)
    expect(res.body.count).toBe(0)
    expect(res.body.hashes).toEqual([])
  })

  it('respects the after parameter', async () => {
    mockQuery.mockResolvedValueOnce(mockSuspiciousHash({ status: 'confirmed' }))

    await request(app).get('/api/auth/fetch-hashes?after=2026-06-01')

    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('WHERE status'),
      ['confirmed', '2026-06-01', 50, 0]
    )
  })
})

// ═══════════════════════════════════════════════════
// GET /api/auth/safe-hashes
// ═══════════════════════════════════════════════════
describe('GET /api/auth/safe-hashes', () => {
  it('returns 200 with sha256 array', async () => {
    mockQuery.mockResolvedValueOnce(mockSuspiciousHash({
      status: 'confirmed',
      sha256: VALID_SHA256,
    }))

    const res = await request(app).get('/api/auth/safe-hashes')

    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
    expect(res.body[0]).toBe(VALID_SHA256)
  })

  it('returns 200 with empty array when no confirmed hashes', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/auth/safe-hashes')

    expect(res.status).toBe(200)
    expect(res.body).toEqual([])
  })
})

// ═══════════════════════════════════════════════════
// GET /api/auth/safe-files
// ═══════════════════════════════════════════════════
describe('GET /api/auth/safe-files', () => {
  it('returns 200 with safe files list', async () => {
    mockQuery.mockResolvedValueOnce([
      { partialHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        fileName: 'safe.dll', size: 12345, confirmCount: 5,
        lastSeen: '2026-07-01 12:00:00' },
    ])

    const res = await request(app).get('/api/auth/safe-files')

    expect(res.status).toBe(200)
    expect(res.body[0].partialHash).toBeDefined()
    expect(res.body[0].confirmCount).toBe(5)
  })

  it('returns 200 with empty array when no safe files', async () => {
    mockQuery.mockResolvedValueOnce([])

    const res = await request(app).get('/api/auth/safe-files')

    expect(res.status).toBe(200)
    expect(res.body).toEqual([])
  })

  it('respects the since parameter', async () => {
    mockQuery.mockResolvedValueOnce([])

    await request(app).get('/api/auth/safe-files?since=2026-07-01')

    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining('WHERE last_seen'),
      ['2026-07-01', 50, 0]
    )
  })
})
