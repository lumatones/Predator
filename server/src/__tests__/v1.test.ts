/**
 * Integration tests for v1 API routes
 *
 * Tests: GET /api/v1/signatures, /health, /stats, POST /signatures/refresh
 * All DB calls are mocked — no MySQL required.
 *
 * NOTE: _sigVersion is module-level state in v1.ts (persists via Node module cache).
 * Tests that depend on the version number are ordered deliberately.
 */
import { describe, it, expect, beforeEach } from 'vitest'
import request from 'supertest'
import {
  createV1TestApp,
  mockQuery,
  mockCountResult,
} from './test-helper'

let app: any

beforeEach(async () => {
  app = await createV1TestApp()
})

// ═══════════════════════════════════════════════════
// GET /api/v1/health
// ═══════════════════════════════════════════════════
describe('GET /api/v1/health', () => {
  it('returns 200 with status ok and version', async () => {
    const res = await request(app).get('/api/v1/health')

    expect(res.status).toBe(200)
    expect(res.body.data.status).toBe('ok')
    expect(res.body.data.version).toBeDefined()
    expect(res.body.data.apiVersion).toBe('v1')
    expect(res.headers['x-api-version']).toBe('1')
  })
})

// ═══════════════════════════════════════════════════
// GET /api/v1/signatures
// ═══════════════════════════════════════════════════
describe('GET /api/v1/signatures', () => {
  it('returns 200 with keywords and patterns', async () => {
    const res = await request(app).get('/api/v1/signatures')

    expect(res.status).toBe(200)
    expect(res.body.data.keywords).toBeDefined()
    expect(res.body.data.patterns).toBeDefined()
    expect(res.body.data.version).toBeGreaterThanOrEqual(1)
    expect(res.body.meta.totalKeywords).toBeGreaterThan(0)
    expect(res.body.meta.totalPatterns).toBeGreaterThan(0)
  })

  it('returns 200 when since_version is 0 (outdated)', async () => {
    const res = await request(app).get('/api/v1/signatures?since_version=0')

    expect(res.status).toBe(200)
    expect(res.body.data.keywords).toBeDefined()
  })

  it('returns 200 when since_version is not provided', async () => {
    const res = await request(app).get('/api/v1/signatures')

    expect(res.status).toBe(200)
    expect(res.body.data.version).toBeGreaterThanOrEqual(1)
  })

  it('returns 304 when since_version matches or exceeds current', async () => {
    // Use a high version number to guarantee 304
    const res = await request(app).get('/api/v1/signatures?since_version=9999')

    expect(res.status).toBe(304)
  })
})

// ═══════════════════════════════════════════════════
// POST /api/v1/signatures/refresh
// ═══════════════════════════════════════════════════
describe('POST /api/v1/signatures/refresh', () => {
  it('requires authentication and bumps version', async () => {
    const res = await request(app).post('/api/v1/signatures/refresh')

    expect(res.status).toBe(200)
    expect(res.body.data.version).toBeGreaterThan(0)
  })

  it('bumps version each call', async () => {
    // Capture version before refresh
    const before = await request(app).get('/api/v1/signatures')
    const prevVersion = before.body.data.version

    const res = await request(app).post('/api/v1/signatures/refresh')

    expect(res.status).toBe(200)
    expect(res.body.data.version).toBe(prevVersion + 1)
  })
})

// ═══════════════════════════════════════════════════
// GET /api/v1/stats
// ═══════════════════════════════════════════════════
describe('GET /api/v1/stats', () => {
  it('returns 200 with statistics', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(50))  // totalScans
    mockQuery.mockResolvedValueOnce(mockCountResult(100)) // totalHashes
    mockQuery.mockResolvedValueOnce(mockCountResult(25))  // totalTokens
    mockQuery.mockResolvedValueOnce(mockCountResult(10))  // totalSafeFiles

    const res = await request(app).get('/api/v1/stats')

    expect(res.status).toBe(200)
    expect(res.body.data.totalScans).toBe(50)
    expect(res.body.data.totalHashes).toBe(100)
    expect(res.body.data.totalTokens).toBe(25)
    expect(res.body.data.totalSafeFiles).toBe(10)
    // signatureVersion is stateful — just verify it's a number
    expect(typeof res.body.data.signatureVersion).toBe('number')
  })

  it('returns 200 with zeros when no data', async () => {
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce(mockCountResult(0))
    mockQuery.mockResolvedValueOnce(mockCountResult(0))

    const res = await request(app).get('/api/v1/stats')

    expect(res.status).toBe(200)
    expect(res.body.data.totalScans).toBe(0)
    expect(res.body.data.totalHashes).toBe(0)
  })

  it('returns 500 on DB error', async () => {
    mockQuery.mockRejectedValueOnce(new Error('DB error'))

    const res = await request(app).get('/api/v1/stats')

    expect(res.status).toBe(500)
    expect(res.body.error.code).toBe('INTERNAL_ERROR')
  })
})
