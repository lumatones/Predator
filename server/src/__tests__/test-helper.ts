/**
 * Test helper — creates isolated Express apps for integration testing.
 *
 * Mocks the database to avoid needing a real MySQL connection.
 * Tests run fast, isolated, and deterministically.
 */
import express from 'express'
import { vi } from 'vitest'
import type { Request, Response, NextFunction } from 'express'

// ── Mock the database BEFORE importing the route ──
export const mockQuery = vi.fn()

vi.mock('../config/database', () => ({
  query: mockQuery,
  getDb: vi.fn(),
  testConnection: vi.fn().mockResolvedValue(true),
}))

// ── Mock JWT auth (used by admin routes) ──
vi.mock('../middleware/auth', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...(actual as any),
    verifyToken: (req: Request, _res: Response, next: NextFunction) => {
      ;(req as any).admin = { id: 1, username: 'testadmin', role: 'superadmin' }
      next()
    },
    generateToken: (admin: any) => `test-jwt-${admin.id}-${admin.username}`,
  }
})

// ── Mock classifier (used by submit-scan) ──
vi.mock('../services/classifier', () => ({
  classifyBatch: vi.fn().mockResolvedValue({
    stats: { autoSafe: 0, autoMalicious: 0, pending: 0 },
  }),
  autoPromoteShadowRules: vi.fn().mockResolvedValue(undefined),
  startAutoClassifier: vi.fn(),
  stopAutoClassifier: vi.fn(),
}))

// ── Mock metrics (used by server index but not needed for isolated route tests) ──
vi.mock('../middleware/metrics', () => ({
  metricsMiddleware: (_req: any, _res: any, next: any) => next(),
  metricsRouter: express.Router(),
  startMetricsUpdater: vi.fn(),
  trackScan: vi.fn(),
  trackHashSubmission: vi.fn(),
  trackHashConfirmed: vi.fn(),
  trackTokenUsed: vi.fn(),
}))

// ── Mock bcrypt for admin login tests ──
vi.mock('bcryptjs', () => ({
  default: {
    compare: vi.fn().mockResolvedValue(true),
    hash: vi.fn().mockResolvedValue('$2a$10$hash'),
  },
  compare: vi.fn().mockResolvedValue(true),
  hash: vi.fn().mockResolvedValue('$2a$10$hash'),
}))

import bcrypt from 'bcryptjs'

/**
 * Create a test app with ONLY auth routes mounted.
 */
export async function createTestApp(): Promise<express.Express> {
  mockQuery.mockReset()

  const authRoutes = (await import('../routes/auth')).default

  const app = express()
  app.use(express.json())

  // Mock `app.get('io')` for WebSocket events
  app.set('io', {
    to: () => ({ emit: vi.fn() }),
  })

  app.use('/api/auth', authRoutes)

  // Global error handler
  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled error:', err)
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred' } })
  })

  return app
}

/**
 * Create a test app with admin routes mounted.
 * verifyToken is mocked to auto-authenticate as testadmin.
 */
export async function createAdminTestApp(): Promise<express.Express> {
  mockQuery.mockReset()

  const adminRoutes = (await import('../routes/admin')).default

  const app = express()
  app.use(express.json())

  app.set('io', {
    to: () => ({ emit: vi.fn() }),
  })

  app.use('/api/admin', adminRoutes)

  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled error:', err)
    res.status(500).json({ error: 'Internal server error' })
  })

  return app
}

/**
 * Create a test app with v1 routes mounted.
 */
export async function createV1TestApp(): Promise<express.Express> {
  mockQuery.mockReset()

  const v1Routes = (await import('../routes/v1')).default

  const app = express()
  app.use(express.json())

  app.set('io', {
    to: () => ({ emit: vi.fn() }),
  })

  app.use('/api/v1', v1Routes)

  app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled error:', err)
    res.status(500).json({ error: 'Internal server error' })
  })

  return app
}

// ── Mock data factories ──

export function mockToken(overrides: Partial<{
  id: number
  code: string
  is_active: boolean | number
  used_by: string | null
  used_at: string | null
  created_at: string
}> = {}) {
  return [
    {
      id: overrides.id ?? 1,
      code: overrides.code ?? 'AABBCCDDEEFF00112233445566778899',
      is_active: (overrides.is_active as boolean) ?? true,
      used_by: overrides.used_by ?? null,
      used_at: overrides.used_at ?? null,
      created_at: overrides.created_at ?? '2026-01-01 00:00:00',
    },
  ]
}

export function mockAdmin(overrides: Partial<{
  id: number
  username: string
  password_hash: string
  role: string
}> = {}) {
  return [
    {
      id: overrides.id ?? 1,
      username: overrides.username ?? 'admin',
      password_hash: overrides.password_hash ?? '$2a$10$hash',
      role: overrides.role ?? 'superadmin',
    },
  ]
}

export function mockRequest(overrides: Partial<{
  id: number
  pc_username: string
  status: string
  created_at: string
  expires_at: string | null
  approved_by: number | null
  approved_at: string | null
}> = {}) {
  return [
    {
      id: overrides.id ?? 1,
      pc_username: overrides.pc_username ?? 'Player01',
      status: overrides.status ?? 'pending',
      created_at: overrides.created_at ?? '2026-07-01 12:00:00',
      expires_at: overrides.expires_at ?? null,
      approved_by: overrides.approved_by ?? null,
      approved_at: overrides.approved_at ?? null,
    },
  ]
}

export function mockTokenRow(overrides: Partial<{
  id: number
  code: string
  is_active: boolean
  used_by: string | null
  used_at: string | null
  created_at: string
  created_by_name: string | null
}> = {}) {
  return [
    {
      id: overrides.id ?? 1,
      code: overrides.code ?? 'AABBCCDDEEFF00112233445566778899',
      is_active: overrides.is_active ?? true,
      used_by: overrides.used_by ?? null,
      used_at: overrides.used_at ?? null,
      created_at: overrides.created_at ?? '2026-07-01 12:00:00',
      created_by_name: overrides.created_by_name ?? 'admin',
    },
  ]
}

export function mockSuspiciousHash(overrides: Partial<{
  id: number
  sha256: string
  file_name: string
  pc_username: string | null
  file_size: number
  risk_score: number
  status: string
  reviewed_by: number | null
  reviewed_by_name: string | null
  reviewed_at: string | null
  created_at: string
}> = {}) {
  return [
    {
      id: overrides.id ?? 1,
      sha256: overrides.sha256 ?? 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      file_name: overrides.file_name ?? 'suspicious.dll',
      pc_username: overrides.pc_username ?? 'Player01',
      file_size: overrides.file_size ?? 12345,
      risk_score: overrides.risk_score ?? 75,
      status: overrides.status ?? 'pending',
      reviewed_by: overrides.reviewed_by ?? null,
      reviewed_by_name: overrides.reviewed_by_name ?? null,
      reviewed_at: overrides.reviewed_at ?? null,
      created_at: overrides.created_at ?? '2026-07-01 12:00:00',
    },
  ]
}

export function mockScanResult(overrides: Partial<{
  id: number
  pc_username: string
  mode: string
  total_scanned: number
  suspicious_files: number
  high_risk_count: number
  created_at: string
  results_json: string | null
}> = {}) {
  return [
    {
      id: overrides.id ?? 1,
      pc_username: overrides.pc_username ?? 'Player01',
      mode: overrides.mode ?? 'full',
      total_scanned: overrides.total_scanned ?? 1000,
      suspicious_files: overrides.suspicious_files ?? 3,
      high_risk_count: overrides.high_risk_count ?? 1,
      created_at: overrides.created_at ?? '2026-07-01 12:00:00',
      results_json: overrides.results_json ?? null,
    },
  ]
}

export function mockShadowFinding(overrides: Partial<{
  id: number
  pc_username: string
  file_name: string
  rule_name: string
  sha256: string | null
  occurrence_count: number
  unique_pcs: number
  status: string
  matches: string | null
  created_at: string
}> = {}) {
  return [
    {
      id: overrides.id ?? 1,
      pc_username: overrides.pc_username ?? 'Player01',
      scan_mode: 'full',
      file_path: 'C:\\file.dll',
      file_name: overrides.file_name ?? 'suspicious.dll',
      file_type: 'file',
      rule_name: overrides.rule_name ?? 'SUSPICIOUS_BEHAVIOR',
      matches: overrides.matches ?? '["suspicious_api_call"]',
      sha256: overrides.sha256 ?? 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      tlsh: null,
      occurrence_count: overrides.occurrence_count ?? 3,
      unique_pcs: overrides.unique_pcs ?? 2,
      status: overrides.status ?? 'shadow',
      promoted_by: null,
      promoted_by_name: null,
      promoted_at: null,
      created_at: overrides.created_at ?? '2026-07-01 12:00:00',
    },
  ]
}

export function mockCountResult(count: number = 5) {
  return [{ cnt: count }]
}

export function mockInsertResult(insertId = 1) {
  return { insertId, affectedRows: 1 } as any
}

export function mockUpdateResult(affectedRows = 1) {
  return { affectedRows } as any
}

export const VALID_TOKEN = 'AABBCCDD-EEFF0011-22334455-66778899'
export const VALID_TOKEN_CLEAN = 'AABBCCDDEEFF00112233445566778899'
export const VALID_SHA256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

// Mock bcrypt compare for login tests
export function mockBcryptCompare(result: boolean) {
  ;(bcrypt.compare as any).mockResolvedValue(result)
}
