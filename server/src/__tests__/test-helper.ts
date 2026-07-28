/**
 * Test helper — creates an isolated Express app for integration testing.
 *
 * Mocks the database to avoid needing a real MySQL connection.
 * Tests run fast, isolated, and deterministically.
 */
import express from 'express'
import { vi } from 'vitest'

// ── Mock the database BEFORE importing the route ──
export const mockQuery = vi.fn()

vi.mock('../config/database', () => ({
  query: mockQuery,
  testConnection: vi.fn().mockResolvedValue(true),
}))

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

/**
 * Create a test app with ONLY auth routes mounted.
 * No helmet, no rate limiting, no CORS — just the route handlers.
 */
export async function createTestApp(): Promise<express.Express> {
  // Reset mocks before each test
  mockQuery.mockReset()

  // Dynamic import AFTER mocks are set up
  const authRoutes = (await import('../routes/auth')).default

  const app = express()
  app.use(express.json())

  // Mock `app.get('io')` for WebSocket events (routes call this as optional)
  app.set('io', {
    to: () => ({
      emit: vi.fn(),
    }),
  })

  app.use('/api/auth', authRoutes)

  // Global error handler (same as production)
  app.use(
    (
      err: any,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      console.error('Unhandled error:', err)
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An unexpected error occurred',
        },
      })
    },
  )

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

export function mockInsertResult(insertId = 1) {
  return { insertId } as any
}

export const VALID_TOKEN = 'AABBCCDD-EEFF0011-22334455-66778899'
export const VALID_TOKEN_CLEAN = 'AABBCCDDEEFF00112233445566778899'
