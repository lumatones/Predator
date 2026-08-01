/**
 * Predator Server — Shared Types & Zod Schemas
 * Single source of truth for all API contracts.
 */
import { z } from 'zod'

// ═══════════════════════════════════════════════════
// REUSABLE SCHEMAS
// ═══════════════════════════════════════════════════

export const tokenCodeSchema = z
  .string()
  .min(1, 'Token is required')
  .transform(s => s.replace(/[-\s]/g, '').toUpperCase())
  .refine(s => s.length === 32, 'Token must be 32 hex characters')
  .refine(s => /^[0-9A-F]{32}$/.test(s), 'Token must be hex only')

export const pcUsernameSchema = z
  .string()
  .min(1, 'PC username is required')
  .max(100)
  .trim()

export const positiveIntSchema = z
  .number()
  .int()
  .positive()

export const sha256Schema = z
  .string()
  .length(64)
  .regex(/^[a-f0-9]{64}$/, 'Must be a valid SHA256 hash')

// ═══════════════════════════════════════════════════
// AUTH ROUTE SCHEMAS
// ═══════════════════════════════════════════════════

export const checkTokenSchema = z.object({
  token: z.string().min(1, 'Token is required'),
})

export const useTokenSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  pc_username: z.string().max(100).optional(),
})

export const requestAccessSchema = z.object({
  pc_username: z.string().min(1, 'PC username is required').max(100).trim(),
})

const evidenceRecordSchema = z.object({
  id: z.string().max(255),
  source: z.string().max(100),
  category: z.string().max(100),
  weight: z.number().min(0).max(1),
  confidence: z.number().min(0).max(100),
  explanation: z.string().max(1000),
  raw: z.string().max(2000),
  timestamp: z.string().max(64),
  relatedFindingIds: z.array(z.string().max(255)).max(20).optional(),
})

const scanDiagnosticSchema = z.object({
  detectorId: z.string().max(100),
  status: z.enum(['failed', 'timeout', 'unsupported']),
  errorCode: z.string().max(100).optional(),
  errorMessage: z.string().max(500).optional(),
})

export const submitScanSchema = z.object({
  token_id: z.number().int().positive('token_id must be a positive integer'),
  pc_username: z.string().max(100).optional(),
  client_version: z.string().max(20).optional(),
  mode: z.string().max(20).optional(),
  total_scanned: z.number().int().min(0).optional(),
  suspicious_files: z.number().int().min(0).optional(),
  high_risk_count: z.number().int().min(0).optional(),
  scan_time_ms: z.number().int().min(0).optional(),
  status: z.enum(['complete', 'inconclusive']).optional().default('complete'),
  diagnostics: z.array(scanDiagnosticSchema).max(20).optional(),
  results: z.array(z.object({
    path: z.string(),
    fileName: z.string(),
    type: z.string(),
    risk: z.enum(['high', 'medium', 'low']),
    matches: z.array(z.string()),
    sha256: z.string().optional(),
    partialHash: z.string().max(64).optional(),
    size: z.number().optional(),
    modifiedAt: z.string().optional(),
    findingKind: z.string().optional(),
    evidence: z.array(evidenceRecordSchema).max(50).optional(),
    findingId: z.string().max(255).optional(),
    riskScore: z.number().min(0).max(100).optional(),
    riskExplanation: z.string().max(1000).optional(),
    tlsh: z.string().max(256).optional(),
  })).max(200).superRefine((results, ctx) => {
    const evidenceCount = results.reduce((total, result) => total + (result.evidence?.length ?? 0), 0)
    if (evidenceCount > 1000) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Evidence payload is too large' })
    }
  }).optional(),
})

export const submitHashesSchema = z.object({
  token_id: z.number().int().positive('token_id must be a positive integer'),
  pc_username: z.string().max(100).optional(),
  hashes: z
    .array(
      z.object({
        sha256: z.string().length(64).regex(/^[a-f0-9]{64}$/).optional(),
        partialHash: z.string().length(64).optional(),
        file_name: z.string().max(255).optional(),
        file_path: z.string().optional(),
        file_size: z.number().int().min(0).optional(),
        risk: z.enum(['high', 'medium', 'low']).optional(),
        risk_score: z.number().int().min(0).optional(),
        matches: z.array(z.string()).optional(),
        has_valid_signature: z.boolean().optional(),
        tlsh: z.string().max(256).optional(),
      })
    )
    .min(1, 'At least one hash is required')
    .max(500, 'Maximum 500 hashes per request'),
})

export const submitSafeFilesSchema = z.object({
  entries: z
    .array(
      z.object({
        partialHash: z.string().length(64),
        fileName: z.string().max(255).optional(),
        size: z.number().int().positive(),
        confirmCount: z.number().int().min(1).optional(),
      })
    )
    .min(1)
    .max(500),
})

// ── Shadow Findings ──

export const submitShadowSchema = z.object({
  type: z.literal('shadow-findings'),
  token_id: z.number().int().positive().optional(),
  pc_username: z.string().max(100).optional(),
  findings: z
    .array(
      z.object({
        path: z.string(),
        fileName: z.string(),
        type: z.string().optional(),
        ruleName: z.string().optional(),
        matches: z.array(z.string()).optional(),
        sha256: z.string().optional(),
        tlsh: z.string().max(256).optional(),
      })
    )
    .min(1)
    .max(200),
})

export const shadowPromoteSchema = z.object({
  rule_name: z.string().min(1).max(255),
  target_status: z.enum(['confirmed', 'false_positive']),
})

// ═══════════════════════════════════════════════════
// ADMIN ROUTE SCHEMAS
// ═══════════════════════════════════════════════════

export const adminLoginSchema = z.object({
  username: z.string().min(1, 'Username is required').max(50),
  password: z.string().min(1, 'Password is required').max(255),
})

export const idParamSchema = z.object({
  id: z.string().regex(/^\d+$/, 'ID must be a number').transform(Number),
})

export const tokensGenerateSchema = z.object({
  count: z.number().int().min(1).max(10).optional().default(1),
})

export const hashConfirmFromScanSchema = z.object({
  sha256: z.string().length(64).regex(/^[a-f0-9]{64}$/, 'Must be SHA256'),
  file_name: z.string().max(255).optional(),
  file_size: z.number().int().min(0).optional(),
})

export const clientHashRegisterSchema = z.object({
  version: z.string().min(1).max(20).regex(/^\d+\.\d+\.\d+$/, 'Version must be semver (e.g. 0.4.5)'),
  sha256: z.string().length(64).regex(/^[a-f0-9]{64}$/, 'Must be SHA256'),
})

export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).optional().default(1),
  limit: z.coerce.number().int().min(1).max(500).optional().default(50),
  status: z.enum(['pending', 'confirmed', 'false_positive', 'shadow', 'promoted', 'rejected', 'all']).optional(),
  after: z.string().optional(),
  since: z.string().optional(),
})



// ═══════════════════════════════════════════════════
// TYPESCRIPT TYPES (inferred from Zod)
// ═══════════════════════════════════════════════════

export type TokenCode = z.infer<typeof tokenCodeSchema>
export type UseTokenInput = z.infer<typeof useTokenSchema>
export type RequestAccessInput = z.infer<typeof requestAccessSchema>
export type SubmitScanInput = z.infer<typeof submitScanSchema>
export type SubmitHashesInput = z.infer<typeof submitHashesSchema>
export type AdminLoginInput = z.infer<typeof adminLoginSchema>
export type HashConfirmInput = z.infer<typeof hashConfirmFromScanSchema>

// ═══════════════════════════════════════════════════
// VALIDATION MIDDLEWARE FACTORY
// ═══════════════════════════════════════════════════

import type { Request, Response, NextFunction } from 'express'

/**
 * Creates a validation middleware for a Zod schema.
 * Validates req.body. If invalid, returns 400 with field-level errors.
 */
export function validate(schema: z.ZodSchema, source: 'body' | 'query' | 'params' = 'body') {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req[source])
    if (!result.success) {
      return res.status(400).json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request data',
          fields: result.error.issues.map(i => ({
            path: i.path.join('.'),
            message: i.message,
          })),
        },
      })
    }
    // Replace with parsed (and transformed) data
    req[source] = result.data
    next()
  }
}

// ═══════════════════════════════════════════════════
// DB ROW TYPES (for TypeScript awareness)
// ═══════════════════════════════════════════════════

export interface TokenRow {
  id: number
  code: string
  is_active: boolean
  used_by: string | null
  used_at: string | null
  created_at: string
  created_by_name?: string
}

export interface RequestRow {
  id: number
  pc_username: string
  status: 'pending' | 'approved' | 'rejected'
  created_at: string
  expires_at: string | null
  approved_by_name?: string
}

export interface AdminRow {
  id: number
  username: string
  password_hash: string
  role: 'admin' | 'superadmin'
}

export interface ScanResultRow {
  id: number
  token_id: number
  pc_username: string
  mode: string
  total_scanned: number
  suspicious_files: number
  high_risk_count: number
  scan_time_ms: number
  scan_status: 'complete' | 'inconclusive'
  diagnostics_json: string | null
  results_json: string | null
  created_at: string
}

export interface SuspiciousHashRow {
  id: number
  sha256: string
  tlsh: string | null
  file_name: string | null
  pc_username: string | null
  file_size: number
  risk_score: number
  status: 'pending' | 'confirmed' | 'false_positive'
  reviewed_by: number | null
  reviewed_at: string | null
  created_at: string
}

export interface SafeFileRow {
  partialHash: string
  fileName: string
  fileSize: number
  confirmCount: number
  lastSeen: string
}

export interface ShadowFindingRow {
  id: number
  token_id: number | null
  pc_username: string
  scan_mode: string | null
  file_path: string | null
  file_name: string | null
  file_type: string
  rule_name: string | null
  matches: string | null // JSON
  sha256: string | null
  tlsh: string | null
  occurrence_count: number
  unique_pcs: number
  status: 'shadow' | 'promoted' | 'rejected'
  promoted_by: number | null
  promoted_at: string | null
  created_at: string
}
