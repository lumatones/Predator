/**
 * Predator Server — Standard Error Format
 *
 * Unified error response for all server endpoints:
 *   { error: { code: string, message: string, requestId?: string } }
 *
 * Usage:
 *   import { sendError } from '../helpers/errors'
 *   return sendError(res, 404, 'NOT_FOUND', 'Resource not found')
 */

import type { Response } from 'express'

export interface ApiErrorBody {
  error: {
    code: string
    message: string
    requestId?: string
  }
}

/** Standard error codes for consistent client handling */
export const ErrorCode = {
  VALIDATION: 'VALIDATION_ERROR',
  NOT_FOUND: 'NOT_FOUND',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  CONFLICT: 'CONFLICT',
  RATE_LIMITED: 'RATE_LIMITED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INTERNAL: 'INTERNAL_ERROR',
} as const

/**
 * Send a standardized error response.
 *
 * @param res - Express Response
 * @param status - HTTP status code
 * @param code - Machine-readable error code (e.g. 'NOT_FOUND')
 * @param message - Human-readable error message
 * @param requestId - Optional request ID (auto-detected from req if available)
 */
export function sendError(
  res: Response,
  status: number,
  code: string,
  message: string,
  requestId?: string,
): void {
  const body: ApiErrorBody = {
    error: { code, message },
  }
  if (requestId || res.req?.requestId) {
    body.error.requestId = requestId || (res.req as any)?.requestId
  }
  res.status(status).json(body)
}

/**
 * Throwable API error — caught by global error handler.
 */
export class ApiError extends Error {
  public status: number
  public code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
    this.name = 'ApiError'
  }
}
