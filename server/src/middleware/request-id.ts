/**
 * Predator Server — X-Request-ID Middleware
 *
 * Generates or forwards a unique request ID for every HTTP request.
 * - Reads X-Request-ID header from incoming request (forwarded by proxy/client)
 * - Falls back to generating a short UUID (8-char hex)
 * - Attaches to req.requestId for downstream handlers
 * - Sets X-Request-ID response header for tracing
 *
 * Usage (index.ts):
 *   import { requestIdMiddleware } from './middleware/request-id'
 *   app.use(requestIdMiddleware)
 */

import type { Request, Response, NextFunction } from 'express'
import crypto from 'crypto'

// Augment Express Request type
declare global {
  namespace Express {
    interface Request {
      requestId: string
    }
  }
}

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Forward existing ID or generate a new one
  const id = (req.headers['x-request-id'] as string)
    || crypto.randomBytes(4).toString('hex') // 8-char hex

  req.requestId = id
  res.setHeader('X-Request-ID', id)
  next()
}
