import jwt from 'jsonwebtoken'
import type { Request, Response, NextFunction } from 'express'

// ── Extend Express Request to include admin payload ──
declare global {
  namespace Express {
    interface Request {
      admin?: AdminPayload
    }
  }
}

interface AdminPayload {
  id: number
  username: string
  role: 'admin' | 'superadmin'
}

/** Lazy-load JWT_SECRET — allows dotenv to set it before first use.
 *  Throws if not set — caught by route handlers returning 500. */
function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET
  if (!secret) {
    throw new Error('JWT_SECRET is not configured. Set it in .env file.')
  }
  return secret
}

function generateToken(admin: AdminPayload): string {
  const secret = getJwtSecret()
  return jwt.sign(
    { id: admin.id, username: admin.username, role: admin.role },
    secret,
    { expiresIn: (process.env.JWT_EXPIRES_IN || '24h') as any }
  )
}

function verifyToken(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers.authorization
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authorization required' })
    return
  }

  try {
    const secret = getJwtSecret()
    const token = header.split(' ')[1]
    const decoded = jwt.verify(token, secret) as AdminPayload
    req.admin = decoded
    next()
  } catch (err) {
    res.status(401).json({ error: 'Token invalid or expired' })
  }
}

export { generateToken, verifyToken }
export type { AdminPayload }
