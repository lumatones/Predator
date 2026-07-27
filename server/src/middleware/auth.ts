import jwt from 'jsonwebtoken'
import type { Request, Response, NextFunction } from 'express'

interface AdminPayload {
  id: number
  username: string
  role: 'admin' | 'superadmin'
}

/** Lazy-load JWT_SECRET — allows dotenv to set it before first use */
function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET
  if (!secret) {
    console.error('FATAL: JWT_SECRET is not set in environment (.env)')
    process.exit(1)
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
    ;(req as any).admin = decoded
    next()
  } catch (err) {
    res.status(401).json({ error: 'Token invalid or expired' })
  }
}

export { generateToken, verifyToken }
export type { AdminPayload }
