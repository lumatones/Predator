import jwt from 'jsonwebtoken'
import type { Request, Response, NextFunction } from 'express'

const JWT_SECRET = process.env.JWT_SECRET

if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set in environment (.env)')
  process.exit(1)
}

interface AdminPayload {
  id: number
  username: string
  role: 'admin' | 'superadmin'
}

function generateToken(admin: AdminPayload): string {
  return jwt.sign(
    { id: admin.id, username: admin.username, role: admin.role },
    JWT_SECRET!,
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
    const token = header.split(' ')[1]
    const decoded = jwt.verify(token, JWT_SECRET!) as AdminPayload
    ;(req as any).admin = decoded
    next()
  } catch (err) {
    res.status(401).json({ error: 'Token invalid or expired' })
  }
}

export { generateToken, verifyToken }
export type { AdminPayload }
