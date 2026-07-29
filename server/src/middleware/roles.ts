/**
 * Predator Server — RBAC Middleware (A6)
 *
 * Role-based access control for admin endpoints.
 *
 * Roles:
 *   superadmin — full access (approve/reject, generate tokens, manage hashes, promote shadows)
 *   admin      — standard access (view all, approve/reject, manage tokens)
 *   moderator  — read-only access (view pending, tokens, history, hashes)
 *
 * Usage:
 *   import { requireRole } from '../middleware/roles'
 *   router.post('/tokens/generate', requireRole('superadmin'), ...)
 */

import type { Request, Response, NextFunction } from 'express'

export type AdminRole = 'superadmin' | 'admin' | 'moderator'

const ROLE_HIERARCHY: Record<AdminRole, number> = {
  superadmin: 3,
  admin: 2,
  moderator: 1,
}

/**
 * Middleware: require a minimum role level.
 * Checks req.admin.role against the hierarchy.
 */
export function requireRole(minRole: AdminRole) {
  return (req: Request, res: Response, next: NextFunction) => {
    const admin = (req as any).admin
    if (!admin) {
      return res.status(401).json({ error: 'Authentication required' })
    }

    const userLevel = ROLE_HIERARCHY[admin.role as AdminRole] || 0
    const requiredLevel = ROLE_HIERARCHY[minRole]

    if (userLevel < requiredLevel) {
      return res.status(403).json({
        error: `Access denied. Requires ${minRole} role or higher.`,
      })
    }

    next()
  }
}
