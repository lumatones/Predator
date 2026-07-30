/**
 * Predator Server — WebSocket Auth Middleware
 *
 * Authenticates Socket.IO connections using JWT (same as HTTP auth).
 *
 * Flow:
 *   1. Client connects with handshake auth: { token: '<jwt>' }
 *   2. Middleware verifies JWT → socket.data.admin = { id, username, role }
 *   3. If JWT is invalid/missing → socket.data.admin = null (guest access)
 *   4. Handlers call requireAdmin(socket) / requireRole(socket, 'superadmin') — rejects if unauthorized
 *
 * Usage:
 *   import { wsAuthMiddleware } from './middleware/ws-auth'
 *   io.use(wsAuthMiddleware)
 */

import type { Socket } from 'socket.io'
import jwt from 'jsonwebtoken'
import { z } from 'zod'

// ═══════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════

export interface AdminPayload {
  id: number
  username: string
  role: 'admin' | 'superadmin'
  exp?: number
  iat?: number
}

/** Make global augmentation available for Socket.data */
declare module 'socket.io' {
  interface SocketData {
    admin: AdminPayload | null
    authedAt?: number
  }
}

// ═══════════════════════════════════════════════════
// WS ERROR CODES (typed, consistent with HTTP errors)
// ═══════════════════════════════════════════════════

export const WsErrorCode = {
  /** JWT is missing or invalid */
  AUTH_INVALID: 'AUTH_INVALID',
  /** JWT has expired */
  AUTH_EXPIRED: 'AUTH_EXPIRED',
  /** Valid JWT but insufficient role */
  AUTH_FORBIDDEN: 'AUTH_FORBIDDEN',
  /** No token provided (guest access denied for this operation) */
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  /** Token format is invalid (not a JWT) */
  AUTH_MALFORMED: 'AUTH_MALFORMED',
  /** Too many connections */
  RATE_LIMITED: 'RATE_LIMITED',
  /** Server-side middleware error */
  INTERNAL: 'INTERNAL',
} as const

export type WsErrorCode = (typeof WsErrorCode)[keyof typeof WsErrorCode]

// ═══════════════════════════════════════════════════
// ZOD SCHEMA — validates handshake auth
// ═══════════════════════════════════════════════════

const handshakeAuthSchema = z.object({
  token: z
    .string()
    .min(10, 'Token is too short to be a valid JWT')
    .max(2000, 'Token is too long')
    .optional(),
})

// ═══════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════

/** Lazy-load JWT_SECRET — same function as HTTP auth middleware.
 *  Throws if not set — caught by Socket.IO error handling. */
function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET
  if (!secret) {
    throw new Error('JWT_SECRET is not configured. Set it in .env file.')
  }
  return secret
}

/**
 * Decode JWT payload without verification (for extracting exp claim).
 * Returns null on any failure.
 */
function decodeJwtPayload(token: string): { exp?: number } | null {
  try {
    if (token.split('.').length < 2) return null
    // JWT uses base64url (RFC 7519), Node understands base64 with padding
    const payloadB64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'))
  } catch {
    return null
  }
}

// ═══════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════

/**
 * Socket.IO middleware — runs on every connection BEFORE event handlers.
 *
 * Validates JWT from handshake auth. Does NOT block guest connections.
 * Sets socket.data.admin = AdminPayload | null.
 * Sets socket.data.authedAt = Date.now() on successful auth.
 */
export function wsAuthMiddleware(socket: Socket, next: (err?: Error) => void): void {
  try {
    // ── Validate handshake auth format (Zod) ──
    const parseResult = handshakeAuthSchema.safeParse(socket.handshake.auth)
    if (!parseResult.success) {
      socket.data.admin = null
      next()
      return
    }

    const token = parseResult.data.token

    if (!token) {
      socket.data.admin = null
      next()
      return
    }

    // ── Verify JWT ──
    try {
      const secret = getJwtSecret()
      const decoded = jwt.verify(token, secret) as AdminPayload
      socket.data.admin = decoded
      socket.data.authedAt = Date.now()
    } catch (err: any) {
      // Distinguish expired vs invalid
      if (err.name === 'TokenExpiredError') {
        socket.data.admin = null
        // Don't reject — guest access still works
      } else {
        socket.data.admin = null
      }
    }

    next()
  } catch {
    next(new Error('Auth middleware error'))
  }
}

// ═══════════════════════════════════════════════════
// ACCESS GUARDS
// ═══════════════════════════════════════════════════

/**
 * Require admin auth for an event handler.
 * Returns true if authorized. Emits 'error' event and returns false otherwise.
 *
 * @example
 *   socket.on('admin-action', () => {
 *     if (!requireAdmin(socket)) return
 *     // ... admin logic
 *   })
 */
export function requireAdmin(socket: Socket): boolean {
  if (!socket.data.admin) {
    socket.emit('error', {
      code: WsErrorCode.AUTH_REQUIRED,
      message: 'Admin authentication required',
    })
    return false
  }

  // Check if token has expired (server-side check, in case clock skew misses it)
  if (socket.data.admin.exp && socket.data.admin.exp * 1000 < Date.now()) {
    socket.emit('error', {
      code: WsErrorCode.AUTH_EXPIRED,
      message: 'Session expired — please re-login',
    })
    return false
  }

  return true
}

/**
 * Require a minimum role for an event handler.
 * Use for superadmin-only operations (token generation, user management).
 *
 * @example
 *   socket.on('superadmin-action', () => {
 *     if (!requireRole(socket, 'superadmin')) return
 *     // ... superadmin logic
 *   })
 */
export function requireRole(socket: Socket, minimumRole: 'admin' | 'superadmin'): boolean {
  if (!socket.data.admin) {
    socket.emit('error', {
      code: WsErrorCode.AUTH_REQUIRED,
      message: 'Admin authentication required',
    })
    return false
  }

  if (socket.data.admin.exp && socket.data.admin.exp * 1000 < Date.now()) {
    socket.emit('error', {
      code: WsErrorCode.AUTH_EXPIRED,
      message: 'Session expired — please re-login',
    })
    return false
  }

  const roleHierarchy: Record<string, number> = { admin: 1, superadmin: 2 }
  const userLevel = roleHierarchy[socket.data.admin.role] || 0
  const requiredLevel = roleHierarchy[minimumRole] || 0

  if (userLevel < requiredLevel) {
    socket.emit('error', {
      code: WsErrorCode.AUTH_FORBIDDEN,
      message: `Insufficient role: '${minimumRole}' required, you have '${socket.data.admin.role}'`,
    })
    return false
  }

  return true
}

/**
 * Get the admin payload from socket data.
 * Returns null for guest connections.
 */
export function getAdmin(socket: Socket): AdminPayload | null {
  return socket.data.admin || null
}

/**
 * Check if socket is authenticated as admin (without emitting errors).
 * Useful for conditional logic that doesn't require auth but benefits from it.
 */
export function isAdmin(socket: Socket): boolean {
  return !!socket.data.admin
}

/**
 * Get connection metadata for audit logging.
 */
export function getConnectionMeta(socket: Socket): {
  ip: string
  adminId: number | null
  adminUsername: string | null
  role: string | null
} {
  const fwd = socket.handshake.headers['x-forwarded-for']
  const ip = typeof fwd === 'string' ? fwd.split(',')[0].trim() : socket.handshake.address || 'unknown'

  return {
    ip,
    adminId: socket.data.admin?.id ?? null,
    adminUsername: socket.data.admin?.username ?? null,
    role: socket.data.admin?.role ?? null,
  }
}
