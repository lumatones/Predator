/**
 * Predator Server — WebSocket Auth Middleware
 *
 * Authenticates Socket.IO connections using JWT (same as HTTP auth).
 *
 * Flow:
 *   1. Client connects with handshake auth: { token: '<jwt>' }
 *   2. Middleware verifies JWT → socket.data.admin = { id, username, role }
 *   3. If JWT is invalid → socket.data.admin = null (guest access)
 *   4. join-admin handler calls requireAdmin(socket) — rejects if no valid JWT
 *
 * Usage:
 *   import { wsAuthMiddleware } from './middleware/ws-auth'
 *   io.use(wsAuthMiddleware)
 */

import type { Socket } from 'socket.io'
import jwt from 'jsonwebtoken'
import type { AdminPayload } from './auth'

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
 * Socket.IO middleware — runs on every connection BEFORE event handlers.
 * Validates JWT from handshake auth. Does NOT block guest connections.
 */
export function wsAuthMiddleware(socket: Socket, next: (err?: Error) => void): void {
  try {
    const token: string | undefined = socket.handshake.auth?.token

    if (token && typeof token === 'string') {
      try {
        const secret = getJwtSecret()
        const decoded = jwt.verify(token, secret) as AdminPayload
        socket.data.admin = decoded
      } catch {
        socket.data.admin = null
      }
    } else {
      socket.data.admin = null
    }

    next()
  } catch {
    next(new Error('Auth middleware error'))
  }
}

/**
 * Require admin auth for an event handler.
 * Returns true if authorized. Emits 'error' event and returns false otherwise.
 */
export function requireAdmin(socket: Socket): boolean {
  if (!socket.data.admin) {
    socket.emit('error', { code: 'AUTH_REQUIRED', message: 'Admin authentication required' })
    return false
  }
  return true
}

/**
 * Get the admin payload from socket data.
 */
export function getAdmin(socket: Socket): AdminPayload | null {
  return socket.data.admin || null
}
