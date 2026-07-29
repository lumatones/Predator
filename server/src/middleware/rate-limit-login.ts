/**
 * Predator Server — Login Rate Limiting (A5 + A7)
 *
 * Tracks failed login attempts per IP address.
 * Blocks login for 15 minutes after 5 consecutive failures.
 *
 * Failed attempts are also logged to admin_audit_log via audit-log.ts.
 */

const FAILED_ATTEMPTS = new Map<string, { count: number; firstAttempt: number }>()
const MAX_ATTEMPTS = 5
const BLOCK_WINDOW_MS = 15 * 60 * 1000 // 15 minutes

/** Clean stale entries every 5 minutes */
let _loginCleanupTimer: ReturnType<typeof setInterval> | null = null

_loginCleanupTimer = setInterval(() => {
  const cutoff = Date.now() - BLOCK_WINDOW_MS * 2
  for (const [key, entry] of FAILED_ATTEMPTS) {
    if (entry.firstAttempt < cutoff) FAILED_ATTEMPTS.delete(key)
  }
}, 5 * 60 * 1000)

export interface LoginRateLimitResult {
  blocked: boolean
  remaining: number
  message?: string
}

/**
 * Check if a login attempt should be blocked.
 * Returns { blocked, remaining } for the given key (IP address).
 */
export function checkLoginRateLimit(key: string): LoginRateLimitResult {
  const now = Date.now()
  const entry = FAILED_ATTEMPTS.get(key)

  if (!entry || now - entry.firstAttempt > BLOCK_WINDOW_MS) {
    return { blocked: false, remaining: MAX_ATTEMPTS }
  }

  if (entry.count >= MAX_ATTEMPTS) {
    const minutesLeft = Math.ceil((entry.firstAttempt + BLOCK_WINDOW_MS - now) / 60000)
    return {
      blocked: true,
      remaining: 0,
      message: `Too many failed attempts. Try again in ${minutesLeft} minutes.`,
    }
  }

  return { blocked: false, remaining: MAX_ATTEMPTS - entry.count }
}

/**
 * Record a failed login attempt for the given key.
 */
export function recordFailedAttempt(key: string): void {
  const now = Date.now()
  const entry = FAILED_ATTEMPTS.get(key)

  if (!entry || now - entry.firstAttempt > BLOCK_WINDOW_MS) {
    FAILED_ATTEMPTS.set(key, { count: 1, firstAttempt: now })
  } else {
    entry.count++
  }
}

/**
 * Clear rate limit for a key (after successful login).
 */
export function clearRateLimit(key: string): void {
  FAILED_ATTEMPTS.delete(key)
}

/** Stop the background cleanup timer (graceful shutdown). */
export function stopLoginRateLimitCleanup(): void {
  if (_loginCleanupTimer) { clearInterval(_loginCleanupTimer); _loginCleanupTimer = null }
}
