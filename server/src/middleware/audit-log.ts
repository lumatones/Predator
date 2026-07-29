/**
 * Predator Server — Admin Audit Log
 *
 * NOTE: Table is created via raw SQL (CREATE TABLE IF NOT EXISTS) rather
 * than Drizzle migrations to keep the audit log self-contained. This is
 * intentional — the audit log is an infrastructure concern, not a business
 * schema entity. If migrating to full Drizzle in the future, add:
 *   - adminAuditLog table to db/schema.ts
 *   - Run drizzle-kit generate
 *
 * Records every admin action for accountability and security auditing.
 *
 * Actions logged:
 *   - login / login_failed
 *   - approve / reject / approve_batch / reject_batch
 *   - token_generate / token_revoke
 *   - hash_confirm / hash_reject / hash_confirm_from_scan
 *   - shadow_promote / shadow_reject
 *
 * Usage:
 *   import { logAdminAction } from '../middleware/audit-log'
 *   logAdminAction(req, 'approve', { requestId: 42 })
 */

import type { Request } from 'express'
import { query } from '../config/database'

export type AdminActionType =
  | 'login'
  | 'login_failed'
  | 'approve'
  | 'reject'
  | 'approve_batch'
  | 'reject_batch'
  | 'token_generate'
  | 'token_revoke'
  | 'hash_confirm'
  | 'hash_reject'
  | 'hash_confirm_from_scan'
  | 'shadow_promote'
  | 'shadow_reject'

interface AuditMeta {
  requestId?: number
  hashId?: number
  tokenId?: number
  count?: number
  ruleName?: string
  sha256?: string
}

/**
 * Initialize the audit log table. Called once at server start.
 */
export async function initAuditLog(): Promise<void> {
  try {
    await query(`
      CREATE TABLE IF NOT EXISTS admin_audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT,
        admin_username VARCHAR(50) NOT NULL,
        action VARCHAR(50) NOT NULL,
        target_id INT,
        target_type VARCHAR(50),
        meta JSON,
        ip_address VARCHAR(45),
        request_id VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_admin (admin_id),
        INDEX idx_action (action),
        INDEX idx_created (created_at),
        FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `)
    console.log('  📝 Admin audit log ready')
  } catch (err) { console.warn('[audit-log] init failed:', (err as Error).message) }
}

/**
 * Log an admin action asynchronously (fire-and-forget).
 * Never throws — errors are logged silently.
 */
export function logAdminAction(
  req: Request,
  action: AdminActionType,
  meta?: AuditMeta,
): void {
  const adminId = (req as any).admin?.id || null
  const adminUsername = (req as any).admin?.username || 'unknown'
  const ip = req.ip || req.socket.remoteAddress || 'unknown'
  const requestId = req.requestId || null

  // Fire-and-forget — don't block the response
  query(
    `INSERT INTO admin_audit_log (admin_id, admin_username, action, target_id, target_type, meta, ip_address, request_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      adminId,
      adminUsername,
      action,
      meta?.requestId || meta?.hashId || meta?.tokenId || null,
      meta?.requestId ? 'request' : meta?.hashId ? 'hash' : meta?.tokenId ? 'token' : null,
      meta ? JSON.stringify(meta) : null,
      ip,
      requestId,
    ]
  ).catch((err) => {
    console.warn('[audit-log] write failed:', (err as Error).message)
  })
}

/**
 * Get audit log entries with pagination (for admin UI).
 */
export async function getAuditLog(
  page: number,
  limit: number,
): Promise<{ entries: any[]; total: number }> {
  const offset = (page - 1) * limit
  const [countRows] = await query<{ cnt: number }[]>(
    'SELECT COUNT(*) AS cnt FROM admin_audit_log'
  )
  const rows = await query<any[]>(
    'SELECT * FROM admin_audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?',
    [limit, offset]
  )
  return {
    entries: rows.map(r => ({
      ...r,
      meta: r.meta ? (() => { try { return JSON.parse(r.meta as string) } catch { return null } })() : null,
    })),
    total: countRows?.cnt || 0,
  }
}
