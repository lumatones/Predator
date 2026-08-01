/**
 * Predator Server — Drizzle ORM Schema
 *
 * Single source of truth for all database tables.
 * Auto-generate migrations with: npx drizzle-kit generate
 *
 * Tables:
 *   admins              — Admin panel users
 *   tokens              — Auth tokens for scanner clients
 *   requests            — Access requests from scanner clients
 *   scan_results        — Scan submission results
 *   suspicious_hashes   — Confirmed/pending cheat hashes
 *   safe_files          — Community-verified safe files whitelist
 *   shadow_findings     — Shadow-mode findings (auto-promotable rules)
 *
 * NOTE: All datetime defaults use sql`CURRENT_TIMESTAMP` (unquoted)
 * to ensure MySQL interprets them as function calls, not string literals.
 */
import { sql } from 'drizzle-orm'
import {
  mysqlTable,
  mysqlEnum,
  int,
  bigint,
  varchar,
  char,
  mediumtext,
  boolean,
  datetime,
  json,
  index,
  uniqueIndex,
  serial,
} from 'drizzle-orm/mysql-core'

// ════════════════════════════════════════════════════════════════
// admins
// ════════════════════════════════════════════════════════════════

export const admins = mysqlTable('admins', {
  id: serial('id').primaryKey().autoincrement(),
  username: varchar('username', { length: 50 }).notNull().unique(),
  password_hash: varchar('password_hash', { length: 255 }).notNull(),
  role: mysqlEnum('role', ['admin', 'superadmin']).default('admin').notNull(),
  created_at: datetime('created_at', { mode: 'string' }).default(sql`CURRENT_TIMESTAMP`).notNull(),
})

// ════════════════════════════════════════════════════════════════
// tokens
// ════════════════════════════════════════════════════════════════

export const tokens = mysqlTable('tokens', {
  id: serial('id').primaryKey().autoincrement(),
  code: char('code', { length: 32 }).notNull().unique(),
  created_by: bigint('created_by', { mode: 'number', unsigned: true }).references(() => admins.id, { onDelete: 'set null' }),
  used_by: varchar('used_by', { length: 100 }),
  used_at: datetime('used_at', { mode: 'string' }),
  is_active: boolean('is_active').default(true).notNull(),
  revoked_at: datetime('revoked_at', { mode: 'string' }),
  created_at: datetime('created_at', { mode: 'string' }).default(sql`CURRENT_TIMESTAMP`).notNull(),
})

// ════════════════════════════════════════════════════════════════
// requests
// ════════════════════════════════════════════════════════════════

export const requests = mysqlTable('requests', {
  id: serial('id').primaryKey().autoincrement(),
  pc_username: varchar('pc_username', { length: 100 }).notNull(),
  status: mysqlEnum('status', ['pending', 'approved', 'rejected']).default('pending').notNull(),
  approved_by: bigint('approved_by', { mode: 'number', unsigned: true }).references(() => admins.id, { onDelete: 'set null' }),
  approved_at: datetime('approved_at', { mode: 'string' }),
  expires_at: datetime('expires_at', { mode: 'string' }),
  created_at: datetime('created_at', { mode: 'string' }).default(sql`CURRENT_TIMESTAMP`).notNull(),
})

// ════════════════════════════════════════════════════════════════
// scan_results
// ════════════════════════════════════════════════════════════════

export const scanResults = mysqlTable('scan_results', {
  id: serial('id').primaryKey().autoincrement(),
  token_id: bigint('token_id', { mode: 'number', unsigned: true }).references(() => tokens.id, { onDelete: 'set null' }),
  pc_username: varchar('pc_username', { length: 100 }).notNull(),
  mode: varchar('mode', { length: 20 }).notNull(),
  total_scanned: int('total_scanned').default(0).notNull(),
  suspicious_files: int('suspicious_files').default(0).notNull(),
  high_risk_count: int('high_risk_count').default(0).notNull(),
  scan_time_ms: int('scan_time_ms').default(0).notNull(),
  scan_status: mysqlEnum('scan_status', ['complete', 'inconclusive']).default('complete').notNull(),
  diagnostics_json: mediumtext('diagnostics_json'),
  results_json: mediumtext('results_json'),
  auto_safe_count: int('auto_safe_count').default(0),
  auto_malicious_count: int('auto_malicious_count').default(0),
  pending_count: int('pending_count').default(0),
  classified_at: datetime('classified_at', { mode: 'string' }),
  created_at: datetime('created_at', { mode: 'string' }).default(sql`CURRENT_TIMESTAMP`).notNull(),
})

// ════════════════════════════════════════════════════════════════
// suspicious_hashes
// ════════════════════════════════════════════════════════════════

export const suspiciousHashes = mysqlTable('suspicious_hashes', {
  id: serial('id').primaryKey().autoincrement(),
  sha256: char('sha256', { length: 64 }).notNull(),
  partial_hash: char('partial_hash', { length: 64 }),
  tlsh: varchar('tlsh', { length: 256 }),
  file_name: varchar('file_name', { length: 255 }),
  file_path: varchar('file_path', { length: 1024 }),
  pc_username: varchar('pc_username', { length: 100 }),
  token_id: int('token_id'),
  file_size: int('file_size').default(0).notNull(),
  risk_score: int('risk_score').default(0).notNull(),
  risk: mysqlEnum('risk', ['high', 'medium', 'low']).default('high').notNull(),
  matches: json('matches'),
  has_valid_signature: boolean('has_valid_signature'),
  status: mysqlEnum('status', ['pending', 'confirmed', 'false_positive']).default('pending').notNull(),
  reviewed_by: bigint('reviewed_by', { mode: 'number', unsigned: true }).references(() => admins.id, { onDelete: 'set null' }),
  reviewed_at: datetime('reviewed_at', { mode: 'string' }),
  auto_classified: boolean('auto_classified').default(false),
  auto_reason: varchar('auto_reason', { length: 255 }),
  created_at: datetime('created_at', { mode: 'string' }).default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (table) => ({
  sha256Unique: uniqueIndex('uk_sha256').on(table.sha256),
  tlshIdx: index('idx_tlsh').on(table.tlsh),
  partialHashIdx: index('idx_partial_hash').on(table.partial_hash),
  statusIdx: index('idx_sh_status').on(table.status),
  createdAtIdx: index('idx_sh_created').on(table.created_at),
}))

// ════════════════════════════════════════════════════════════════
// safe_files
// ════════════════════════════════════════════════════════════════

export const safeFiles = mysqlTable('safe_files', {
  id: serial('id').primaryKey().autoincrement(),
  partial_hash: char('partial_hash', { length: 64 }).notNull(),
  file_name: varchar('file_name', { length: 255 }),
  file_size: int('file_size').default(0).notNull(),
  confirm_count: int('confirm_count').default(1).notNull(),
  first_seen: datetime('first_seen', { mode: 'string' }).default(sql`CURRENT_TIMESTAMP`).notNull(),
  last_seen: datetime('last_seen', { mode: 'string' }).default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (table) => ({
  partialHashSizeUnique: uniqueIndex('uk_partial_hash_size').on(table.partial_hash, table.file_size),
  lastSeenIdx: index('idx_sf_last_seen').on(table.last_seen),
}))

// ════════════════════════════════════════════════════════════════
// shadow_findings
// ════════════════════════════════════════════════════════════════

export const shadowFindings = mysqlTable('shadow_findings', {
  id: serial('id').primaryKey().autoincrement(),
  token_id: int('token_id'),
  pc_username: varchar('pc_username', { length: 100 }).notNull(),
  scan_mode: varchar('scan_mode', { length: 20 }),
  file_path: varchar('file_path', { length: 1024 }),
  file_name: varchar('file_name', { length: 255 }),
  file_type: varchar('file_type', { length: 20 }).default('file').notNull(),
  rule_name: varchar('rule_name', { length: 255 }),
  matches: json('matches'),
  sha256: char('sha256', { length: 64 }),
  tlsh: varchar('tlsh', { length: 256 }),
  occurrence_count: int('occurrence_count').default(1).notNull(),
  unique_pcs: int('unique_pcs').default(1).notNull(),
  status: mysqlEnum('status', ['shadow', 'promoted', 'rejected']).default('shadow').notNull(),
  promoted_by: bigint('promoted_by', { mode: 'number', unsigned: true }).references(() => admins.id, { onDelete: 'set null' }),
  promoted_at: datetime('promoted_at', { mode: 'string' }),
  created_at: datetime('created_at', { mode: 'string' }).default(sql`CURRENT_TIMESTAMP`).notNull(),
}, (table) => ({
  statusIdx: index('idx_sf_status').on(table.status),
  ruleNameIdx: index('idx_sf_rule').on(table.rule_name),
  sha256Idx: index('idx_sf_sha256').on(table.sha256),
}))
