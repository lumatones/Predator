/**
 * Predator Server — Drizzle ORM Client
 *
 * Exports a singleton `db` instance backed by the existing mysql2 pool.
 * The pool is lazy-initialised on first access via config/database.ts.
 *
 * Usage:
 *   import { db } from '../config/database'  // preferred (shared pool)
 *   import { getDb } from './db'              // standalone (for tests)
 *
 * For raw queries (legacy), continue using:
 *   import { query } from '../config/database'
 */
import { drizzle } from 'drizzle-orm/mysql2'
import type { MySql2Database } from 'drizzle-orm/mysql2'
import mysql from 'mysql2/promise'
import * as schema from './schema'

let _db: MySql2Database<typeof schema> | null = null
let _pool: mysql.Pool | null = null

export function getDb(): MySql2Database<typeof schema> {
  if (_db) return _db

  _pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306'),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'predator',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  })

  _db = drizzle(_pool as any, { schema, mode: 'default' }) as MySql2Database<typeof schema>
  return _db
}

/**
 * Close the Drizzle pool. Used in tests and graceful shutdown.
 */
export async function closeDb(): Promise<void> {
  if (_pool) {
    await _pool.end()
    _pool = null
    _db = null
  }
}

export { schema }
