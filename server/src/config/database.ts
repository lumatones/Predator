import mysql from 'mysql2/promise'
import type { Pool as MyPool, RowDataPacket } from 'mysql2/promise'
import { drizzle } from 'drizzle-orm/mysql2'
import type { MySql2Database } from 'drizzle-orm/mysql2'
import * as schema from '../db/schema'

let pool: MyPool | null = null
let _db: MySql2Database<typeof schema> | null = null
const DB_NAME = (): string => process.env.DB_NAME || 'predator'

function getPool(withoutDb: boolean = false): MyPool {
  if (pool && !withoutDb) return pool

  const config: mysql.PoolOptions = {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306'),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  }

  if (!withoutDb) {
    config.database = DB_NAME()
    pool = mysql.createPool(config)

    // Create Drizzle instance backed by the same pool
    _db = drizzle(pool as any, { schema, mode: 'default' }) as MySql2Database<typeof schema>

    return pool
  }

  return mysql.createPool(config)
}

/**
 * Get the Drizzle ORM db instance.
 * Lazily initialised from the existing mysql2 pool.
 * Use this for new code — type-safe queries without SQL strings.
 *
 * @example
 *   import { db } from '../config/database'
 *   const results = await db.select().from(scanResults).where(eq(scanResults.mode, 'full'))
 */
function getDb(): MySql2Database<typeof schema> {
  if (!_db) getPool()
  return _db!
}

async function ensureDatabase(): Promise<void> {
  const tempPool = getPool(true)
  try {
    await tempPool.execute(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME()}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`)
    console.log(`  ✓ Database "${DB_NAME()}" ensured`)
  } finally {
    await tempPool.end()
  }
}

async function query<T = RowDataPacket[]>(sql: string, params: any[] = []): Promise<T> {
  const conn = getPool()
  const [rows] = await conn.query(sql, params)
  return rows as T
}

async function testConnection(): Promise<boolean> {
  try {
    await ensureDatabase()
    const conn = getPool()
    const connection = await conn.getConnection()
    connection.release()
    console.log('  ✓ MySQL connected')
    return true
  } catch (err: any) {
    console.error('  ✗ MySQL connection failed:', err.message)
    return false
  }
}

export { getPool, query, testConnection, getDb }
