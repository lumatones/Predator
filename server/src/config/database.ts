import mysql from 'mysql2/promise'
import type { Pool, RowDataPacket, ResultSetHeader } from 'mysql2/promise'

let pool: Pool | null = null
const DB_NAME = (): string => process.env.DB_NAME || 'predator'

function getPool(withoutDb: boolean = false): Pool {
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
    return pool
  }

  return mysql.createPool(config)
}

async function ensureDatabase(): Promise<void> {
  const tempPool = getPool(true)
  try {
    await tempPool.execute(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME()}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`)
    console.log(`  \u2713 Database "${DB_NAME()}" ensured`)
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
    console.log('  \u2713 MySQL connected')
    return true
  } catch (err: any) {
    console.error('  \u2717 MySQL connection failed:', err.message)
    return false
  }
}

export { getPool, query, testConnection }
