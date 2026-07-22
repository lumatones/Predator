const mysql = require('mysql2/promise')

let pool = null
const DB_NAME = () => process.env.DB_NAME || 'predator'

function getPool(withoutDb = false) {
  if (pool && !withoutDb) return pool

  const config = {
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

async function ensureDatabase() {
  const tempPool = getPool(true)
  try {
    await tempPool.execute(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME()}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`)
    console.log(`  ✓ Database "${DB_NAME()}" ensured`)
  } finally {
    await tempPool.end()
  }
}

async function query(sql, params = []) {
  const conn = getPool()
  // Используем query() вместо execute() для совместимости с LIMIT ?
  // Prepared statements (execute) не поддерживают LIMIT с параметрами
  const [rows] = await conn.query(sql, params)
  return rows
}

async function testConnection() {
  try {
    await ensureDatabase()
    const conn = getPool()
    await conn.getConnection()
    console.log('  ✓ MySQL connected')
    return true
  } catch (err) {
    console.error('  ✗ MySQL connection failed:', err.message)
    return false
  }
}

module.exports = { getPool, query, testConnection }
