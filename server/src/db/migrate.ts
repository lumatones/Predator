/**
 * Predator Server — Programmatic Database Migration
 *
 * Reads drizzle SQL migration files and executes them via mysql2.
 * Tracks applied migrations in the drizzle __drizzle_migrations meta table.
 * Run: node dist/db/migrate.js
 */
import mysql from 'mysql2/promise'
import fs from 'fs'
import path from 'path'

const MIGRATIONS_DIR = './drizzle'

async function run(): Promise<void> {
  console.log('Running database migrations...')

  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306'),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'predator',
    multipleStatements: true,
  })

  // Ensure meta table
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS __drizzle_migrations (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) NOT NULL UNIQUE,
      applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `)

  // Read migration SQL files sorted by name
  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort()

  for (const file of files) {
    const [alreadyApplied] = await pool.query(
      'SELECT 1 FROM __drizzle_migrations WHERE name = ?',
      [file]
    ) as any[]

    if (alreadyApplied.length > 0) {
      console.log(`  ✓ ${file} (already applied)`)
      continue
    }

    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf-8')
    // Split by drizzle statement breakpoint
    const statements = sql
      .split('--> statement-breakpoint')
      .map(s => s.trim())
      .filter(Boolean)

    for (const stmt of statements) {
      console.log(`  → ${stmt.slice(0, 60)}...`)
      await pool.query(stmt)
    }

    await pool.execute(
      'INSERT INTO __drizzle_migrations (name) VALUES (?)',
      [file]
    )
    console.log(`  ✓ ${file} applied (${statements.length} statements)`)
  }

  await pool.end()
  console.log('Migrations applied successfully.')
  process.exit(0)
}

run().catch((err: unknown) => {
  console.error('Migration failed:', err instanceof Error ? err.message : String(err))
  process.exit(1)
})
