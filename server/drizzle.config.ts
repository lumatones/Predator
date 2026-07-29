/**
 * Predator Server — Drizzle Kit Configuration
 *
 * Generates SQL migrations from schema definitions.
 *
 * Commands:
 *   npx drizzle-kit generate   — Generate migration from schema changes
 *   npx drizzle-kit migrate    — Apply pending migrations
 *   npx drizzle-kit push       — Push schema directly (dev only)
 *   npx drizzle-kit introspect — Introspect existing DB → schema
 *
 * NOTE: Uses tsx runner because tsconfig.json uses CommonJS.
 *       drizzle-kit auto-detects the schema file.
 */
import { defineConfig } from 'drizzle-kit'

export default defineConfig({
  dialect: 'mysql',
  schema: './src/db/schema.ts',
  out: './drizzle',
  dbCredentials: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306'),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'predator',
  },
  verbose: true,
  strict: true,
})
