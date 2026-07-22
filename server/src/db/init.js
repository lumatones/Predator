require('dotenv').config()
const bcrypt = require('bcryptjs')
const { query, testConnection } = require('../config/database')

async function init() {
  console.log('\n🗄️  Predator — Database Init\n')

  const connected = await testConnection()
  if (!connected) {
    console.error('\n  ❌ Cannot connect to MySQL. Check your .env settings and WAMP.\n')
    process.exit(1)
  }

  // ── Create tables ──
  console.log('  Creating tables...')

  await query(`
    CREATE TABLE IF NOT EXISTS admins (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('admin', 'superadmin') DEFAULT 'admin',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS tokens (
      id INT AUTO_INCREMENT PRIMARY KEY,
      code CHAR(32) UNIQUE NOT NULL,
      created_by INT REFERENCES admins(id),
      used_by VARCHAR(100),
      used_at DATETIME,
      is_active BOOLEAN DEFAULT TRUE,
      revoked_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS requests (
      id INT AUTO_INCREMENT PRIMARY KEY,
      pc_username VARCHAR(100) NOT NULL,
      status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
      approved_by INT REFERENCES admins(id),
      approved_at DATETIME,
      expires_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `)

  console.log('  ✓ Tables created\n')

  // ── Create default admin ──
  const username = process.env.ADMIN_USERNAME || 'admin'
  const password = process.env.ADMIN_PASSWORD || 'admin123'

  const existing = await query('SELECT id FROM admins WHERE username = ?', [username])

  if (existing.length === 0) {
    const hash = await bcrypt.hash(password, 10)
    await query('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)', [
      username, hash, 'superadmin',
    ])
    console.log(`  ✓ Default admin created: ${username} / ${password}\n`)
  } else {
    console.log(`  ✓ Admin "${username}" already exists\n`)
  }

  console.log('  ✅ Database is ready!\n')
  process.exit(0)
}

init().catch((err) => {
  console.error('  ❌ Init failed:', err.message)
  process.exit(1)
})
