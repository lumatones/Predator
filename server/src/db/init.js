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

  await query(`
    CREATE TABLE IF NOT EXISTS scan_results (
      id INT AUTO_INCREMENT PRIMARY KEY,
      token_id INT REFERENCES tokens(id),
      pc_username VARCHAR(100) NOT NULL,
      mode VARCHAR(20) NOT NULL,
      total_scanned INT DEFAULT 0,
      suspicious_files INT DEFAULT 0,
      high_risk_count INT DEFAULT 0,
      scan_time_ms INT DEFAULT 0,
      results_json MEDIUMTEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS suspicious_hashes (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      sha256        CHAR(64) NOT NULL,
      file_name     VARCHAR(255),
      pc_username   VARCHAR(100),
      file_size     INT DEFAULT 0,
      risk_score    INT DEFAULT 0,
      status        ENUM('pending', 'confirmed', 'false_positive') DEFAULT 'pending',
      reviewed_by   INT REFERENCES admins(id),
      reviewed_at   DATETIME,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_sha256 (sha256)
    ) ENGINE=InnoDB
  `)

  // MySQL < 8.0 не поддерживает IF NOT EXISTS для CREATE INDEX
  try {
    await query('CREATE INDEX idx_sh_status ON suspicious_hashes(status)')
  } catch (err) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  try {
    await query('CREATE INDEX idx_sh_created ON suspicious_hashes(created_at)')
  } catch (err) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  console.log('  ✓ Tables created\n')

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
