import 'dotenv/config'
import bcrypt from 'bcryptjs'
import { query, testConnection } from '../config/database'

async function init(): Promise<void> {
  console.log('\n  Predator — Database Init\n')

  const connected = await testConnection()
  if (!connected) {
    console.error('\n  Cannot connect to MySQL. Check your .env settings and WAMP.\n')
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
      partial_hash  CHAR(64) DEFAULT NULL,
      tlsh          VARCHAR(256) DEFAULT NULL,
      file_name     VARCHAR(255),
      file_path     VARCHAR(1024) DEFAULT NULL,
      pc_username   VARCHAR(100),
      file_size     INT DEFAULT 0,
      risk_score    INT DEFAULT 0,
      risk          ENUM('high', 'medium', 'low') DEFAULT 'high',
      matches       JSON DEFAULT NULL,
      has_valid_signature BOOLEAN DEFAULT NULL,
      status        ENUM('pending', 'confirmed', 'false_positive') DEFAULT 'pending',
      reviewed_by   INT REFERENCES admins(id),
      reviewed_at   DATETIME,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_sha256 (sha256)
    ) ENGINE=InnoDB
  `)

  // Add tlsh column if upgrading from pre-TLSH schema
  try {
    await query('ALTER TABLE suspicious_hashes ADD COLUMN partial_hash CHAR(64) DEFAULT NULL AFTER sha256')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !err.message.includes('Duplicate column')) throw err
  }

  try {
    await query('ALTER TABLE suspicious_hashes ADD COLUMN file_path VARCHAR(1024) DEFAULT NULL AFTER file_name')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !err.message.includes('Duplicate column')) throw err
  }

  try {
    await query('ALTER TABLE suspicious_hashes ADD COLUMN risk ENUM(\'high\', \'medium\', \'low\') DEFAULT \'high\' AFTER risk_score')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !err.message.includes('Duplicate column')) throw err
  }

  try {
    await query('ALTER TABLE suspicious_hashes ADD COLUMN matches JSON DEFAULT NULL AFTER risk')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !err.message.includes('Duplicate column')) throw err
  }

  try {
    await query('ALTER TABLE suspicious_hashes ADD COLUMN tlsh VARCHAR(256) DEFAULT NULL AFTER partial_hash')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !err.message.includes('Duplicate column')) throw err
  }

  try {
    await query('ALTER TABLE suspicious_hashes ADD COLUMN has_valid_signature BOOLEAN DEFAULT NULL AFTER risk_score')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !err.message.includes('Duplicate column')) throw err
  }

  try {
    await query('CREATE INDEX idx_tlsh ON suspicious_hashes(tlsh(36))')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  try {
    await query('CREATE INDEX idx_partial_hash ON suspicious_hashes(partial_hash)')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  await query(`
    CREATE TABLE IF NOT EXISTS safe_files (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      partial_hash  CHAR(64) NOT NULL,
      file_name     VARCHAR(255),
      file_size     INT DEFAULT 0,
      confirm_count INT DEFAULT 1,
      first_seen    DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen     DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_partial_hash_size (partial_hash, file_size)
    ) ENGINE=InnoDB
  `)

  try {
    await query('CREATE INDEX idx_sh_status ON suspicious_hashes(status)')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  try {
    await query('CREATE INDEX idx_sh_created ON suspicious_hashes(created_at)')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  try {
    await query('CREATE INDEX idx_sf_last_seen ON safe_files(last_seen)')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  // ── Shadow Findings table ──
  await query(`
    CREATE TABLE IF NOT EXISTS client_hashes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      version VARCHAR(20) UNIQUE NOT NULL,
      sha256 CHAR(64) NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS shadow_findings (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      token_id      INT,
      pc_username   VARCHAR(100) NOT NULL,
      scan_mode     VARCHAR(20),
      file_path     VARCHAR(1024),
      file_name     VARCHAR(255),
      file_type     VARCHAR(20) DEFAULT 'file',
      rule_name     VARCHAR(255),
      matches       JSON,
      sha256        CHAR(64),
      tlsh          VARCHAR(256),
      occurrence_count INT DEFAULT 1,
      unique_pcs    INT DEFAULT 1,
      status        ENUM('shadow', 'promoted', 'rejected') DEFAULT 'shadow',
      promoted_by   INT,
      promoted_at   DATETIME,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `)

  try {
    await query('CREATE INDEX idx_sf_status ON shadow_findings(status)')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  try {
    await query('CREATE INDEX idx_sf_rule ON shadow_findings(rule_name(64))')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  try {
    await query('CREATE INDEX idx_sf_sha256 ON shadow_findings(sha256)')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_KEYNAME' && !err.message.includes('Duplicate key name')) throw err
  }

  console.log('  Tables created\n')

  const username = process.env.ADMIN_USERNAME || 'admin'
  const password = process.env.ADMIN_PASSWORD
  if (!password) {
    console.error('\n  FATAL: ADMIN_PASSWORD is not set in environment (.env)\n  Set ADMIN_PASSWORD in your .env file before running init.\n')
    process.exit(1)
  }

  const existing = await query<{ id: number }[]>('SELECT id FROM admins WHERE username = ?', [username])

  if (existing.length === 0) {
    const hash = await bcrypt.hash(password, 10)
    await query('INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)', [
      username, hash, 'superadmin',
    ])
    console.log(`  Default admin created: ${username} / ${password}\n`)
  } else {
    console.log(`  Admin "${username}" already exists\n`)
  }

  console.log('  Database is ready!\n')
  process.exit(0)
}

init().catch((err: any) => {
  console.error('  Init failed:', err.message)
  process.exit(1)
})
