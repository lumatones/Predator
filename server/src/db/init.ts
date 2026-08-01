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
      scan_status ENUM('complete', 'inconclusive') DEFAULT 'complete',
      diagnostics_json MEDIUMTEXT,
      results_json MEDIUMTEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `)

  // Preserve trust-state columns for databases created before inconclusive scans.
  try {
    await query("ALTER TABLE scan_results ADD COLUMN scan_status ENUM('complete', 'inconclusive') DEFAULT 'complete' AFTER scan_time_ms")
  } catch (err: any) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !err.message.includes('Duplicate column')) throw err
  }

  try {
    await query('ALTER TABLE scan_results ADD COLUMN diagnostics_json MEDIUMTEXT DEFAULT NULL AFTER scan_status')
  } catch (err: any) {
    if (err.code !== 'ER_DUP_FIELDNAME' && !err.message.includes('Duplicate column')) throw err
  }

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

  // ═══════════════════════════════════════════════
  // Website tables (public site: players DB, news, users)
  // ═══════════════════════════════════════════════

  await query(`
    CREATE TABLE IF NOT EXISTS website_users (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      email         VARCHAR(255) UNIQUE,
      password_hash VARCHAR(255),
      display_name  VARCHAR(100) NOT NULL,
      avatar_url    VARCHAR(1024),
      subscription  ENUM('free', 'pro') DEFAULT 'free' NOT NULL,
      subscription_expires DATETIME,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS linked_socials (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      user_id       INT NOT NULL,
      provider      ENUM('discord', 'telegram') NOT NULL,
      provider_id   VARCHAR(100) NOT NULL,
      provider_name VARCHAR(100),
      avatar_url    VARCHAR(1024),
      access_token  VARCHAR(1024),
      refresh_token VARCHAR(1024),
      token_expires DATETIME,
      notify_checks BOOLEAN DEFAULT TRUE,
      notify_results BOOLEAN DEFAULT TRUE,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_provider_user (provider, provider_id),
      INDEX idx_ls_user (user_id)
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS linked_servers (
      id              INT AUTO_INCREMENT PRIMARY KEY,
      user_id         INT NOT NULL,
      discord_guild_id VARCHAR(64) NOT NULL,
      guild_name      VARCHAR(100) NOT NULL,
      guild_icon      VARCHAR(1024),
      is_active       BOOLEAN DEFAULT TRUE,
      checks_this_week INT DEFAULT 0,
      week_reset_at   DATETIME,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE KEY uk_guild (discord_guild_id),
      INDEX idx_ls_user2 (user_id)
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS check_requests (
      id              INT AUTO_INCREMENT PRIMARY KEY,
      server_id       INT,
      requester_name  VARCHAR(100) NOT NULL,
      player_name     VARCHAR(100) NOT NULL,
      player_steam_id VARCHAR(64),
      status          ENUM('pending', 'scanning', 'completed', 'cancelled') DEFAULT 'pending',
      scan_token_id   INT,
      result_summary  JSON,
      risk_level      ENUM('clean', 'low', 'medium', 'high'),
      discord_message_id VARCHAR(64),
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      completed_at    DATETIME,
      INDEX idx_cr_server (server_id),
      INDEX idx_cr_status (status)
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS player_profiles (
      id              INT AUTO_INCREMENT PRIMARY KEY,
      display_name    VARCHAR(100) NOT NULL,
      server_name     VARCHAR(100),
      risk_level      ENUM('clean', 'low', 'medium', 'high') DEFAULT 'clean',
      total_scans     INT DEFAULT 0,
      cheat_traces    INT DEFAULT 0,
      last_scan_at    DATETIME,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_pp_risk (risk_level),
      INDEX idx_pp_server (server_name),
      INDEX idx_pp_name (display_name)
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS news_articles (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      title         VARCHAR(255) NOT NULL,
      excerpt       TEXT,
      content       MEDIUMTEXT,
      tag           VARCHAR(50),
      tag_color     VARCHAR(20) DEFAULT '#22c55e',
      author_id     INT,
      is_published  BOOLEAN DEFAULT TRUE,
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_na_published (is_published)
    ) ENGINE=InnoDB
  `)

  await query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id            INT AUTO_INCREMENT PRIMARY KEY,
      user_id       INT NOT NULL,
      type          VARCHAR(50) NOT NULL,
      title         VARCHAR(255) NOT NULL,
      body          TEXT,
      is_read       BOOLEAN DEFAULT FALSE,
      link          VARCHAR(1024),
      created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_n_user (user_id),
      INDEX idx_n_unread (user_id, is_read)
    ) ENGINE=InnoDB
  `)

  // Seed real release notes so the news page isn't empty
  const [newsCount] = await query<{ cnt: number }[]>('SELECT COUNT(*) as cnt FROM news_articles')
  if (!(newsCount as any)?.cnt) {
    const RELEASE_NOTES = [
      {
        title: 'Predator v0.5.1 — язык/токен, без демо-скана',
        excerpt: 'Выбор языка и токен сохраняются в конфиге, демо-проверка убрана, риск-скоринг переработан.',
        content: 'Релиз v0.5.1: сохранение выбранного языка и активированного токена между запусками, удаление демо-шага из онбординга, анти-фолс-позитив матчинг сигналов (word boundaries), средний вес категории вместо суммарного, riskScore согласован с уровнем риска.',
        tag: 'Релиз',
        tagColor: '#22c55e',
        daysAgo: 1,
      },
      {
        title: 'Predator v0.5.0 — Аудит безопасности + серверные хеши',
        excerpt: 'Server-verified integrity baseline, детект подмены exe, evidence model с объяснимым риском.',
        content: 'Релиз v0.5.0 включает: таблицу client_hashes с admin-эндпоинтом регистрации sha256, различение легальных автообновлений от подмены, подключение criticalTamperResponse, проверку целостности во всех режимах скана и structured evidence model.',
        tag: 'Релиз',
        tagColor: '#22c55e',
        daysAgo: 2,
      },
      {
        title: 'Улучшен UI Dashboard — Glass Morphism v2',
        excerpt: 'Новая визуальная палитра, компактный режим сканирования, тултипы и микроанимации.',
        content: 'Обновлён весь фронтенд: компактный режим для фонового сканирования, улучшенные карточки угроз, модальные окна с деталями файлов, интерактивная карта угроз.',
        tag: 'Обновление',
        tagColor: '#8b5cf6',
        daysAgo: 5,
      },
      {
        title: 'Новые DMA-детекты — Xilinx FPGA + PCIe',
        excerpt: 'Обнаружение DMA-карт, FPGA-устройств и vulnerable драйверов (BYOVD).',
        content: 'Добавлены: сканирование PCIe config space, обнаружение Xilinx/Altera FPGA, проверка vulnerable драйверов (rtcore, gdrv, iqvw64e), BYOVD-детект через KDMapper/DrvMap.',
        tag: 'Безопасность',
        tagColor: '#ef4444',
        daysAgo: 8,
      },
      {
        title: 'Cloud-классификатор v2 — Correlation Engine',
        excerpt: 'Мульти-сигнальная классификация с crowdsource-верификацией и adaptive thresholds.',
        content: 'Новый классификатор: 11 сигналов, correlation bonus для слабых индикаторов, crowdsource safe/malicious через уникальные PC, TLSH fuzzy matching, adaptive thresholds для DMA и cleaner нахождений.',
        tag: 'Команда',
        tagColor: '#f59e0b',
        daysAgo: 11,
      },
    ]
    for (const n of RELEASE_NOTES) {
      await query(
        'INSERT INTO news_articles (title, excerpt, content, tag, tag_color, created_at) VALUES (?, ?, ?, ?, ?, DATE_SUB(NOW(), INTERVAL ? DAY))',
        [n.title, n.excerpt, n.content, n.tag, n.tagColor, n.daysAgo],
      )
    }
    console.log('  Seeded ' + RELEASE_NOTES.length + ' news articles\n')
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
