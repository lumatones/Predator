-- ══════════════════════════════════════════════
-- Predator Website — Extended Schema
-- ══════════════════════════════════════════════

-- ── Website Users (Discord/Telegram OAuth) ─────────
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
) ENGINE=InnoDB;

-- ── Linked Social Accounts ─────────────────────
CREATE TABLE IF NOT EXISTS linked_socials (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  user_id       INT NOT NULL REFERENCES website_users(id) ON DELETE CASCADE,
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
) ENGINE=InnoDB;

-- ── Linked Discord Servers ─────────────────────
CREATE TABLE IF NOT EXISTS linked_servers (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  user_id         INT NOT NULL REFERENCES website_users(id) ON DELETE CASCADE,
  discord_guild_id VARCHAR(64) NOT NULL,
  guild_name      VARCHAR(100) NOT NULL,
  guild_icon      VARCHAR(1024),
  is_active       BOOLEAN DEFAULT TRUE,
  checks_this_week INT DEFAULT 0,
  week_reset_at   DATETIME,
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_guild (discord_guild_id),
  INDEX idx_ls_user2 (user_id)
) ENGINE=InnoDB;

-- ── Check Requests (from Discord bot or web) ───
CREATE TABLE IF NOT EXISTS check_requests (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  server_id       INT REFERENCES linked_servers(id) ON DELETE SET NULL,
  requester_name  VARCHAR(100) NOT NULL,
  player_name     VARCHAR(100) NOT NULL,
  player_steam_id VARCHAR(64),
  status          ENUM('pending', 'scanning', 'completed', 'cancelled') DEFAULT 'pending',
  scan_token_id   INT REFERENCES tokens(id) ON DELETE SET NULL,
  result_summary  JSON,
  risk_level      ENUM('clean', 'low', 'medium', 'high'),
  discord_message_id VARCHAR(64),
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at    DATETIME,
  INDEX idx_cr_server (server_id),
  INDEX idx_cr_status (status)
) ENGINE=InnoDB;

-- ── Player Profiles (public DB) ────────────────
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
) ENGINE=InnoDB;

-- ── News Articles ──────────────────────────────
CREATE TABLE IF NOT EXISTS news_articles (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  title         VARCHAR(255) NOT NULL,
  excerpt       TEXT,
  content       MEDIUMTEXT,
  tag           VARCHAR(50),
  tag_color     VARCHAR(20) DEFAULT '#22c55e',
  author_id     INT REFERENCES website_users(id) ON DELETE SET NULL,
  is_published  BOOLEAN DEFAULT TRUE,
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_na_published (is_published)
) ENGINE=InnoDB;

-- ── Notifications ──────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  user_id       INT NOT NULL REFERENCES website_users(id) ON DELETE CASCADE,
  type          VARCHAR(50) NOT NULL,
  title         VARCHAR(255) NOT NULL,
  body          TEXT,
  is_read       BOOLEAN DEFAULT FALSE,
  link          VARCHAR(1024),
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_n_user (user_id),
  INDEX idx_n_unread (user_id, is_read)
) ENGINE=InnoDB;
