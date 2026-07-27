-- ══════════════════════════════════════════════
-- Predator — Database Schema (MySQL)
-- ══════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS predator
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE predator;

-- ── Administrators ────────────────────────────

CREATE TABLE IF NOT EXISTS admins (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  username    VARCHAR(50)  UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role        ENUM('admin', 'superadmin') DEFAULT 'admin',
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ── Access Tokens ─────────────────────────────

CREATE TABLE IF NOT EXISTS tokens (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  code        CHAR(32) UNIQUE NOT NULL,
  created_by  INT REFERENCES admins(id),
  used_by     VARCHAR(100),          -- PC username that used this token
  used_at     DATETIME,
  is_active   BOOLEAN DEFAULT TRUE,
  revoked_at  DATETIME,
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ── Access Requests ───────────────────────────

CREATE TABLE IF NOT EXISTS requests (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  pc_username VARCHAR(100) NOT NULL,
  status      ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
  approved_by INT REFERENCES admins(id),
  approved_at DATETIME,
  expires_at  DATETIME,
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ── Scan Results (submit from app) ────────────────

CREATE TABLE IF NOT EXISTS scan_results (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  token_id        INT REFERENCES tokens(id),
  pc_username     VARCHAR(100) NOT NULL,
  mode            VARCHAR(20) NOT NULL,
  total_scanned   INT DEFAULT 0,
  suspicious_files INT DEFAULT 0,
  high_risk_count INT DEFAULT 0,
  scan_time_ms    INT DEFAULT 0,
  results_json    MEDIUMTEXT,
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE INDEX idx_scan_results_created ON scan_results(created_at);
CREATE INDEX idx_scan_results_mode ON scan_results(mode);
CREATE INDEX idx_scan_results_pc ON scan_results(pc_username);

-- ── Cloud Signature Database ────────────────────────

CREATE TABLE IF NOT EXISTS suspicious_hashes (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  sha256        CHAR(64) NOT NULL,
  tlsh          VARCHAR(256) DEFAULT NULL,
  file_name     VARCHAR(255),
  pc_username   VARCHAR(100),
  file_size     INT DEFAULT 0,
  risk_score    INT DEFAULT 0,
  status        ENUM('pending', 'confirmed', 'false_positive') DEFAULT 'pending',
  reviewed_by   INT REFERENCES admins(id),
  reviewed_at   DATETIME,
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_sha256 (sha256),
  INDEX idx_tlsh (tlsh(36))
) ENGINE=InnoDB;

CREATE INDEX idx_sh_status ON suspicious_hashes(status);
CREATE INDEX idx_sh_created ON suspicious_hashes(created_at);

-- ── Community Safe Files (crowdsourced whitelist) ────────

CREATE TABLE IF NOT EXISTS safe_files (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  partial_hash  CHAR(64) NOT NULL,
  file_name     VARCHAR(255),
  file_size     INT DEFAULT 0,
  confirm_count INT DEFAULT 1,
  first_seen    DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_seen     DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_partial_hash_size (partial_hash, file_size)
) ENGINE=InnoDB;

CREATE INDEX idx_sf_last_seen ON safe_files(last_seen);

-- ── Shadow Findings (shadow-mode rule telemetry) ────────

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
  promoted_by   INT REFERENCES admins(id),
  promoted_at   DATETIME,
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE INDEX idx_sf_status ON shadow_findings(status);
CREATE INDEX idx_sf_rule ON shadow_findings(rule_name(64));
CREATE INDEX idx_sf_sha256 ON shadow_findings(sha256);
