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
