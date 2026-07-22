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
