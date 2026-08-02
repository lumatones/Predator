-- Migration 0004: admin_audit_log — correct FK type
-- The table is normally created by audit-log.ts (server startup), but
-- migrations run BEFORE the server. This migration creates the table if
-- it doesn't exist yet, then ensures admin_id is BIGINT UNSIGNED.
-- Single multi-statement query to keep foreign_key_checks on one connection.
CREATE TABLE IF NOT EXISTS `admin_audit_log` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `admin_id` bigint unsigned,
  `admin_username` VARCHAR(50) NOT NULL,
  `action` VARCHAR(50) NOT NULL,
  `target_id` INT,
  `target_type` VARCHAR(50),
  `meta` JSON,
  `ip_address` VARCHAR(45),
  `request_id` VARCHAR(20),
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_admin` (`admin_id`),
  INDEX `idx_action` (`action`),
  INDEX `idx_created` (`created_at`),
  FOREIGN KEY (`admin_id`) REFERENCES `admins`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

SET foreign_key_checks = 0;
ALTER TABLE `admin_audit_log` MODIFY COLUMN `admin_id` bigint unsigned;
SET foreign_key_checks = 1;
