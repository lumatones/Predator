CREATE TABLE `admins` (
	`id` serial AUTO_INCREMENT NOT NULL,
	`username` varchar(50) NOT NULL,
	`password_hash` varchar(255) NOT NULL,
	`role` enum('admin','superadmin') NOT NULL DEFAULT 'admin',
	`created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `admins_id` PRIMARY KEY(`id`),
	CONSTRAINT `admins_username_unique` UNIQUE(`username`)
);
--> statement-breakpoint
CREATE TABLE `requests` (
	`id` serial AUTO_INCREMENT NOT NULL,
	`pc_username` varchar(100) NOT NULL,
	`status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
	`approved_by` int,
	`approved_at` datetime,
	`expires_at` datetime,
	`created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `requests_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `safe_files` (
	`id` serial AUTO_INCREMENT NOT NULL,
	`partial_hash` char(64) NOT NULL,
	`file_name` varchar(255),
	`file_size` int NOT NULL DEFAULT 0,
	`confirm_count` int NOT NULL DEFAULT 1,
	`first_seen` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	`last_seen` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `safe_files_id` PRIMARY KEY(`id`),
	CONSTRAINT `uk_partial_hash_size` UNIQUE(`partial_hash`,`file_size`)
);
--> statement-breakpoint
CREATE TABLE `scan_results` (
	`id` serial AUTO_INCREMENT NOT NULL,
	`token_id` int,
	`pc_username` varchar(100) NOT NULL,
	`mode` varchar(20) NOT NULL,
	`total_scanned` int NOT NULL DEFAULT 0,
	`suspicious_files` int NOT NULL DEFAULT 0,
	`high_risk_count` int NOT NULL DEFAULT 0,
	`scan_time_ms` int NOT NULL DEFAULT 0,
	`results_json` mediumtext,
	`auto_safe_count` int DEFAULT 0,
	`auto_malicious_count` int DEFAULT 0,
	`pending_count` int DEFAULT 0,
	`classified_at` datetime,
	`created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `scan_results_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `shadow_findings` (
	`id` serial AUTO_INCREMENT NOT NULL,
	`token_id` int,
	`pc_username` varchar(100) NOT NULL,
	`scan_mode` varchar(20),
	`file_path` varchar(1024),
	`file_name` varchar(255),
	`file_type` varchar(20) NOT NULL DEFAULT 'file',
	`rule_name` varchar(255),
	`matches` json,
	`sha256` char(64),
	`tlsh` varchar(256),
	`occurrence_count` int NOT NULL DEFAULT 1,
	`unique_pcs` int NOT NULL DEFAULT 1,
	`status` enum('shadow','promoted','rejected') NOT NULL DEFAULT 'shadow',
	`promoted_by` int,
	`promoted_at` datetime,
	`created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `shadow_findings_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `suspicious_hashes` (
	`id` serial AUTO_INCREMENT NOT NULL,
	`sha256` char(64) NOT NULL,
	`partial_hash` char(64),
	`tlsh` varchar(256),
	`file_name` varchar(255),
	`file_path` varchar(1024),
	`pc_username` varchar(100),
	`token_id` int,
	`file_size` int NOT NULL DEFAULT 0,
	`risk_score` int NOT NULL DEFAULT 0,
	`risk` enum('high','medium','low') NOT NULL DEFAULT 'high',
	`matches` json,
	`has_valid_signature` boolean,
	`status` enum('pending','confirmed','false_positive') NOT NULL DEFAULT 'pending',
	`reviewed_by` int,
	`reviewed_at` datetime,
	`auto_classified` boolean DEFAULT false,
	`auto_reason` varchar(255),
	`created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `suspicious_hashes_id` PRIMARY KEY(`id`),
	CONSTRAINT `uk_sha256` UNIQUE(`sha256`)
);
--> statement-breakpoint
CREATE TABLE `tokens` (
	`id` serial AUTO_INCREMENT NOT NULL,
	`code` char(32) NOT NULL,
	`created_by` int,
	`used_by` varchar(100),
	`used_at` datetime,
	`is_active` boolean NOT NULL DEFAULT true,
	`revoked_at` datetime,
	`created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `tokens_id` PRIMARY KEY(`id`),
	CONSTRAINT `tokens_code_unique` UNIQUE(`code`)
);
--> statement-breakpoint
ALTER TABLE `requests` ADD CONSTRAINT `requests_approved_by_admins_id_fk` FOREIGN KEY (`approved_by`) REFERENCES `admins`(`id`) ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `scan_results` ADD CONSTRAINT `scan_results_token_id_tokens_id_fk` FOREIGN KEY (`token_id`) REFERENCES `tokens`(`id`) ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `shadow_findings` ADD CONSTRAINT `shadow_findings_promoted_by_admins_id_fk` FOREIGN KEY (`promoted_by`) REFERENCES `admins`(`id`) ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `suspicious_hashes` ADD CONSTRAINT `suspicious_hashes_reviewed_by_admins_id_fk` FOREIGN KEY (`reviewed_by`) REFERENCES `admins`(`id`) ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE `tokens` ADD CONSTRAINT `tokens_created_by_admins_id_fk` FOREIGN KEY (`created_by`) REFERENCES `admins`(`id`) ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX `idx_sf_last_seen` ON `safe_files` (`last_seen`);--> statement-breakpoint
CREATE INDEX `idx_sf_status` ON `shadow_findings` (`status`);--> statement-breakpoint
CREATE INDEX `idx_sf_rule` ON `shadow_findings` (`rule_name`);--> statement-breakpoint
CREATE INDEX `idx_sf_sha256` ON `shadow_findings` (`sha256`);--> statement-breakpoint
CREATE INDEX `idx_tlsh` ON `suspicious_hashes` (`tlsh`);--> statement-breakpoint
CREATE INDEX `idx_partial_hash` ON `suspicious_hashes` (`partial_hash`);--> statement-breakpoint
CREATE INDEX `idx_sh_status` ON `suspicious_hashes` (`status`);--> statement-breakpoint
CREATE INDEX `idx_sh_created` ON `suspicious_hashes` (`created_at`);