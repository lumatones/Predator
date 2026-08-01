ALTER TABLE `scan_results` ADD `scan_status` enum('complete','inconclusive') NOT NULL DEFAULT 'complete' AFTER `scan_time_ms`;
--> statement-breakpoint
ALTER TABLE `scan_results` ADD `diagnostics_json` mediumtext AFTER `scan_status`;
--> statement-breakpoint
