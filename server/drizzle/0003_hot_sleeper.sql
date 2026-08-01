ALTER TABLE `requests` MODIFY COLUMN `approved_by` bigint unsigned;--> statement-breakpoint
ALTER TABLE `scan_results` MODIFY COLUMN `token_id` bigint unsigned;--> statement-breakpoint
ALTER TABLE `shadow_findings` MODIFY COLUMN `promoted_by` bigint unsigned;--> statement-breakpoint
ALTER TABLE `suspicious_hashes` MODIFY COLUMN `reviewed_by` bigint unsigned;--> statement-breakpoint
ALTER TABLE `tokens` MODIFY COLUMN `created_by` bigint unsigned;