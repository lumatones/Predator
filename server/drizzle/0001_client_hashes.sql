CREATE TABLE `client_hashes` (
	`id` serial AUTO_INCREMENT NOT NULL,
	`version` varchar(20) NOT NULL,
	`sha256` char(64) NOT NULL,
	`created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
	CONSTRAINT `client_hashes_id` PRIMARY KEY(`id`),
	CONSTRAINT `client_hashes_version_unique` UNIQUE(`version`)
);
--> statement-breakpoint
