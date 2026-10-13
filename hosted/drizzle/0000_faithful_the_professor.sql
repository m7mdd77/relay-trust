CREATE TABLE `relay_sandboxes` (
	`id` text PRIMARY KEY NOT NULL,
	`revision` integer NOT NULL,
	`expires` integer NOT NULL,
	`data` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `relay_sandbox_expiry` ON `relay_sandboxes` (`expires`);