CREATE TYPE "public"."webhook_delivery_source" AS ENUM('event', 'replay', 'test', 'verify');--> statement-breakpoint
CREATE TYPE "public"."webhook_delivery_status" AS ENUM('success', 'failed');--> statement-breakpoint
CREATE TABLE "webhook_deliveries" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"client_id" uuid NOT NULL,
	"event" varchar(120) NOT NULL,
	"payload" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"idempotency_key" varchar(128) NOT NULL,
	"source" "webhook_delivery_source" DEFAULT 'event' NOT NULL,
	"status" "webhook_delivery_status" NOT NULL,
	"attempt" integer DEFAULT 1 NOT NULL,
	"triggered_by_user_id" uuid,
	"replay_of_delivery_id" uuid,
	"http_status" integer,
	"response_time_ms" integer,
	"response_body" text,
	"error_message" text,
	"delivered_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "organization_clients" ADD COLUMN "webhook_verified" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "organization_clients" ADD COLUMN "webhook_verified_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_client_id_organization_clients_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."organization_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_triggered_by_user_id_users_id_fk" FOREIGN KEY ("triggered_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_webhook_deliveries_org_id" ON "webhook_deliveries" USING btree ("org_id");--> statement-breakpoint
CREATE INDEX "idx_webhook_deliveries_client_id" ON "webhook_deliveries" USING btree ("client_id");--> statement-breakpoint
CREATE INDEX "idx_webhook_deliveries_client_created_at" ON "webhook_deliveries" USING btree ("client_id","created_at");--> statement-breakpoint
CREATE INDEX "idx_webhook_deliveries_client_status" ON "webhook_deliveries" USING btree ("client_id","status");--> statement-breakpoint
CREATE INDEX "idx_webhook_deliveries_idempotency_key" ON "webhook_deliveries" USING btree ("idempotency_key");--> statement-breakpoint
CREATE INDEX "idx_webhook_deliveries_replay_of_delivery_id" ON "webhook_deliveries" USING btree ("replay_of_delivery_id");