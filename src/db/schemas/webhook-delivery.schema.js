import { relations, sql } from "drizzle-orm";
import {
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { organizations } from "./organization.schema.js";
import { organizationClients } from "./organization-client.schema.js";
import { users } from "./user.schema.js";

export const webhookDeliveryStatusEnum = pgEnum("webhook_delivery_status", [
  "success",
  "failed",
]);

export const webhookDeliverySourceEnum = pgEnum("webhook_delivery_source", [
  "event",
  "replay",
  "test",
  "verify",
]);

export const webhookDeliveries = pgTable(
  "webhook_deliveries",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    clientId: uuid("client_id")
      .notNull()
      .references(() => organizationClients.id, { onDelete: "cascade" }),
    event: varchar("event", { length: 120 }).notNull(),
    payload: jsonb("payload")
      .default(sql`'{}'::jsonb`)
      .notNull(),
    idempotencyKey: varchar("idempotency_key", { length: 128 }).notNull(),
    source: webhookDeliverySourceEnum("source").default("event").notNull(),
    status: webhookDeliveryStatusEnum("status").notNull(),
    attempt: integer("attempt").default(1).notNull(),
    triggeredByUserId: uuid("triggered_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    replayOfDeliveryId: uuid("replay_of_delivery_id"),
    httpStatus: integer("http_status"),
    responseTimeMs: integer("response_time_ms"),
    responseBody: text("response_body"),
    errorMessage: text("error_message"),
    deliveredAt: timestamp("delivered_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    webhookDeliveriesOrgIdx: index("idx_webhook_deliveries_org_id").on(
      table.orgId,
    ),
    webhookDeliveriesClientIdx: index("idx_webhook_deliveries_client_id").on(
      table.clientId,
    ),
    webhookDeliveriesClientCreatedIdx: index(
      "idx_webhook_deliveries_client_created_at",
    ).on(table.clientId, table.createdAt),
    webhookDeliveriesClientStatusIdx: index(
      "idx_webhook_deliveries_client_status",
    ).on(table.clientId, table.status),
    webhookDeliveriesIdempotencyIdx: index(
      "idx_webhook_deliveries_idempotency_key",
    ).on(table.idempotencyKey),
    webhookDeliveriesReplayOfIdx: index(
      "idx_webhook_deliveries_replay_of_delivery_id",
    ).on(table.replayOfDeliveryId),
  }),
);

export const webhookDeliveriesRelations = relations(
  webhookDeliveries,
  ({ one }) => ({
    organization: one(organizations, {
      fields: [webhookDeliveries.orgId],
      references: [organizations.id],
    }),
    client: one(organizationClients, {
      fields: [webhookDeliveries.clientId],
      references: [organizationClients.id],
    }),
    triggeredByUser: one(users, {
      fields: [webhookDeliveries.triggeredByUserId],
      references: [users.id],
      relationName: "webhook_delivery_triggered_by_user",
    }),
  }),
);
