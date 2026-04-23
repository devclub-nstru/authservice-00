import { relations, sql } from "drizzle-orm";
import {
  boolean,
  integer,
  index,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import { organizations } from "./organization.schema.js";
import { users } from "./user.schema.js";

export const organizationClientProviderEnum = pgEnum(
  "organization_client_provider",
  ["google", "github"],
);

export const oauthFlowTypeEnum = pgEnum("oauth_flow_type", [
  "signin",
  "signup",
]);

export const organizationClients = pgTable(
  "organization_clients",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    redirectUris: jsonb("redirect_uris")
      .default(sql`'[]'::jsonb`)
      .notNull(),
    authorizedOrigins: jsonb("authorized_origins")
      .default(sql`'[]'::jsonb`)
      .notNull(),
    clientSecretHash: varchar("client_secret_hash", { length: 255 }),
    clientSecretCiphertext: text("client_secret_ciphertext"),
    webhookUrl: varchar("webhook_url", { length: 500 }),
    webhookSecretHash: varchar("webhook_secret_hash", { length: 255 }),
    webhookSecretCiphertext: text("webhook_secret_ciphertext"),
    webhookEnabled: boolean("webhook_enabled").default(false).notNull(),
    webhookVerified: boolean("webhook_verified").default(false).notNull(),
    webhookVerifiedAt: timestamp("webhook_verified_at", {
      withTimezone: true,
    }),
    createdByUserId: uuid("created_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    updatedByUserId: uuid("updated_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    organizationClientsOrgIdx: index("idx_organization_clients_org_id").on(
      table.orgId,
    ),
    organizationClientsNamePerOrgUniqueIdx: uniqueIndex(
      "organization_clients_name_per_org_unique_idx",
    ).on(table.orgId, sql`lower(${table.name})`),
  }),
);

export const organizationClientProviders = pgTable(
  "organization_client_providers",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    clientId: uuid("client_id")
      .notNull()
      .references(() => organizationClients.id, { onDelete: "cascade" }),
    provider: organizationClientProviderEnum("provider").notNull(),
    providerClientId: varchar("provider_client_id", { length: 255 }).notNull(),
    providerClientSecretHash: varchar("provider_client_secret_hash", {
      length: 255,
    }).notNull(),
    providerClientSecretCiphertext: text("provider_client_secret_ciphertext"),
    callbackUrl: varchar("callback_url", { length: 500 }).notNull(),
    isActive: boolean("is_active").default(true).notNull(),
    createdByUserId: uuid("created_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    updatedByUserId: uuid("updated_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    organizationClientProvidersClientIdx: index(
      "idx_organization_client_providers_client_id",
    ).on(table.clientId),
    organizationClientProvidersUniqueProviderPerClientIdx: uniqueIndex(
      "organization_client_providers_unique_provider_per_client_idx",
    ).on(table.clientId, table.provider),
  }),
);

export const organizationClientUsers = pgTable(
  "organization_client_users",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    clientId: uuid("client_id")
      .notNull()
      .references(() => organizationClients.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    firstSignedInAt: timestamp("first_signed_in_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    lastSignedInAt: timestamp("last_signed_in_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    organizationClientUsersUniqueIdx: uniqueIndex(
      "organization_client_users_unique_idx",
    ).on(table.clientId, table.userId),
    organizationClientUsersClientIdx: index(
      "idx_organization_client_users_client_id",
    ).on(table.clientId),
    organizationClientUsersUserIdx: index(
      "idx_organization_client_users_user_id",
    ).on(table.userId),
  }),
);

export const oauthReloginRequirements = pgTable(
  "oauth_relogin_requirements",
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
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    clientContext: varchar("client_context", { length: 255 }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    oauthReloginRequirementsUniqueIdx: uniqueIndex(
      "oauth_relogin_requirements_unique_idx",
    ).on(table.orgId, table.clientId, table.userId),
    oauthReloginRequirementsExpiresIdx: index(
      "idx_oauth_relogin_requirements_expires_at",
    ).on(table.expiresAt),
  }),
);

export const oauthReloginChallenges = pgTable(
  "oauth_relogin_challenges",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`gen_random_uuid()`),
    token: varchar("token", { length: 255 }).notNull(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    sessionId: uuid("session_id").notNull(),
    sessionVersion: integer("session_version").notNull(),
    orgId: uuid("org_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    clientId: uuid("client_id")
      .notNull()
      .references(() => organizationClients.id, { onDelete: "cascade" }),
    flowType: oauthFlowTypeEnum("flow_type").notNull(),
    clientContext: varchar("client_context", { length: 255 }),
    redirectTo: text("redirect_to").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .defaultNow()
      .notNull(),
  },
  (table) => ({
    oauthReloginChallengesTokenUniqueIdx: uniqueIndex(
      "oauth_relogin_challenges_token_unique_idx",
    ).on(table.token),
    oauthReloginChallengesExpiresIdx: index(
      "idx_oauth_relogin_challenges_expires_at",
    ).on(table.expiresAt),
  }),
);

export const organizationClientsRelations = relations(
  organizationClients,
  ({ one, many }) => ({
    organization: one(organizations, {
      fields: [organizationClients.orgId],
      references: [organizations.id],
    }),
    createdByUser: one(users, {
      fields: [organizationClients.createdByUserId],
      references: [users.id],
      relationName: "organization_client_created_by_user",
    }),
    updatedByUser: one(users, {
      fields: [organizationClients.updatedByUserId],
      references: [users.id],
      relationName: "organization_client_updated_by_user",
    }),
    providers: many(organizationClientProviders),
    clientUsers: many(organizationClientUsers),
  }),
);

export const organizationClientProvidersRelations = relations(
  organizationClientProviders,
  ({ one }) => ({
    client: one(organizationClients, {
      fields: [organizationClientProviders.clientId],
      references: [organizationClients.id],
    }),
    createdByUser: one(users, {
      fields: [organizationClientProviders.createdByUserId],
      references: [users.id],
      relationName: "organization_client_provider_created_by_user",
    }),
    updatedByUser: one(users, {
      fields: [organizationClientProviders.updatedByUserId],
      references: [users.id],
      relationName: "organization_client_provider_updated_by_user",
    }),
  }),
);

export const organizationClientUsersRelations = relations(
  organizationClientUsers,
  ({ one }) => ({
    client: one(organizationClients, {
      fields: [organizationClientUsers.clientId],
      references: [organizationClients.id],
    }),
    user: one(users, {
      fields: [organizationClientUsers.userId],
      references: [users.id],
      relationName: "organization_client_user",
    }),
  }),
);
