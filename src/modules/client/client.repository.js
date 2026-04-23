import { and, asc, eq, sql } from "drizzle-orm";
import db from "../../db/client/db.js";
import {
  organizationClientProviders,
  organizationClientUsers,
  organizationClients,
  users,
} from "../../db/schemas/index.js";

export const createOrganizationClient = async (payload, tx = db) => {
  const [created] = await tx
    .insert(organizationClients)
    .values(payload)
    .returning();

  return created;
};

export const findOrganizationClientById = async (orgId, clientId, tx = db) => {
  const [client] = await tx
    .select()
    .from(organizationClients)
    .where(
      and(
        eq(organizationClients.orgId, orgId),
        eq(organizationClients.id, clientId),
      ),
    )
    .limit(1);

  return client || null;
};

export const findOrganizationClientByClientId = async (clientId, tx = db) => {
  const [client] = await tx
    .select()
    .from(organizationClients)
    .where(eq(organizationClients.id, clientId))
    .limit(1);

  return client || null;
};

export const findOrganizationClientByNormalizedName = async (
  orgId,
  normalizedName,
  tx = db,
) => {
  const [client] = await tx
    .select()
    .from(organizationClients)
    .where(
      and(
        eq(organizationClients.orgId, orgId),
        sql`lower(${organizationClients.name}) = ${normalizedName}`,
      ),
    )
    .limit(1);

  return client || null;
};

export const listOrganizationClientsByOrgId = async (orgId, tx = db) => {
  return tx
    .select()
    .from(organizationClients)
    .where(eq(organizationClients.orgId, orgId))
    .orderBy(asc(organizationClients.createdAt));
};

export const updateOrganizationClientById = async (
  orgId,
  clientId,
  payload,
  tx = db,
) => {
  const [updated] = await tx
    .update(organizationClients)
    .set({ ...payload, updatedAt: new Date() })
    .where(
      and(
        eq(organizationClients.orgId, orgId),
        eq(organizationClients.id, clientId),
      ),
    )
    .returning();

  return updated || null;
};

export const findOrganizationClientWebhookConfig = async (
  orgId,
  clientId,
  tx = db,
) => {
  const [client] = await tx
    .select({
      id: organizationClients.id,
      orgId: organizationClients.orgId,
      name: organizationClients.name,
      webhookUrl: organizationClients.webhookUrl,
      webhookSecretHash: organizationClients.webhookSecretHash,
      webhookSecretCiphertext: organizationClients.webhookSecretCiphertext,
      webhookEnabled: organizationClients.webhookEnabled,
      webhookVerified: organizationClients.webhookVerified,
      webhookVerifiedAt: organizationClients.webhookVerifiedAt,
    })
    .from(organizationClients)
    .where(
      and(
        eq(organizationClients.orgId, orgId),
        eq(organizationClients.id, clientId),
      ),
    )
    .limit(1);

  return client || null;
};

export const deleteOrganizationClientById = async (
  orgId,
  clientId,
  tx = db,
) => {
  const [deleted] = await tx
    .delete(organizationClients)
    .where(
      and(
        eq(organizationClients.orgId, orgId),
        eq(organizationClients.id, clientId),
      ),
    )
    .returning();

  return deleted || null;
};

export const createOrganizationClientProvider = async (payload, tx = db) => {
  const [created] = await tx
    .insert(organizationClientProviders)
    .values(payload)
    .returning();

  return created;
};

export const findOrganizationClientProvider = async (
  clientId,
  provider,
  tx = db,
) => {
  const [clientProvider] = await tx
    .select()
    .from(organizationClientProviders)
    .where(
      and(
        eq(organizationClientProviders.clientId, clientId),
        eq(organizationClientProviders.provider, provider),
      ),
    )
    .limit(1);

  return clientProvider || null;
};

export const listOrganizationClientProviders = async (clientId, tx = db) => {
  return tx
    .select()
    .from(organizationClientProviders)
    .where(eq(organizationClientProviders.clientId, clientId))
    .orderBy(asc(organizationClientProviders.createdAt));
};

export const listOrganizationClientProvidersByOrgId = async (
  orgId,
  tx = db,
) => {
  return tx
    .select({
      id: organizationClientProviders.id,
      clientId: organizationClientProviders.clientId,
      provider: organizationClientProviders.provider,
      providerClientId: organizationClientProviders.providerClientId,
      providerClientSecretHash:
        organizationClientProviders.providerClientSecretHash,
      providerClientSecretCiphertext:
        organizationClientProviders.providerClientSecretCiphertext,
      callbackUrl: organizationClientProviders.callbackUrl,
      isActive: organizationClientProviders.isActive,
      createdByUserId: organizationClientProviders.createdByUserId,
      updatedByUserId: organizationClientProviders.updatedByUserId,
      createdAt: organizationClientProviders.createdAt,
      updatedAt: organizationClientProviders.updatedAt,
    })
    .from(organizationClientProviders)
    .innerJoin(
      organizationClients,
      eq(organizationClients.id, organizationClientProviders.clientId),
    )
    .where(eq(organizationClients.orgId, orgId))
    .orderBy(asc(organizationClientProviders.createdAt));
};

export const findActiveOrganizationClientProvider = async (
  orgId,
  clientId,
  provider,
  tx = db,
) => {
  const [clientProvider] = await tx
    .select({
      clientId: organizationClientProviders.clientId,
      provider: organizationClientProviders.provider,
      providerClientId: organizationClientProviders.providerClientId,
      providerClientSecretHash:
        organizationClientProviders.providerClientSecretHash,
      providerClientSecretCiphertext:
        organizationClientProviders.providerClientSecretCiphertext,
      callbackUrl: organizationClientProviders.callbackUrl,
      isActive: organizationClientProviders.isActive,
      organizationName: organizationClients.name,
      authorizedOrigins: organizationClients.authorizedOrigins,
      redirectUris: organizationClients.redirectUris,
    })
    .from(organizationClientProviders)
    .innerJoin(
      organizationClients,
      eq(organizationClients.id, organizationClientProviders.clientId),
    )
    .where(
      and(
        eq(organizationClients.orgId, orgId),
        eq(organizationClients.id, clientId),
        eq(organizationClientProviders.provider, provider),
        eq(organizationClientProviders.isActive, true),
      ),
    )
    .limit(1);

  return clientProvider || null;
};

export const listActiveOrganizationClientProviders = async (
  orgId,
  clientId,
  tx = db,
) => {
  return tx
    .select({
      provider: organizationClientProviders.provider,
      callbackUrl: organizationClientProviders.callbackUrl,
      isActive: organizationClientProviders.isActive,
    })
    .from(organizationClientProviders)
    .innerJoin(
      organizationClients,
      eq(organizationClients.id, organizationClientProviders.clientId),
    )
    .where(
      and(
        eq(organizationClients.orgId, orgId),
        eq(organizationClients.id, clientId),
        eq(organizationClientProviders.isActive, true),
      ),
    )
    .orderBy(asc(organizationClientProviders.createdAt));
};

export const updateOrganizationClientProvider = async (
  clientId,
  provider,
  payload,
  tx = db,
) => {
  const [updated] = await tx
    .update(organizationClientProviders)
    .set({ ...payload, updatedAt: new Date() })
    .where(
      and(
        eq(organizationClientProviders.clientId, clientId),
        eq(organizationClientProviders.provider, provider),
      ),
    )
    .returning();

  return updated || null;
};

export const deleteOrganizationClientProvider = async (
  clientId,
  provider,
  tx = db,
) => {
  const [deleted] = await tx
    .delete(organizationClientProviders)
    .where(
      and(
        eq(organizationClientProviders.clientId, clientId),
        eq(organizationClientProviders.provider, provider),
      ),
    )
    .returning();

  return deleted || null;
};

export const upsertOrganizationClientUser = async (
  clientId,
  userId,
  tx = db,
) => {
  const now = new Date();

  const [row] = await tx
    .insert(organizationClientUsers)
    .values({
      clientId,
      userId,
      firstSignedInAt: now,
      lastSignedInAt: now,
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: [
        organizationClientUsers.clientId,
        organizationClientUsers.userId,
      ],
      set: {
        lastSignedInAt: now,
        updatedAt: now,
      },
    })
    .returning();

  return row;
};

export const listOrganizationClientUsers = async (
  orgId,
  clientId,
  { limit = 50, offset = 0 } = {},
  tx = db,
) => {
  return tx
    .select({
      userId: users.id,
      email: users.email,
      name: users.name,
      avatarUrl: users.avatarUrl,
      emailVerified: users.emailVerified,
      lastLoginAt: users.lastLoginAt,
      firstSignedInAt: organizationClientUsers.firstSignedInAt,
      lastSignedInAt: organizationClientUsers.lastSignedInAt,
      linkedAt: organizationClientUsers.createdAt,
    })
    .from(organizationClientUsers)
    .innerJoin(
      organizationClients,
      eq(organizationClients.id, organizationClientUsers.clientId),
    )
    .innerJoin(users, eq(users.id, organizationClientUsers.userId))
    .where(
      and(
        eq(organizationClients.orgId, orgId),
        eq(organizationClientUsers.clientId, clientId),
      ),
    )
    .orderBy(asc(organizationClientUsers.createdAt))
    .limit(limit)
    .offset(offset);
};
