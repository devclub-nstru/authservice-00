import crypto from "node:crypto";
import db from "../../db/client/db.js";
import env from "../../core/config/config.js";
import {
  badRequest,
  conflict,
  forbidden,
  notFound,
} from "../../utils/errors.js";
import { hashPassword } from "../auth/password.service.js";
import {
  decryptClientSecret,
  encryptClientSecret,
} from "./client-secret-crypto.js";
import {
  findOrganizationById,
  findOrganizationMember,
} from "../organization/organization.repository.js";
import {
  CLIENT_CALLBACK_BASE_PATH,
  CLIENT_ERRORS,
  CLIENT_MANAGE_ROLES,
  CLIENT_MESSAGES,
  CLIENT_SECRET_BYTES,
} from "./client.constants.js";
import {
  createOrganizationClient,
  createOrganizationClientProvider,
  deleteOrganizationClientById,
  deleteOrganizationClientProvider,
  findOrganizationClientById,
  findOrganizationClientByNormalizedName,
  findOrganizationClientProvider,
  listOrganizationClientUsers,
  listOrganizationClientProviders,
  listOrganizationClientProvidersByOrgId,
  listOrganizationClientsByOrgId,
  findOrganizationClientWebhookConfig,
  updateOrganizationClientById,
  updateOrganizationClientProvider,
} from "./client.repository.js";

const normalizeName = (name) => name.trim().replace(/\s+/g, " ");
const normalizeForUniqueness = (value) => value.trim().toLowerCase();

const generatePlatformClientSecret = () => {
  return crypto.randomBytes(CLIENT_SECRET_BYTES).toString("base64url");
};

const generateWebhookSecret = () => {
  return crypto.randomBytes(CLIENT_SECRET_BYTES).toString("base64url");
};

const normalizeAuthorizedOrigins = (authorizedOrigins) => {
  try {
    const deduplicated = new Set();

    for (const originUrl of authorizedOrigins || []) {
      const parsed = new URL(originUrl);
      deduplicated.add(parsed.origin);
    }

    return Array.from(deduplicated).sort();
  } catch {
    badRequest(CLIENT_ERRORS.INVALID_AUTHORIZED_ORIGIN);
  }
};

const normalizeRedirectUris = (redirectUris, { required = false } = {}) => {
  try {
    const deduplicated = new Set();

    for (const redirectUri of redirectUris || []) {
      const parsed = new URL(redirectUri);
      deduplicated.add(parsed.toString());
    }

    const normalized = Array.from(deduplicated).sort();

    if (required && normalized.length === 0) {
      badRequest(CLIENT_ERRORS.REDIRECT_URI_REQUIRED);
    }

    return normalized;
  } catch {
    badRequest(CLIENT_ERRORS.INVALID_REDIRECT_URI);
  }
};

const getProviderCallbackUrl = (orgId, clientId, provider) => {
  return `${env.API_BASE_URL}${CLIENT_CALLBACK_BASE_PATH}/${orgId}/clients/${clientId}/${provider}/callback`;
};

const getVisibleWebhookSecret = (client, canManage) => {
  if (!canManage) {
    return undefined;
  }

  if (!client.webhookSecretCiphertext) {
    return null;
  }

  return decryptClientSecret(client.webhookSecretCiphertext);
};

const sanitizeProvider = (provider, canManage) => {
  const base = {
    id: provider.id,
    provider: provider.provider,
    callbackUrl: provider.callbackUrl,
    isActive: provider.isActive,
    createdAt: provider.createdAt,
    updatedAt: provider.updatedAt,
    secretConfigured: Boolean(
      provider.providerClientSecretHash ||
      provider.providerClientSecretCiphertext,
    ),
  };

  if (!canManage) {
    return base;
  }

  return {
    ...base,
    providerClientId: provider.providerClientId,
  };
};

const sanitizeClient = (client, providers, canManage) => ({
  id: client.id,
  orgId: client.orgId,
  name: client.name,
  redirectUris: client.redirectUris,
  authorizedOrigins: client.authorizedOrigins,
  createdByUserId: client.createdByUserId,
  updatedByUserId: client.updatedByUserId,
  createdAt: client.createdAt,
  updatedAt: client.updatedAt,
  clientSecretConfigured: Boolean(
    client.clientSecretHash || client.clientSecretCiphertext,
  ),
  webhookEnabled: client.webhookEnabled || false,
  webhookUrl: canManage ? client.webhookUrl || null : undefined,
  webhookSecret: getVisibleWebhookSecret(client, canManage),
  providers: providers.map((provider) => sanitizeProvider(provider, canManage)),
});

const requireOrganization = async (orgId, tx = db) => {
  const organization = await findOrganizationById(orgId, tx);
  if (!organization) {
    notFound(CLIENT_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  return organization;
};

const requireOrganizationMembership = async (orgId, actorUserId, tx = db) => {
  const membership = await findOrganizationMember(orgId, actorUserId, tx);
  if (!membership) {
    forbidden(CLIENT_ERRORS.MEMBER_REQUIRED);
  }

  return membership;
};

const requireOrganizationManageRole = async (orgId, actorUserId, tx = db) => {
  const membership = await requireOrganizationMembership(
    orgId,
    actorUserId,
    tx,
  );
  if (!CLIENT_MANAGE_ROLES.includes(membership.role)) {
    forbidden(CLIENT_ERRORS.INSUFFICIENT_PERMISSIONS);
  }

  return membership;
};

const ensureClientNameUnique = async (
  orgId,
  clientName,
  existingClientId = null,
  tx = db,
) => {
  const normalizedName = normalizeForUniqueness(clientName);
  const existing = await findOrganizationClientByNormalizedName(
    orgId,
    normalizedName,
    tx,
  );

  if (existing && existing.id !== existingClientId) {
    conflict(CLIENT_ERRORS.CLIENT_NAME_EXISTS);
  }
};

const getClientWithProviders = async (orgId, clientId, tx = db) => {
  const client = await findOrganizationClientById(orgId, clientId, tx);
  if (!client) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  const providers = await listOrganizationClientProviders(client.id, tx);
  return { client, providers };
};

export const createOrganizationClientForUser = async (
  orgId,
  actorUserId,
  payload,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const normalizedName = normalizeName(payload.name);
  const redirectUris = normalizeRedirectUris(payload.redirectUris, {
    required: true,
  });
  const authorizedOrigins = normalizeAuthorizedOrigins(
    payload.authorizedOrigins,
  );
  const plainClientSecret = generatePlatformClientSecret();
  const clientSecretHash = await hashPassword(plainClientSecret);
  const clientSecretCiphertext = encryptClientSecret(plainClientSecret);

  const createdClient = await db.transaction(async (tx) => {
    await ensureClientNameUnique(orgId, normalizedName, null, tx);

    return createOrganizationClient(
      {
        orgId,
        name: normalizedName,
        redirectUris,
        authorizedOrigins,
        clientSecretHash,
        clientSecretCiphertext,
        createdByUserId: actorUserId,
        updatedByUserId: actorUserId,
      },
      tx,
    );
  });

  return {
    client: sanitizeClient(createdClient, [], true),
    clientSecret: plainClientSecret,
  };
};

export const listOrganizationClientsForUser = async (orgId, actorUserId) => {
  await requireOrganization(orgId);
  const membership = await requireOrganizationMembership(orgId, actorUserId);
  const canManage = CLIENT_MANAGE_ROLES.includes(membership.role);

  const [clients, providers] = await Promise.all([
    listOrganizationClientsByOrgId(orgId),
    listOrganizationClientProvidersByOrgId(orgId),
  ]);

  const providersByClientId = providers.reduce((acc, provider) => {
    if (!acc[provider.clientId]) {
      acc[provider.clientId] = [];
    }

    acc[provider.clientId].push(provider);
    return acc;
  }, {});

  return clients.map((client) => {
    const clientProviders = providersByClientId[client.id] || [];
    return sanitizeClient(client, clientProviders, canManage);
  });
};

export const getOrganizationClientForUser = async (
  orgId,
  clientId,
  actorUserId,
) => {
  await requireOrganization(orgId);
  const membership = await requireOrganizationMembership(orgId, actorUserId);
  const canManage = CLIENT_MANAGE_ROLES.includes(membership.role);

  const { client, providers } = await getClientWithProviders(orgId, clientId);
  return sanitizeClient(client, providers, canManage);
};

export const updateOrganizationClientForUser = async (
  orgId,
  clientId,
  actorUserId,
  payload,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const updatedClient = await db.transaction(async (tx) => {
    await getClientWithProviders(orgId, clientId, tx);

    const updates = {
      updatedByUserId: actorUserId,
    };

    if (payload.name) {
      const normalizedName = normalizeName(payload.name);
      await ensureClientNameUnique(orgId, normalizedName, clientId, tx);
      updates.name = normalizedName;
    }

    if (Object.prototype.hasOwnProperty.call(payload, "authorizedOrigins")) {
      updates.authorizedOrigins = normalizeAuthorizedOrigins(
        payload.authorizedOrigins,
      );
    }

    if (Object.prototype.hasOwnProperty.call(payload, "redirectUris")) {
      updates.redirectUris = normalizeRedirectUris(payload.redirectUris, {
        required: true,
      });
    }

    return updateOrganizationClientById(orgId, clientId, updates, tx);
  });

  if (!updatedClient) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  const providers = await listOrganizationClientProviders(clientId);
  return sanitizeClient(updatedClient, providers, true);
};

export const deleteOrganizationClientForUser = async (
  orgId,
  clientId,
  actorUserId,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const deleted = await deleteOrganizationClientById(orgId, clientId);
  if (!deleted) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  return CLIENT_MESSAGES.CLIENT_DELETED;
};

export const addOrganizationClientProviderForUser = async (
  orgId,
  clientId,
  actorUserId,
  payload,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const { client } = await getClientWithProviders(orgId, clientId);

  const existingProvider = await findOrganizationClientProvider(
    client.id,
    payload.provider,
  );

  if (existingProvider) {
    conflict(CLIENT_ERRORS.PROVIDER_EXISTS);
  }

  const providerSecretHash = await hashPassword(payload.providerClientSecret);
  const providerSecretCiphertext = encryptClientSecret(
    payload.providerClientSecret,
  );
  const created = await createOrganizationClientProvider({
    clientId: client.id,
    provider: payload.provider,
    providerClientId: payload.providerClientId,
    providerClientSecretHash: providerSecretHash,
    providerClientSecretCiphertext: providerSecretCiphertext,
    callbackUrl: getProviderCallbackUrl(orgId, client.id, payload.provider),
    isActive: true,
    createdByUserId: actorUserId,
    updatedByUserId: actorUserId,
  });

  return sanitizeProvider(created, true);
};

export const updateOrganizationClientProviderForUser = async (
  orgId,
  clientId,
  provider,
  actorUserId,
  payload,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const { client } = await getClientWithProviders(orgId, clientId);
  const existingProvider = await findOrganizationClientProvider(
    client.id,
    provider,
  );

  if (!existingProvider) {
    notFound(CLIENT_ERRORS.PROVIDER_NOT_FOUND);
  }

  const updates = {
    updatedByUserId: actorUserId,
  };

  if (payload.providerClientId) {
    updates.providerClientId = payload.providerClientId;
  }

  if (typeof payload.isActive === "boolean") {
    updates.isActive = payload.isActive;
  }

  if (payload.providerClientSecret) {
    updates.providerClientSecretHash = await hashPassword(
      payload.providerClientSecret,
    );
    updates.providerClientSecretCiphertext = encryptClientSecret(
      payload.providerClientSecret,
    );
  }

  const updated = await updateOrganizationClientProvider(
    client.id,
    provider,
    updates,
  );

  if (!updated) {
    notFound(CLIENT_ERRORS.PROVIDER_NOT_FOUND);
  }

  return sanitizeProvider(updated, true);
};

export const deleteOrganizationClientProviderForUser = async (
  orgId,
  clientId,
  provider,
  actorUserId,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const { client } = await getClientWithProviders(orgId, clientId);
  const deleted = await deleteOrganizationClientProvider(client.id, provider);

  if (!deleted) {
    notFound(CLIENT_ERRORS.PROVIDER_NOT_FOUND);
  }

  return CLIENT_MESSAGES.PROVIDER_REMOVED;
};

export const configureOrganizationClientWebhookForUser = async (
  orgId,
  clientId,
  actorUserId,
  payload,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const plainWebhookSecret = generateWebhookSecret();
  const encryptedWebhookSecret = encryptClientSecret(plainWebhookSecret);
  const webhookSecretHash = await hashPassword(plainWebhookSecret);

  const updated = await updateOrganizationClientById(orgId, clientId, {
    webhookUrl: payload.webhookUrl,
    webhookSecretHash,
    webhookSecretCiphertext: encryptedWebhookSecret,
    webhookEnabled: true,
    updatedByUserId: actorUserId,
  });

  if (!updated) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  return {
    webhookEnabled: true,
    webhookUrl: updated.webhookUrl,
    webhookSecret: plainWebhookSecret,
  };
};

export const rotateOrganizationClientWebhookSecretForUser = async (
  orgId,
  clientId,
  actorUserId,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const currentConfig = await findOrganizationClientWebhookConfig(
    orgId,
    clientId,
  );
  if (!currentConfig) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  if (!currentConfig.webhookEnabled || !currentConfig.webhookUrl) {
    badRequest(CLIENT_ERRORS.WEBHOOK_NOT_CONFIGURED);
  }

  const plainWebhookSecret = generateWebhookSecret();
  const encryptedWebhookSecret = encryptClientSecret(plainWebhookSecret);
  const webhookSecretHash = await hashPassword(plainWebhookSecret);

  const updated = await updateOrganizationClientById(orgId, clientId, {
    webhookSecretHash,
    webhookSecretCiphertext: encryptedWebhookSecret,
    updatedByUserId: actorUserId,
  });

  if (!updated) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  return {
    webhookEnabled: true,
    webhookUrl: updated.webhookUrl,
    webhookSecret: plainWebhookSecret,
  };
};

export const disableOrganizationClientWebhookForUser = async (
  orgId,
  clientId,
  actorUserId,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const updated = await updateOrganizationClientById(orgId, clientId, {
    webhookEnabled: false,
    webhookUrl: null,
    webhookSecretHash: null,
    webhookSecretCiphertext: null,
    updatedByUserId: actorUserId,
  });

  if (!updated) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  return CLIENT_MESSAGES.WEBHOOK_DISABLED;
};

export const getOrganizationClientWebhookConfigForDispatch = async (
  orgId,
  clientId,
) => {
  const config = await findOrganizationClientWebhookConfig(orgId, clientId);
  if (!config || !config.webhookEnabled || !config.webhookUrl) {
    return null;
  }

  if (!config.webhookSecretCiphertext) {
    return null;
  }

  return {
    clientId: config.id,
    orgId: config.orgId,
    clientName: config.name,
    webhookUrl: config.webhookUrl,
    webhookSecret: decryptClientSecret(config.webhookSecretCiphertext),
  };
};

export const rotateOrganizationClientSecretForUser = async (
  orgId,
  clientId,
  actorUserId,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);

  const plainClientSecret = generatePlatformClientSecret();
  const clientSecretHash = await hashPassword(plainClientSecret);
  const clientSecretCiphertext = encryptClientSecret(plainClientSecret);

  const updated = await updateOrganizationClientById(orgId, clientId, {
    clientSecretHash,
    clientSecretCiphertext,
    updatedByUserId: actorUserId,
  });

  if (!updated) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  return {
    client: sanitizeClient(
      updated,
      await listOrganizationClientProviders(clientId),
      true,
    ),
    clientSecret: plainClientSecret,
  };
};

export const listOrganizationClientUsersForUser = async (
  orgId,
  clientId,
  actorUserId,
  pagination,
) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);
  await getClientWithProviders(orgId, clientId);

  const users = await listOrganizationClientUsers(orgId, clientId, pagination);

  return users;
};
