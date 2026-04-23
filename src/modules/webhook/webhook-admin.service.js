import crypto from "node:crypto";
import { badRequest, forbidden, notFound } from "../../utils/errors.js";
import {
  CLIENT_ERRORS,
  CLIENT_MANAGE_ROLES,
  CLIENT_MESSAGES,
} from "../client/client.constants.js";
import {
  findOrganizationClientById,
  findOrganizationClientWebhookConfig,
  updateOrganizationClientById,
} from "../client/client.repository.js";
import { decryptClientSecret } from "../client/client-secret-crypto.js";
import {
  findOrganizationById,
  findOrganizationMember,
} from "../organization/organization.repository.js";
import { queueServiceWebhookEvent } from "./webhook.queue.js";
import {
  countWebhookDeliveriesByClient,
  createWebhookDelivery,
  findWebhookDeliveryById,
  getWebhookDeliveryStatusSummary,
  listWebhookDeliveriesByClient,
} from "./webhook.repository.js";
import { dispatchServiceWebhook } from "./webhook.service.js";

const createIdempotencyKey = ({ orgId, clientId, event, seed }) => {
  return crypto
    .createHash("sha256")
    .update(`${orgId}:${clientId}:${event}:${seed}`)
    .digest("hex");
};

const requireOrganization = async (orgId) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(CLIENT_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  return organization;
};

const requireOrganizationManageRole = async (orgId, actorUserId) => {
  const membership = await findOrganizationMember(orgId, actorUserId);
  if (!membership) {
    forbidden(CLIENT_ERRORS.MEMBER_REQUIRED);
  }

  if (!CLIENT_MANAGE_ROLES.includes(membership.role)) {
    forbidden(CLIENT_ERRORS.INSUFFICIENT_PERMISSIONS);
  }

  return membership;
};

const requireClient = async (orgId, clientId) => {
  const client = await findOrganizationClientById(orgId, clientId);
  if (!client) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  return client;
};

const getConfiguredWebhook = async (orgId, clientId) => {
  const config = await findOrganizationClientWebhookConfig(orgId, clientId);
  if (!config) {
    notFound(CLIENT_ERRORS.CLIENT_NOT_FOUND);
  }

  if (
    !config.webhookEnabled ||
    !config.webhookUrl ||
    !config.webhookSecretCiphertext
  ) {
    badRequest(CLIENT_ERRORS.WEBHOOK_NOT_CONFIGURED);
  }

  return {
    ...config,
    webhookSecret: decryptClientSecret(config.webhookSecretCiphertext),
  };
};

const requireVerifiedWebhook = async (orgId, clientId) => {
  const config = await getConfiguredWebhook(orgId, clientId);
  if (!config.webhookVerified) {
    badRequest(CLIENT_ERRORS.WEBHOOK_NOT_VERIFIED);
  }

  return config;
};

const createDeliveryAttempt = async ({
  orgId,
  clientId,
  event,
  payload,
  idempotencyKey,
  source,
  status,
  result,
  attempt = 1,
  triggeredByUserId = null,
  replayOfDeliveryId = null,
  errorMessage = null,
}) => {
  return createWebhookDelivery({
    orgId,
    clientId,
    event,
    payload: payload || {},
    idempotencyKey,
    source,
    status,
    attempt,
    triggeredByUserId,
    replayOfDeliveryId,
    httpStatus: result?.httpStatus || null,
    responseTimeMs: result?.responseTimeMs || null,
    responseBody: result?.responseBody || null,
    errorMessage,
    deliveredAt: result?.deliveredAt || new Date(),
  });
};

export const listWebhookDeliveriesForUser = async ({
  orgId,
  clientId,
  actorUserId,
  query,
}) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);
  await requireClient(orgId, clientId);

  const [deliveries, total] = await Promise.all([
    listWebhookDeliveriesByClient(orgId, clientId, query),
    countWebhookDeliveriesByClient(orgId, clientId, query),
  ]);

  return {
    deliveries,
    pagination: {
      limit: query.limit,
      offset: query.offset,
      count: deliveries.length,
      total,
    },
  };
};

export const getWebhookDeliveryForUser = async ({
  orgId,
  clientId,
  deliveryId,
  actorUserId,
}) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);
  await requireClient(orgId, clientId);

  const delivery = await findWebhookDeliveryById(orgId, clientId, deliveryId);
  if (!delivery) {
    notFound(CLIENT_ERRORS.WEBHOOK_DELIVERY_NOT_FOUND);
  }

  return delivery;
};

export const replayWebhookDeliveryForUser = async ({
  orgId,
  clientId,
  deliveryId,
  actorUserId,
}) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);
  await requireVerifiedWebhook(orgId, clientId);

  const delivery = await findWebhookDeliveryById(orgId, clientId, deliveryId);
  if (!delivery) {
    notFound(CLIENT_ERRORS.WEBHOOK_DELIVERY_NOT_FOUND);
  }

  if (delivery.status !== "failed") {
    badRequest(CLIENT_ERRORS.WEBHOOK_REPLAY_ONLY_FAILED);
  }

  const queued = await queueServiceWebhookEvent({
    orgId,
    clientId,
    event: delivery.event,
    payload: delivery.payload,
    idempotencySeed: `replay:${delivery.id}:${Date.now()}`,
    source: "replay",
    replayOfDeliveryId: delivery.id,
    triggeredByUserId: actorUserId,
  });

  if (!queued) {
    badRequest(CLIENT_ERRORS.WEBHOOK_NOT_CONFIGURED);
  }

  return {
    message: CLIENT_MESSAGES.WEBHOOK_REPLAY_QUEUED,
    queued: true,
    idempotencyKey: queued.idempotencyKey,
  };
};

export const getWebhookStatusForUser = async ({
  orgId,
  clientId,
  actorUserId,
}) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);
  await requireClient(orgId, clientId);

  const summary = await getWebhookDeliveryStatusSummary(orgId, clientId);

  return {
    ...summary,
    pendingCount: 0,
  };
};

export const testWebhookForUser = async ({
  orgId,
  clientId,
  actorUserId,
  payload,
}) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);
  const config = await getConfiguredWebhook(orgId, clientId);

  const idempotencyKey = createIdempotencyKey({
    orgId,
    clientId,
    event: "webhook.test",
    seed: `${actorUserId}:${Date.now()}`,
  });

  try {
    const result = await dispatchServiceWebhook({
      webhookUrl: config.webhookUrl,
      webhookSecret: config.webhookSecret,
      event: "webhook.test",
      payload: {
        orgId,
        clientId,
        testedAt: new Date().toISOString(),
        requestedByUserId: actorUserId,
        payload: payload || {},
      },
      idempotencyKey,
    });

    await createDeliveryAttempt({
      orgId,
      clientId,
      event: "webhook.test",
      payload: {
        orgId,
        clientId,
        testedAt: new Date().toISOString(),
        requestedByUserId: actorUserId,
        payload: payload || {},
      },
      idempotencyKey,
      source: "test",
      status: "success",
      result,
      triggeredByUserId: actorUserId,
    });

    return {
      success: true,
      idempotencyKey,
      httpStatus: result.httpStatus,
      responseTimeMs: result.responseTimeMs,
      responseBody: result.responseBody,
    };
  } catch (error) {
    const result = error.deliveryResult || {};
    await createDeliveryAttempt({
      orgId,
      clientId,
      event: "webhook.test",
      payload: {
        orgId,
        clientId,
        testedAt: new Date().toISOString(),
        requestedByUserId: actorUserId,
        payload: payload || {},
      },
      idempotencyKey,
      source: "test",
      status: "failed",
      result,
      triggeredByUserId: actorUserId,
      errorMessage: result.errorMessage || error.message,
    });

    return {
      success: false,
      idempotencyKey,
      httpStatus: result.httpStatus || null,
      responseTimeMs: result.responseTimeMs || null,
      responseBody: result.responseBody || null,
      error: result.errorMessage || error.message,
    };
  }
};

export const verifyWebhookOwnershipForUser = async ({
  orgId,
  clientId,
  actorUserId,
}) => {
  await requireOrganization(orgId);
  await requireOrganizationManageRole(orgId, actorUserId);
  const config = await getConfiguredWebhook(orgId, clientId);

  const challenge = crypto.randomBytes(24).toString("base64url");
  const idempotencyKey = createIdempotencyKey({
    orgId,
    clientId,
    event: "webhook.challenge",
    seed: challenge,
  });

  let result;
  try {
    result = await dispatchServiceWebhook({
      webhookUrl: config.webhookUrl,
      webhookSecret: config.webhookSecret,
      event: "webhook.challenge",
      payload: {
        orgId,
        clientId,
        challenge,
        requestedByUserId: actorUserId,
        requestedAt: new Date().toISOString(),
      },
      idempotencyKey,
    });
  } catch (error) {
    const failureResult = error.deliveryResult || {};
    await createDeliveryAttempt({
      orgId,
      clientId,
      event: "webhook.challenge",
      payload: {
        orgId,
        clientId,
        challenge,
        requestedByUserId: actorUserId,
      },
      idempotencyKey,
      source: "verify",
      status: "failed",
      result: failureResult,
      triggeredByUserId: actorUserId,
      errorMessage: failureResult.errorMessage || error.message,
    });

    badRequest(CLIENT_ERRORS.WEBHOOK_CHALLENGE_FAILED);
  }

  const returnedChallenge =
    result.responseData && typeof result.responseData === "object"
      ? result.responseData.challenge
      : null;

  if (returnedChallenge !== challenge) {
    await createDeliveryAttempt({
      orgId,
      clientId,
      event: "webhook.challenge",
      payload: {
        orgId,
        clientId,
        challenge,
        requestedByUserId: actorUserId,
      },
      idempotencyKey,
      source: "verify",
      status: "failed",
      result,
      triggeredByUserId: actorUserId,
      errorMessage: CLIENT_ERRORS.WEBHOOK_CHALLENGE_FAILED,
    });

    badRequest(CLIENT_ERRORS.WEBHOOK_CHALLENGE_FAILED);
  }

  await updateOrganizationClientById(orgId, clientId, {
    webhookVerified: true,
    webhookVerifiedAt: new Date(),
    updatedByUserId: actorUserId,
  });

  await createDeliveryAttempt({
    orgId,
    clientId,
    event: "webhook.challenge",
    payload: {
      orgId,
      clientId,
      challenge,
      requestedByUserId: actorUserId,
    },
    idempotencyKey,
    source: "verify",
    status: "success",
    result,
    triggeredByUserId: actorUserId,
  });

  return {
    verified: true,
    challenge,
    verifiedAt: new Date().toISOString(),
  };
};
