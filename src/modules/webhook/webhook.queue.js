import crypto from "node:crypto";
import { serviceWebhookQueue } from "../../queues/index.js";
import { QUEUE_JOB_NAMES } from "../../core/constants/queue.constants.js";
import { getOrganizationClientWebhookConfigForDispatch } from "../client/client.service.js";

const createWebhookIdempotencyKey = ({ orgId, clientId, event, seed }) => {
  return crypto
    .createHash("sha256")
    .update(`${orgId}:${clientId}:${event}:${seed}`)
    .digest("hex");
};

export const queueServiceWebhookEvent = async ({
  orgId,
  clientId,
  event,
  payload,
  idempotencySeed,
  source = "event",
  replayOfDeliveryId = null,
  triggeredByUserId = null,
  occurredAt,
}) => {
  const webhookConfig = await getOrganizationClientWebhookConfigForDispatch(
    orgId,
    clientId,
  );

  if (!webhookConfig) {
    return null;
  }

  const idempotencyKey = createWebhookIdempotencyKey({
    orgId,
    clientId,
    event,
    seed: idempotencySeed || crypto.randomUUID(),
  });

  await serviceWebhookQueue.add(QUEUE_JOB_NAMES.SEND_SERVICE_WEBHOOK, {
    orgId,
    clientId,
    webhookUrl: webhookConfig.webhookUrl,
    webhookSecret: webhookConfig.webhookSecret,
    event,
    payload,
    idempotencyKey,
    source,
    replayOfDeliveryId,
    triggeredByUserId,
    occurredAt: occurredAt || new Date().toISOString(),
  });

  return { idempotencyKey };
};

export const queueServiceLogoutWebhook = async ({
  orgId,
  clientId,
  userId,
  sessionId,
  clientContext,
}) => {
  const queued = await queueServiceWebhookEvent({
    orgId,
    clientId,
    event: "session.logout",
    payload: {
      orgId,
      clientId,
      userId,
      sessionId,
      clientContext: clientContext || null,
    },
    idempotencySeed: sessionId,
    source: "event",
  });

  return Boolean(queued);
};
