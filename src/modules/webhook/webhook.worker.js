import { Worker } from "bullmq";
import { getRedisClient } from "../../core/config/redis.js";
import logger from "../../core/logger/logger.js";
import { deadLetterQueue } from "../../queues/index.js";
import {
  QUEUE_JOB_NAMES,
  QUEUE_NAMES,
} from "../../core/constants/queue.constants.js";
import { dispatchServiceWebhook } from "./webhook.service.js";
import { createWebhookDelivery } from "./webhook.repository.js";

export const startServiceWebhookWorker = () => {
  const worker = new Worker(
    QUEUE_NAMES.SERVICE_WEBHOOK,
    async (job) => {
      const attempt = (job.attemptsMade || 0) + 1;

      try {
        const result = await dispatchServiceWebhook(job.data);

        if (job.data.orgId && job.data.clientId) {
          await createWebhookDelivery({
            orgId: job.data.orgId,
            clientId: job.data.clientId,
            event: job.data.event,
            payload: job.data.payload || {},
            idempotencyKey: job.data.idempotencyKey,
            source: job.data.source || "event",
            status: "success",
            attempt,
            triggeredByUserId: job.data.triggeredByUserId || null,
            replayOfDeliveryId: job.data.replayOfDeliveryId || null,
            httpStatus: result.httpStatus,
            responseTimeMs: result.responseTimeMs,
            responseBody: result.responseBody,
            errorMessage: null,
            deliveredAt: result.deliveredAt,
          });
        }
      } catch (error) {
        const result = error.deliveryResult || {};

        if (job.data.orgId && job.data.clientId) {
          await createWebhookDelivery({
            orgId: job.data.orgId,
            clientId: job.data.clientId,
            event: job.data.event,
            payload: job.data.payload || {},
            idempotencyKey: job.data.idempotencyKey,
            source: job.data.source || "event",
            status: "failed",
            attempt,
            triggeredByUserId: job.data.triggeredByUserId || null,
            replayOfDeliveryId: job.data.replayOfDeliveryId || null,
            httpStatus: result.httpStatus || null,
            responseTimeMs: result.responseTimeMs || null,
            responseBody: result.responseBody || null,
            errorMessage: result.errorMessage || error.message,
            deliveredAt: result.deliveredAt || new Date(),
          });
        }

        throw error;
      }

      logger.info("Service webhook delivered", {
        jobId: job.id,
        event: job.data.event,
        webhookUrl: job.data.webhookUrl,
      });
    },
    { connection: getRedisClient() },
  );

  worker.on("failed", async (job, error) => {
    logger.error("Service webhook delivery failed", {
      jobId: job?.id,
      error: error.message,
    });

    const maxAttempts = Number(job?.opts?.attempts || 1);
    const isFinalFailure = Boolean(job && job.attemptsMade >= maxAttempts);

    if (job && isFinalFailure) {
      await deadLetterQueue.add(QUEUE_JOB_NAMES.SERVICE_WEBHOOK_FAILED, {
        queue: QUEUE_NAMES.SERVICE_WEBHOOK,
        payload: job.data,
        reason: error.message,
      });
    }
  });

  return worker;
};
