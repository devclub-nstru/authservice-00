import { Worker } from "bullmq";
import db from "../db/client/db.js";
import {
  emailVerificationTokens,
  passwordResetTokens,
  sessions,
} from "../db/schemas/index.js";
import { lte } from "drizzle-orm";
import { getRedisClient } from "../core/config/redis.js";
import logger from "../core/logger/logger.js";
import {
  closeRedisConnection,
  ensureRedisConnection,
} from "../core/config/redis.js";
import { startEmailWorker } from "../modules/email/email.worker.js";
import { deadLetterQueue } from "../queues/index.js";
import {
  QUEUE_JOB_NAMES,
  QUEUE_NAMES,
} from "../core/constants/queue.constants.js";

const cleanupWorker = new Worker(
  QUEUE_NAMES.CLEANUP,
  async () => {
    const now = new Date();
    await Promise.all([
      db.delete(sessions).where(lte(sessions.expiresAt, now)),
      db
        .delete(emailVerificationTokens)
        .where(lte(emailVerificationTokens.expiresAt, now)),
      db
        .delete(passwordResetTokens)
        .where(lte(passwordResetTokens.expiresAt, now)),
    ]);

    logger.info("Cleanup job finished");
  },
  { connection: getRedisClient() },
);

cleanupWorker.on("failed", async (job, error) => {
  logger.error("Cleanup job failed", { jobId: job?.id, error: error.message });

  if (job) {
    await deadLetterQueue.add(QUEUE_JOB_NAMES.CLEANUP_FAILED, {
      queue: QUEUE_NAMES.CLEANUP,
      payload: job.data,
      reason: error.message,
    });
  }
});

const deviceAlertWorker = new Worker(
  QUEUE_NAMES.DEVICE_ALERT,
  async (job) => {
    logger.info("Processed device alert job", {
      userId: job.data.userId,
      email: job.data.email,
    });
  },
  { connection: getRedisClient() },
);

deviceAlertWorker.on("failed", async (job, error) => {
  logger.error("Device alert job failed", {
    jobId: job?.id,
    error: error.message,
  });

  if (job) {
    await deadLetterQueue.add(QUEUE_JOB_NAMES.DEVICE_ALERT_FAILED, {
      queue: QUEUE_NAMES.DEVICE_ALERT,
      payload: job.data,
      reason: error.message,
    });
  }
});

const emailWorker = startEmailWorker();

const shutdown = async () => {
  logger.info("Shutting down workers");
  await Promise.all([
    cleanupWorker.close(),
    deviceAlertWorker.close(),
    emailWorker.close(),
  ]);
  await closeRedisConnection();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

const bootstrap = async () => {
  await ensureRedisConnection();
  logger.info("Worker process started");
};

bootstrap().catch(async (error) => {
  logger.error("Worker bootstrap failed", { error: error.message });
  await closeRedisConnection();
  process.exit(1);
});
