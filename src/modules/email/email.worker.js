import { Worker } from "bullmq";
import { getRedisClient } from "../../core/config/redis.js";
import logger from "../../core/logger/logger.js";
import { deadLetterQueue } from "../../queues/index.js";
import { sendEmail } from "./email.service.js";
import {
  QUEUE_JOB_NAMES,
  QUEUE_NAMES,
} from "../../core/constants/queue.constants.js";

export const startEmailWorker = () => {
  const worker = new Worker(
    QUEUE_NAMES.EMAIL,
    async (job) => {
      await sendEmail(job.data);
      logger.info("Email sent", { jobId: job.id, to: job.data.to });
    },
    { connection: getRedisClient() },
  );

  worker.on("failed", async (job, error) => {
    logger.error("Email job failed", { jobId: job?.id, error: error.message });

    if (job) {
      await deadLetterQueue.add(QUEUE_JOB_NAMES.EMAIL_FAILED, {
        queue: QUEUE_NAMES.EMAIL,
        payload: job.data,
        reason: error.message,
      });
    }
  });

  return worker;
};
