import { Queue } from "bullmq";
import { getRedisClient } from "../core/config/redis.js";
import {
  QUEUE_DEFAULT_OPTIONS,
  QUEUE_NAMES,
} from "../core/constants/queue.constants.js";

const connection = getRedisClient();

export const emailQueue = new Queue(QUEUE_NAMES.EMAIL, {
  connection,
  defaultJobOptions: QUEUE_DEFAULT_OPTIONS,
});

export const deviceAlertQueue = new Queue(QUEUE_NAMES.DEVICE_ALERT, {
  connection,
  defaultJobOptions: QUEUE_DEFAULT_OPTIONS,
});

export const cleanupQueue = new Queue(QUEUE_NAMES.CLEANUP, {
  connection,
  defaultJobOptions: QUEUE_DEFAULT_OPTIONS,
});

export const deadLetterQueue = new Queue(QUEUE_NAMES.DEAD_LETTER, {
  connection,
  defaultJobOptions: QUEUE_DEFAULT_OPTIONS,
});
