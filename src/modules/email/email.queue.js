import { emailQueue } from "../../queues/index.js";
import {
  EMAIL_JOB_OPTIONS,
  QUEUE_JOB_NAMES,
} from "../../core/constants/queue.constants.js";

export const queueEmailJob = async ({ to, subject, html }) => {
  return emailQueue.add(
    QUEUE_JOB_NAMES.SEND_EMAIL,
    { to, subject, html },
    EMAIL_JOB_OPTIONS,
  );
};
