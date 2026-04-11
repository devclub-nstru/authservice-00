import { MINUTE_MS } from "./time.constants.js";

export const QUEUE_NAMES = {
  EMAIL: "emailQueue",
  DEVICE_ALERT: "deviceAlertQueue",
  CLEANUP: "cleanupQueue",
  DEAD_LETTER: "deadLetterQueue",
};

export const QUEUE_JOB_NAMES = {
  SEND_EMAIL: "send-email",
  NEW_DEVICE_ALERT: "new-device-alert",
  CLEANUP_EXPIRED_RECORDS: "cleanup-expired-records",
  CLEANUP_FAILED: "cleanup-failed",
  DEVICE_ALERT_FAILED: "device-alert-failed",
  EMAIL_FAILED: "email-failed",
};

export const QUEUE_DEFAULT_OPTIONS = {
  attempts: 3,
  backoff: {
    type: "exponential",
    delay: 1000,
  },
  removeOnComplete: true,
  removeOnFail: false,
};

export const EMAIL_JOB_OPTIONS = {
  attempts: 5,
  backoff: {
    type: "exponential",
    delay: 1500,
  },
};

export const CLEANUP_SCHEDULE = {
  intervalMs: 15 * MINUTE_MS,
  jobId: QUEUE_JOB_NAMES.CLEANUP_EXPIRED_RECORDS,
};
