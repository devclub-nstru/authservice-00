import crypto from "node:crypto";
import axios from "axios";

const WEBHOOK_TIMEOUT_MS = 5000;
const WEBHOOK_RESPONSE_BODY_MAX_CHARS = 4000;

const signWebhookPayload = ({ secret, timestamp, body }) => {
  return crypto
    .createHmac("sha256", secret)
    .update(`${timestamp}.${body}`)
    .digest("hex");
};

const serializeResponseBody = (value) => {
  if (value === null || typeof value === "undefined") {
    return null;
  }

  let serialized;
  if (typeof value === "string") {
    serialized = value;
  } else {
    try {
      serialized = JSON.stringify(value);
    } catch {
      serialized = String(value);
    }
  }

  if (serialized.length <= WEBHOOK_RESPONSE_BODY_MAX_CHARS) {
    return serialized;
  }

  return `${serialized.slice(0, WEBHOOK_RESPONSE_BODY_MAX_CHARS)}...`;
};

export const dispatchServiceWebhook = async ({
  webhookUrl,
  webhookSecret,
  event,
  payload,
  idempotencyKey,
  occurredAt,
}) => {
  const timestamp = Date.now().toString();
  const startedAt = Date.now();
  const body = JSON.stringify({
    event,
    occurredAt: occurredAt || new Date().toISOString(),
    payload,
  });

  const signature = signWebhookPayload({
    secret: webhookSecret,
    timestamp,
    body,
  });

  try {
    const response = await axios.post(webhookUrl, JSON.parse(body), {
      timeout: WEBHOOK_TIMEOUT_MS,
      validateStatus: () => true,
      headers: {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Idempotency-Key": idempotencyKey,
      },
    });

    const deliveryResult = {
      httpStatus: response.status,
      responseBody: serializeResponseBody(response.data),
      responseData: response.data,
      responseTimeMs: Date.now() - startedAt,
      deliveredAt: new Date(),
    };

    if (response.status < 200 || response.status >= 300) {
      const error = new Error(
        `Webhook endpoint returned non-success status ${response.status}`,
      );
      error.deliveryResult = deliveryResult;
      throw error;
    }

    return deliveryResult;
  } catch (error) {
    if (error.deliveryResult) {
      throw error;
    }

    const response = axios.isAxiosError(error) ? error.response : null;
    error.deliveryResult = {
      httpStatus: response?.status || null,
      responseBody: serializeResponseBody(response?.data),
      responseData: response?.data,
      responseTimeMs: Date.now() - startedAt,
      deliveredAt: new Date(),
      errorMessage: error.message,
    };

    throw error;
  }
};
