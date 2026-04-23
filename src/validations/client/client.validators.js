import { z } from "zod";
import {
  CLIENT_ALLOWED_PROVIDERS,
  CLIENT_AUTHORIZED_ORIGINS_LIMITS,
  CLIENT_WEBHOOK_DELIVERY_LIST_PAGINATION,
  CLIENT_NAME_LIMITS,
  CLIENT_PROVIDER_CREDENTIAL_LIMITS,
  CLIENT_REDIRECT_URIS_LIMITS,
  CLIENT_USER_LIST_PAGINATION,
} from "../../modules/client/client.constants.js";

const providerSchema = z.enum(CLIENT_ALLOWED_PROVIDERS);

export const organizationClientParamSchema = z.object({
  orgId: z.string().uuid(),
  clientId: z.string().uuid(),
});

export const organizationClientProviderParamSchema = z.object({
  orgId: z.string().uuid(),
  clientId: z.string().uuid(),
  provider: providerSchema,
});

export const organizationClientWebhookDeliveryParamSchema = z.object({
  orgId: z.string().uuid(),
  clientId: z.string().uuid(),
  deliveryId: z.string().uuid(),
});

export const createOrganizationClientSchema = z.object({
  name: z
    .string()
    .trim()
    .min(CLIENT_NAME_LIMITS.MIN)
    .max(CLIENT_NAME_LIMITS.MAX),
  redirectUris: z
    .array(z.string().url())
    .min(CLIENT_REDIRECT_URIS_LIMITS.MIN)
    .max(CLIENT_REDIRECT_URIS_LIMITS.MAX),
  authorizedOrigins: z
    .array(z.string().url())
    .max(CLIENT_AUTHORIZED_ORIGINS_LIMITS.MAX)
    .default([]),
});

export const updateOrganizationClientSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(CLIENT_NAME_LIMITS.MIN)
      .max(CLIENT_NAME_LIMITS.MAX)
      .optional(),
    redirectUris: z
      .array(z.string().url())
      .min(CLIENT_REDIRECT_URIS_LIMITS.MIN)
      .max(CLIENT_REDIRECT_URIS_LIMITS.MAX)
      .optional(),
    authorizedOrigins: z
      .array(z.string().url())
      .max(CLIENT_AUTHORIZED_ORIGINS_LIMITS.MAX)
      .optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one field must be provided",
  });

export const createOrganizationClientProviderSchema = z.object({
  provider: providerSchema,
  providerClientId: z
    .string()
    .trim()
    .min(CLIENT_PROVIDER_CREDENTIAL_LIMITS.ID_MIN)
    .max(CLIENT_PROVIDER_CREDENTIAL_LIMITS.ID_MAX),
  providerClientSecret: z
    .string()
    .min(CLIENT_PROVIDER_CREDENTIAL_LIMITS.SECRET_MIN)
    .max(CLIENT_PROVIDER_CREDENTIAL_LIMITS.SECRET_MAX),
});

export const updateOrganizationClientProviderSchema = z
  .object({
    providerClientId: z
      .string()
      .trim()
      .min(CLIENT_PROVIDER_CREDENTIAL_LIMITS.ID_MIN)
      .max(CLIENT_PROVIDER_CREDENTIAL_LIMITS.ID_MAX)
      .optional(),
    providerClientSecret: z
      .string()
      .min(CLIENT_PROVIDER_CREDENTIAL_LIMITS.SECRET_MIN)
      .max(CLIENT_PROVIDER_CREDENTIAL_LIMITS.SECRET_MAX)
      .optional(),
    isActive: z.boolean().optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one field must be provided",
  });

export const configureOrganizationClientWebhookSchema = z.object({
  webhookUrl: z.string().url(),
});

export const rotateOrganizationClientSecretSchema = z.object({}).passthrough();

export const rotateOrganizationClientWebhookSecretSchema = z
  .object({})
  .passthrough();

export const listOrganizationClientWebhookDeliveriesQuerySchema = z.object({
  limit: z.coerce
    .number()
    .int()
    .positive()
    .max(CLIENT_WEBHOOK_DELIVERY_LIST_PAGINATION.MAX_LIMIT)
    .default(CLIENT_WEBHOOK_DELIVERY_LIST_PAGINATION.DEFAULT_LIMIT),
  offset: z.coerce
    .number()
    .int()
    .min(0)
    .default(CLIENT_WEBHOOK_DELIVERY_LIST_PAGINATION.DEFAULT_OFFSET),
  status: z.enum(["success", "failed"]).optional(),
  source: z.enum(["event", "replay", "test", "verify"]).optional(),
  event: z.string().trim().min(1).max(120).optional(),
});

export const replayOrganizationClientWebhookDeliverySchema = z
  .object({})
  .passthrough();

export const testOrganizationClientWebhookSchema = z
  .object({
    payload: z.record(z.string(), z.any()).optional(),
  })
  .passthrough();

export const verifyOrganizationClientWebhookSchema = z.object({}).passthrough();

export const listOrganizationClientUsersQuerySchema = z.object({
  limit: z.coerce
    .number()
    .int()
    .positive()
    .max(CLIENT_USER_LIST_PAGINATION.MAX_LIMIT)
    .default(CLIENT_USER_LIST_PAGINATION.DEFAULT_LIMIT),
  offset: z.coerce
    .number()
    .int()
    .min(0)
    .default(CLIENT_USER_LIST_PAGINATION.DEFAULT_OFFSET),
});
