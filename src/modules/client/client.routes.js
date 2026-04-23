import { Router } from "express";
import asyncHandler from "../../utils/async-handler.js";
import { requireAuth } from "../auth/auth.middleware.js";
import {
  addOrganizationClientProviderHandler,
  configureOrganizationClientWebhookHandler,
  createOrganizationClientHandler,
  deleteOrganizationClientHandler,
  deleteOrganizationClientProviderHandler,
  disableOrganizationClientWebhookHandler,
  getOrganizationClientHandler,
  getOrganizationClientWebhookDeliveryHandler,
  getOrganizationClientWebhookStatusHandler,
  listOrganizationClientWebhookDeliveriesHandler,
  listOrganizationClientUsersHandler,
  listOrganizationClientsHandler,
  replayOrganizationClientWebhookDeliveryHandler,
  rotateOrganizationClientSecretHandler,
  rotateOrganizationClientWebhookSecretHandler,
  testOrganizationClientWebhookHandler,
  updateOrganizationClientHandler,
  updateOrganizationClientProviderHandler,
  verifyOrganizationClientWebhookHandler,
} from "./client.controller.js";
import {
  organizationClientMutationLimiter,
  organizationClientProviderMutationLimiter,
} from "../../core/ratelimiters/client.ratelimits.js";

const router = Router({ mergeParams: true });

router.get("/", requireAuth, asyncHandler(listOrganizationClientsHandler));
router.get(
  "/:clientId",
  requireAuth,
  asyncHandler(getOrganizationClientHandler),
);
router.get(
  "/:clientId/users",
  requireAuth,
  asyncHandler(listOrganizationClientUsersHandler),
);

router.post(
  "/",
  requireAuth,
  organizationClientMutationLimiter,
  asyncHandler(createOrganizationClientHandler),
);
router.patch(
  "/:clientId",
  requireAuth,
  organizationClientMutationLimiter,
  asyncHandler(updateOrganizationClientHandler),
);
router.delete(
  "/:clientId",
  requireAuth,
  organizationClientMutationLimiter,
  asyncHandler(deleteOrganizationClientHandler),
);
router.post(
  "/:clientId/secret/rotate",
  requireAuth,
  organizationClientMutationLimiter,
  asyncHandler(rotateOrganizationClientSecretHandler),
);

router.post(
  "/:clientId/providers",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(addOrganizationClientProviderHandler),
);
router.patch(
  "/:clientId/providers/:provider",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(updateOrganizationClientProviderHandler),
);
router.delete(
  "/:clientId/providers/:provider",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(deleteOrganizationClientProviderHandler),
);

router.post(
  "/:clientId/webhook",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(configureOrganizationClientWebhookHandler),
);

router.post(
  "/:clientId/webhook/secret/rotate",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(rotateOrganizationClientWebhookSecretHandler),
);

router.get(
  "/:clientId/webhook/status",
  requireAuth,
  asyncHandler(getOrganizationClientWebhookStatusHandler),
);

router.get(
  "/:clientId/webhook/deliveries",
  requireAuth,
  asyncHandler(listOrganizationClientWebhookDeliveriesHandler),
);

router.get(
  "/:clientId/webhook/deliveries/:deliveryId",
  requireAuth,
  asyncHandler(getOrganizationClientWebhookDeliveryHandler),
);

router.post(
  "/:clientId/webhook/deliveries/:deliveryId/replay",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(replayOrganizationClientWebhookDeliveryHandler),
);

router.post(
  "/:clientId/webhook/test",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(testOrganizationClientWebhookHandler),
);

router.post(
  "/:clientId/webhook/verify",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(verifyOrganizationClientWebhookHandler),
);

router.delete(
  "/:clientId/webhook",
  requireAuth,
  organizationClientProviderMutationLimiter,
  asyncHandler(disableOrganizationClientWebhookHandler),
);

export default router;
