import { Router } from "express";
import asyncHandler from "../../utils/async-handler.js";
import { requireAuth } from "../auth/auth.middleware.js";
import {
  createOrganizationHandler,
  createOrganizationInviteHandler,
  deleteOrganizationHandler,
  getOrganizationHandler,
  getOrganizationInviteByTokenHandler,
  listOrganizationInvitesHandler,
  listOrganizationsHandler,
  acceptOrganizationInviteHandler,
  revokeOrganizationInviteHandler,
  transferOrganizationOwnershipHandler,
  updateOrganizationMemberRoleHandler,
  updateOrganizationHandler,
} from "./organization.controller.js";
import {
  organizationInviteAcceptLimiter,
  organizationInviteSendLimiter,
  organizationMutationLimiter,
} from "../../core/ratelimiters/organization.ratelimits.js";

const router = Router();

router.get(
  "/invites/:token",
  requireAuth,
  organizationInviteAcceptLimiter,
  asyncHandler(getOrganizationInviteByTokenHandler),
);
router.post(
  "/invites/accept",
  requireAuth,
  organizationInviteAcceptLimiter,
  asyncHandler(acceptOrganizationInviteHandler),
);

router.post(
  "/",
  requireAuth,
  organizationMutationLimiter,
  asyncHandler(createOrganizationHandler),
);
router.get("/", requireAuth, asyncHandler(listOrganizationsHandler));
router.get("/:orgId", requireAuth, asyncHandler(getOrganizationHandler));
router.patch(
  "/:orgId",
  requireAuth,
  organizationMutationLimiter,
  asyncHandler(updateOrganizationHandler),
);
router.delete(
  "/:orgId",
  requireAuth,
  organizationMutationLimiter,
  asyncHandler(deleteOrganizationHandler),
);
router.patch(
  "/:orgId/members/:userId/role",
  requireAuth,
  organizationMutationLimiter,
  asyncHandler(updateOrganizationMemberRoleHandler),
);
router.post(
  "/:orgId/transfer-ownership",
  requireAuth,
  organizationMutationLimiter,
  asyncHandler(transferOrganizationOwnershipHandler),
);

router.post(
  "/:orgId/invites",
  requireAuth,
  organizationInviteSendLimiter,
  asyncHandler(createOrganizationInviteHandler),
);
router.get(
  "/:orgId/invites",
  requireAuth,
  asyncHandler(listOrganizationInvitesHandler),
);
router.delete(
  "/:orgId/invites/:inviteId",
  requireAuth,
  organizationMutationLimiter,
  asyncHandler(revokeOrganizationInviteHandler),
);

export default router;
