import {
  acceptOrganizationInviteSchema,
  createOrganizationInviteSchema,
  createOrganizationSchema,
  inviteIdParamSchema,
  inviteTokenParamSchema,
  organizationMemberParamSchema,
  organizationIdParamSchema,
  transferOrganizationOwnershipSchema,
  updateOrganizationMemberRoleSchema,
  updateOrganizationSchema,
} from "../../validations/organization/organization.validators.js";
import {
  acceptOrganizationInviteForUser,
  createOrganizationForUser,
  createOrganizationInviteForUser,
  deleteOrganizationForUser,
  getOrganizationForUser,
  getOrganizationInviteByTokenForUser,
  listOrganizationInvitesForUser,
  listOrganizationsForUser,
  revokeOrganizationInviteForUser,
  transferOrganizationOwnershipForUser,
  updateOrganizationMemberRoleForUser,
  updateOrganizationForUser,
} from "./organization.service.js";
import {
  AUDIT_CATEGORY,
  AUDIT_EVENTS,
  AUDIT_STATUS,
} from "../audit/audit.events.js";
import {
  buildAuditContextFromRequest,
  emitAuditEvent,
} from "../audit/audit.service.js";
import { AUDIT_MESSAGES } from "../audit/audit.messages.js";
import { ORGANIZATION_MESSAGES } from "./organization.constants.js";

export const createOrganizationHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const payload = createOrganizationSchema.parse(req.body);

  const result = await createOrganizationForUser(req.auth.sub, payload);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_CREATED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId: result.organization.id,
    message: AUDIT_MESSAGES.ORG_CREATED,
    metadata: {
      role: result.membership.role,
      name: result.organization.name,
    },
  });

  res.status(201).json(result);
};

export const listOrganizationsHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const organizations = await listOrganizationsForUser(req.auth.sub);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_LISTED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    message: AUDIT_MESSAGES.ORG_LISTED,
    metadata: {
      count: organizations.length,
    },
  });

  res.status(200).json({ organizations });
};

export const getOrganizationHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationIdParamSchema.parse(req.params);

  const result = await getOrganizationForUser(orgId, req.auth.sub);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_VIEWED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_VIEWED,
  });

  res.status(200).json(result);
};

export const updateOrganizationHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationIdParamSchema.parse(req.params);
  const payload = updateOrganizationSchema.parse(req.body);

  const organization = await updateOrganizationForUser(
    orgId,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_UPDATED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_UPDATED,
    metadata: {
      updatedFields: Object.keys(payload),
      slug: organization.slug,
    },
  });

  res.status(200).json({ organization });
};

export const deleteOrganizationHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationIdParamSchema.parse(req.params);

  const message = await deleteOrganizationForUser(orgId, req.auth.sub);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_DELETED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_DELETED,
  });

  res.status(200).json({ message });
};

export const createOrganizationInviteHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationIdParamSchema.parse(req.params);
  const payload = createOrganizationInviteSchema.parse(req.body);

  const invite = await createOrganizationInviteForUser(
    orgId,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_INVITE_SENT,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_INVITE_SENT,
    metadata: {
      inviteId: invite.id,
      invitedEmail: invite.invitedEmail,
      role: invite.role,
    },
  });

  res.status(201).json({ message: ORGANIZATION_MESSAGES.INVITE_SENT, invite });
};

export const listOrganizationInvitesHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationIdParamSchema.parse(req.params);

  const invites = await listOrganizationInvitesForUser(orgId, req.auth.sub);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_INVITES_VIEWED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_INVITES_VIEWED,
    metadata: {
      count: invites.length,
    },
  });

  res.status(200).json({ invites });
};

export const getOrganizationInviteByTokenHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { token } = inviteTokenParamSchema.parse(req.params);
  const result = await getOrganizationInviteByTokenForUser(token, req.auth.sub);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_INVITE_VIEWED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId: result.organization.id,
    message: AUDIT_MESSAGES.ORG_INVITE_VIEWED,
    metadata: {
      inviteId: result.invite.id,
    },
  });

  res.status(200).json(result);
};

export const acceptOrganizationInviteHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { token } = acceptOrganizationInviteSchema.parse(req.body);

  const result = await acceptOrganizationInviteForUser(token, req.auth.sub);

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_INVITE_ACCEPTED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId: result.organization.id,
    message: AUDIT_MESSAGES.ORG_INVITE_ACCEPTED,
    metadata: {
      inviteId: result.invite.id,
      role: result.member.role,
    },
  });

  res.status(200).json(result);
};

export const revokeOrganizationInviteHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationIdParamSchema.parse(req.params);
  const { inviteId } = inviteIdParamSchema.parse(req.params);

  const result = await revokeOrganizationInviteForUser(
    orgId,
    inviteId,
    req.auth.sub,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_INVITE_REVOKED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    message: AUDIT_MESSAGES.ORG_INVITE_REVOKED,
    metadata: {
      inviteId,
    },
  });

  res.status(200).json(result);
};

export const updateOrganizationMemberRoleHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId, userId } = organizationMemberParamSchema.parse(req.params);
  const payload = updateOrganizationMemberRoleSchema.parse(req.body);

  const result = await updateOrganizationMemberRoleForUser(
    orgId,
    userId,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_MEMBER_ROLE_UPDATED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    targetUserId: userId,
    message: AUDIT_MESSAGES.ORG_MEMBER_ROLE_UPDATED,
    metadata: {
      role: result.member.role,
    },
  });

  res.status(200).json(result);
};

export const transferOrganizationOwnershipHandler = async (req, res) => {
  const auditContext = buildAuditContextFromRequest(req);
  const { orgId } = organizationIdParamSchema.parse(req.params);
  const payload = transferOrganizationOwnershipSchema.parse(req.body);

  const result = await transferOrganizationOwnershipForUser(
    orgId,
    req.auth.sub,
    payload,
  );

  await emitAuditEvent({
    ...auditContext,
    event: AUDIT_EVENTS.ORG_OWNERSHIP_TRANSFERRED,
    category: AUDIT_CATEGORY.ORGANIZATION,
    status: AUDIT_STATUS.SUCCESS,
    orgId,
    targetUserId: payload.targetUserId,
    message: AUDIT_MESSAGES.ORG_OWNERSHIP_TRANSFERRED,
    metadata: {
      demotedOwnerId: req.auth.sub,
      demotedTo: result.previousOwner.role,
      promotedOwnerId: payload.targetUserId,
    },
  });

  res.status(200).json(result);
};
