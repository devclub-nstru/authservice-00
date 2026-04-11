import crypto from "node:crypto";
import db from "../../db/client/db.js";
import env from "../../core/config/config.js";
import {
  badRequest,
  conflict,
  forbidden,
  notFound,
  unauthorized,
} from "../../utils/errors.js";
import { queueEmailJob } from "../email/email.queue.js";
import { EMAIL_SUBJECTS } from "../email/email.constants.js";
import { organizationInviteTemplate } from "../email/email.templates.js";
import {
  countOrganizationOwners,
  createOrganization,
  createOrganizationInvite,
  createOrganizationMember,
  deleteOrganizationById,
  findActiveInviteByOrgAndEmail,
  findOrganizationById,
  findOrganizationByNormalizedName,
  findOrganizationBySlug,
  findOrganizationInviteById,
  findOrganizationMember,
  findUserByEmail,
  findUserById,
  findValidOrganizationInviteByToken,
  listOrganizationInvites,
  listOrganizationMembers,
  listOrganizationsByUserId,
  markOrganizationInviteUsed,
  revokeOrganizationInvite,
  updateOrganizationMemberRole,
  updateOrganizationById,
} from "./organization.repository.js";
import {
  ORGANIZATION_ERRORS,
  ORGANIZATION_INVITE_TTL_MS,
  ORGANIZATION_MESSAGES,
  ORGANIZATION_ROLES,
  ORGANIZATION_ROUTE_PATHS,
  ORGANIZATION_TOKEN_BYTES,
} from "./organization.constants.js";

const normalizeName = (name) => name.trim().replace(/\s+/g, " ");

const normalizeForUniqueness = (value) => value.trim().toLowerCase();

const slugifyBase = (value) =>
  value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 255);

const generateInviteToken = () =>
  crypto.randomBytes(ORGANIZATION_TOKEN_BYTES).toString("hex");

const buildInviteUrl = (token) =>
  `${env.FRONTEND_URL}${ORGANIZATION_ROUTE_PATHS.FRONTEND_INVITE_ACCEPT}?token=${token}`;

const requireOrgMembership = async (orgId, userId, tx = db) => {
  const membership = await findOrganizationMember(orgId, userId, tx);
  if (!membership) {
    forbidden(ORGANIZATION_ERRORS.MEMBERSHIP_REQUIRED);
  }

  return membership;
};

const requireOrgRoles = async (orgId, userId, roles, tx = db) => {
  const membership = await requireOrgMembership(orgId, userId, tx);
  if (!roles.includes(membership.role)) {
    forbidden(ORGANIZATION_ERRORS.INSUFFICIENT_PERMISSIONS);
  }

  return membership;
};

const ensureUniqueOrganizationName = async (
  name,
  existingOrgId = null,
  tx = db,
) => {
  const normalized = normalizeForUniqueness(name);
  const existing = await findOrganizationByNormalizedName(normalized, tx);

  if (existing && existing.id !== existingOrgId) {
    conflict(ORGANIZATION_ERRORS.NAME_ALREADY_EXISTS);
  }
};

const generateUniqueSlug = async (name, excludeOrgId = null, tx = db) => {
  const baseSlug = slugifyBase(name) || "organization";
  let candidate = baseSlug;
  let counter = 2;

  // Keep slugs deterministic and collision-safe while remaining human-readable.
  while (true) {
    const existing = await findOrganizationBySlug(candidate, tx);
    if (!existing || existing.id === excludeOrgId) {
      return candidate;
    }

    candidate = `${baseSlug}-${counter}`;
    counter += 1;
  }
};

const sanitizeOrganization = (organization) => ({
  id: organization.id,
  name: organization.name,
  slug: organization.slug,
  createdAt: organization.createdAt,
  updatedAt: organization.updatedAt,
});

const sanitizeInvite = (invite) => ({
  id: invite.id,
  orgId: invite.orgId,
  invitedEmail: invite.invitedEmail,
  role: invite.role,
  invitedByUserId: invite.invitedByUserId,
  acceptedByUserId: invite.acceptedByUserId,
  expiresAt: invite.expiresAt,
  createdAt: invite.createdAt,
  usedAt: invite.usedAt,
  revokedAt: invite.revokedAt,
});

export const createOrganizationForUser = async (actorUserId, payload) => {
  const normalizedName = normalizeName(payload.name);

  const result = await db.transaction(async (tx) => {
    await ensureUniqueOrganizationName(normalizedName, null, tx);
    const slug = await generateUniqueSlug(normalizedName, null, tx);

    const organization = await createOrganization(
      {
        name: normalizedName,
        slug,
      },
      tx,
    );

    const membership = await createOrganizationMember(
      {
        orgId: organization.id,
        userId: actorUserId,
        role: ORGANIZATION_ROLES.OWNER,
      },
      tx,
    );

    return { organization, membership };
  });

  return {
    organization: sanitizeOrganization(result.organization),
    membership: result.membership,
  };
};

export const listOrganizationsForUser = async (actorUserId) => {
  return listOrganizationsByUserId(actorUserId);
};

export const getOrganizationForUser = async (orgId, actorUserId) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  await requireOrgMembership(orgId, actorUserId);
  const members = await listOrganizationMembers(orgId);

  return {
    organization: sanitizeOrganization(organization),
    members,
  };
};

export const updateOrganizationForUser = async (
  orgId,
  actorUserId,
  payload,
) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  await requireOrgRoles(orgId, actorUserId, [
    ORGANIZATION_ROLES.OWNER,
    ORGANIZATION_ROLES.ADMIN,
  ]);

  const updated = await db.transaction(async (tx) => {
    const updates = {};

    if (payload.name) {
      const normalizedName = normalizeName(payload.name);
      await ensureUniqueOrganizationName(normalizedName, orgId, tx);
      const slug = await generateUniqueSlug(normalizedName, orgId, tx);

      updates.name = normalizedName;
      updates.slug = slug;
    }

    return updateOrganizationById(orgId, updates, tx);
  });

  if (!updated) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  return sanitizeOrganization(updated);
};

export const deleteOrganizationForUser = async (orgId, actorUserId) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  await requireOrgRoles(orgId, actorUserId, [ORGANIZATION_ROLES.OWNER]);

  const deleted = await deleteOrganizationById(orgId);
  if (!deleted) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  return ORGANIZATION_MESSAGES.ORGANIZATION_DELETED;
};

export const createOrganizationInviteForUser = async (
  orgId,
  actorUserId,
  payload,
) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  await requireOrgRoles(orgId, actorUserId, [
    ORGANIZATION_ROLES.OWNER,
    ORGANIZATION_ROLES.ADMIN,
  ]);

  const invitedEmail = payload.email.trim().toLowerCase();
  const activeInvite = await findActiveInviteByOrgAndEmail(orgId, invitedEmail);
  if (activeInvite) {
    conflict(ORGANIZATION_ERRORS.INVITE_ALREADY_EXISTS);
  }

  const existingUser = await findUserByEmail(invitedEmail);
  if (existingUser) {
    const existingMembership = await findOrganizationMember(
      orgId,
      existingUser.id,
    );
    if (existingMembership) {
      conflict(ORGANIZATION_ERRORS.ALREADY_COLLABORATOR);
    }
  }

  const token = generateInviteToken();
  const expiresAt = new Date(Date.now() + ORGANIZATION_INVITE_TTL_MS);

  const invite = await createOrganizationInvite({
    orgId,
    invitedEmail,
    token,
    role: payload.role,
    invitedByUserId: actorUserId,
    expiresAt,
  });

  await queueEmailJob({
    to: invitedEmail,
    subject: EMAIL_SUBJECTS.ORGANIZATION_INVITE,
    html: organizationInviteTemplate({
      organizationName: organization.name,
      inviteUrl: buildInviteUrl(token),
      expiresAt: expiresAt.toISOString(),
    }),
  });

  return sanitizeInvite(invite);
};

export const listOrganizationInvitesForUser = async (orgId, actorUserId) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  await requireOrgRoles(orgId, actorUserId, [
    ORGANIZATION_ROLES.OWNER,
    ORGANIZATION_ROLES.ADMIN,
  ]);

  const invites = await listOrganizationInvites(orgId);
  return invites.map(sanitizeInvite);
};

export const getOrganizationInviteByTokenForUser = async (
  token,
  actorUserId,
) => {
  const invite = await findValidOrganizationInviteByToken(token);
  if (!invite) {
    unauthorized(ORGANIZATION_ERRORS.INVITE_INVALID);
  }

  const actorUser = await findUserById(actorUserId);
  if (!actorUser) {
    unauthorized(ORGANIZATION_ERRORS.INVITE_INVALID);
  }

  const emailMatches =
    normalizeForUniqueness(invite.invitedEmail) ===
    normalizeForUniqueness(actorUser.email);
  if (!emailMatches) {
    unauthorized(ORGANIZATION_ERRORS.INVITE_EMAIL_MISMATCH);
  }

  const organization = await findOrganizationById(invite.orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  return {
    invite: sanitizeInvite(invite),
    organization: sanitizeOrganization(organization),
  };
};

export const acceptOrganizationInviteForUser = async (token, actorUserId) => {
  return db.transaction(async (tx) => {
    const invite = await findValidOrganizationInviteByToken(token, tx);
    if (!invite) {
      unauthorized(ORGANIZATION_ERRORS.INVITE_INVALID);
    }

    const actorUser = await findUserById(actorUserId, tx);
    if (!actorUser) {
      unauthorized(ORGANIZATION_ERRORS.INVITE_INVALID);
    }

    const emailMatches =
      normalizeForUniqueness(invite.invitedEmail) ===
      normalizeForUniqueness(actorUser.email);

    if (!emailMatches) {
      unauthorized(ORGANIZATION_ERRORS.INVITE_EMAIL_MISMATCH);
    }

    const existingMembership = await findOrganizationMember(
      invite.orgId,
      actorUser.id,
      tx,
    );

    if (existingMembership) {
      conflict(ORGANIZATION_ERRORS.ALREADY_COLLABORATOR);
    }

    const member = await createOrganizationMember(
      {
        orgId: invite.orgId,
        userId: actorUser.id,
        role: invite.role,
        invitedByUserId: invite.invitedByUserId,
      },
      tx,
    );

    const consumedInvite = await markOrganizationInviteUsed(
      invite.id,
      actorUser.id,
      tx,
    );

    const organization = await findOrganizationById(invite.orgId, tx);

    return {
      member,
      invite: sanitizeInvite(consumedInvite),
      organization: sanitizeOrganization(organization),
      message: ORGANIZATION_MESSAGES.INVITE_ACCEPTED,
    };
  });
};

export const revokeOrganizationInviteForUser = async (
  orgId,
  inviteId,
  actorUserId,
) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  await requireOrgRoles(orgId, actorUserId, [
    ORGANIZATION_ROLES.OWNER,
    ORGANIZATION_ROLES.ADMIN,
  ]);

  const invite = await findOrganizationInviteById(inviteId);
  if (!invite || invite.orgId !== orgId) {
    notFound(ORGANIZATION_ERRORS.INVITE_NOT_FOUND);
  }

  if (invite.usedAt) {
    conflict(ORGANIZATION_ERRORS.INVITE_ALREADY_USED);
  }

  if (invite.revokedAt) {
    conflict(ORGANIZATION_ERRORS.INVITE_ALREADY_REVOKED);
  }

  const revoked = await revokeOrganizationInvite(invite.id);

  return {
    invite: sanitizeInvite(revoked),
    message: ORGANIZATION_MESSAGES.INVITE_REVOKED,
  };
};

export const updateOrganizationMemberRoleForUser = async (
  orgId,
  targetUserId,
  actorUserId,
  payload,
) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  await requireOrgRoles(orgId, actorUserId, [ORGANIZATION_ROLES.OWNER]);

  const targetMembership = await findOrganizationMember(orgId, targetUserId);
  if (!targetMembership) {
    notFound(ORGANIZATION_ERRORS.MEMBER_NOT_FOUND);
  }

  if (targetMembership.userId === actorUserId) {
    badRequest(ORGANIZATION_ERRORS.OWNER_SELF_ROLE_CHANGE_NOT_ALLOWED);
  }

  if (payload.role === ORGANIZATION_ROLES.OWNER) {
    badRequest(ORGANIZATION_ERRORS.OWNER_TRANSFER_REQUIRED);
  }

  if (
    targetMembership.role === ORGANIZATION_ROLES.OWNER &&
    payload.role !== ORGANIZATION_ROLES.OWNER
  ) {
    const ownerCount = await countOrganizationOwners(orgId);
    if (ownerCount <= 1) {
      conflict(ORGANIZATION_ERRORS.LAST_OWNER_ROLE_CHANGE_NOT_ALLOWED);
    }
  }

  const updatedMembership = await updateOrganizationMemberRole(
    orgId,
    targetUserId,
    payload.role,
  );

  if (!updatedMembership) {
    notFound(ORGANIZATION_ERRORS.MEMBER_NOT_FOUND);
  }

  return {
    member: updatedMembership,
    message: ORGANIZATION_MESSAGES.MEMBER_ROLE_UPDATED,
  };
};

export const transferOrganizationOwnershipForUser = async (
  orgId,
  actorUserId,
  payload,
) => {
  const organization = await findOrganizationById(orgId);
  if (!organization) {
    notFound(ORGANIZATION_ERRORS.ORGANIZATION_NOT_FOUND);
  }

  if (payload.targetUserId === actorUserId) {
    badRequest(ORGANIZATION_ERRORS.TRANSFER_TARGET_SAME_AS_ACTOR);
  }

  return db.transaction(async (tx) => {
    const actorMembership = await requireOrgRoles(
      orgId,
      actorUserId,
      [ORGANIZATION_ROLES.OWNER],
      tx,
    );

    const targetMembership = await findOrganizationMember(
      orgId,
      payload.targetUserId,
      tx,
    );

    if (!targetMembership) {
      notFound(ORGANIZATION_ERRORS.MEMBER_NOT_FOUND);
    }

    if (targetMembership.role === ORGANIZATION_ROLES.OWNER) {
      conflict(ORGANIZATION_ERRORS.TRANSFER_TARGET_ALREADY_OWNER);
    }

    const promotedMembership = await updateOrganizationMemberRole(
      orgId,
      payload.targetUserId,
      ORGANIZATION_ROLES.OWNER,
      tx,
    );

    const demotedMembership = await updateOrganizationMemberRole(
      orgId,
      actorUserId,
      payload.previousOwnerRole,
      tx,
    );

    return {
      organization: sanitizeOrganization(organization),
      previousOwner: demotedMembership,
      newOwner: promotedMembership,
      message: ORGANIZATION_MESSAGES.OWNERSHIP_TRANSFERRED,
      previousOwnerRole: actorMembership.role,
    };
  });
};
