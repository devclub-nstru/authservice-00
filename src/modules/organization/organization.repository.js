import { and, asc, desc, eq, gt, isNull, sql } from "drizzle-orm";
import db from "../../db/client/db.js";
import {
  organizationInvites,
  organizationMembers,
  organizations,
  users,
} from "../../db/schemas/index.js";
import { ORGANIZATION_ROLES } from "./organization.constants.js";

export const createOrganization = async (payload, tx = db) => {
  const [created] = await tx.insert(organizations).values(payload).returning();
  return created;
};

export const findOrganizationById = async (orgId, tx = db) => {
  const [organization] = await tx
    .select()
    .from(organizations)
    .where(eq(organizations.id, orgId))
    .limit(1);

  return organization || null;
};

export const findOrganizationBySlug = async (slug, tx = db) => {
  const [organization] = await tx
    .select()
    .from(organizations)
    .where(eq(organizations.slug, slug))
    .limit(1);

  return organization || null;
};

export const findOrganizationByNormalizedName = async (
  normalizedName,
  tx = db,
) => {
  const [organization] = await tx
    .select()
    .from(organizations)
    .where(sql`lower(${organizations.name}) = ${normalizedName}`)
    .limit(1);

  return organization || null;
};

export const updateOrganizationById = async (orgId, payload, tx = db) => {
  const [updated] = await tx
    .update(organizations)
    .set({ ...payload, updatedAt: new Date() })
    .where(eq(organizations.id, orgId))
    .returning();

  return updated || null;
};

export const deleteOrganizationById = async (orgId, tx = db) => {
  const [deleted] = await tx
    .delete(organizations)
    .where(eq(organizations.id, orgId))
    .returning();

  return deleted || null;
};

export const createOrganizationMember = async (payload, tx = db) => {
  const [member] = await tx
    .insert(organizationMembers)
    .values(payload)
    .returning();

  return member;
};

export const findOrganizationMember = async (orgId, userId, tx = db) => {
  const [member] = await tx
    .select()
    .from(organizationMembers)
    .where(
      and(
        eq(organizationMembers.orgId, orgId),
        eq(organizationMembers.userId, userId),
      ),
    )
    .limit(1);

  return member || null;
};

export const updateOrganizationMemberRole = async (
  orgId,
  userId,
  role,
  tx = db,
) => {
  const [updated] = await tx
    .update(organizationMembers)
    .set({ role, updatedAt: new Date() })
    .where(
      and(
        eq(organizationMembers.orgId, orgId),
        eq(organizationMembers.userId, userId),
      ),
    )
    .returning();

  return updated || null;
};

export const countOrganizationOwners = async (orgId, tx = db) => {
  const [result] = await tx
    .select({ count: sql`count(*)::int` })
    .from(organizationMembers)
    .where(
      and(
        eq(organizationMembers.orgId, orgId),
        eq(organizationMembers.role, ORGANIZATION_ROLES.OWNER),
      ),
    );

  return Number(result?.count || 0);
};

export const listOrganizationMembers = async (orgId, tx = db) => {
  return tx
    .select({
      id: organizationMembers.id,
      orgId: organizationMembers.orgId,
      userId: organizationMembers.userId,
      role: organizationMembers.role,
      invitedByUserId: organizationMembers.invitedByUserId,
      createdAt: organizationMembers.createdAt,
      updatedAt: organizationMembers.updatedAt,
      email: users.email,
      name: users.name,
      avatarUrl: users.avatarUrl,
    })
    .from(organizationMembers)
    .innerJoin(users, eq(users.id, organizationMembers.userId))
    .where(eq(organizationMembers.orgId, orgId))
    .orderBy(asc(users.email));
};

export const listOrganizationsByUserId = async (userId, tx = db) => {
  return tx
    .select({
      id: organizations.id,
      name: organizations.name,
      slug: organizations.slug,
      createdAt: organizations.createdAt,
      updatedAt: organizations.updatedAt,
      role: organizationMembers.role,
      membershipCreatedAt: organizationMembers.createdAt,
    })
    .from(organizationMembers)
    .innerJoin(organizations, eq(organizations.id, organizationMembers.orgId))
    .where(eq(organizationMembers.userId, userId))
    .orderBy(desc(organizationMembers.createdAt));
};

export const findUserByEmail = async (email, tx = db) => {
  const [user] = await tx
    .select()
    .from(users)
    .where(sql`lower(${users.email}) = lower(${email})`)
    .limit(1);

  return user || null;
};

export const findUserById = async (userId, tx = db) => {
  const [user] = await tx
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1);

  return user || null;
};

export const createOrganizationInvite = async (payload, tx = db) => {
  const [invite] = await tx
    .insert(organizationInvites)
    .values(payload)
    .returning();

  return invite;
};

export const findActiveInviteByOrgAndEmail = async (orgId, email, tx = db) => {
  const [invite] = await tx
    .select()
    .from(organizationInvites)
    .where(
      and(
        eq(organizationInvites.orgId, orgId),
        sql`lower(${organizationInvites.invitedEmail}) = lower(${email})`,
        gt(organizationInvites.expiresAt, new Date()),
        isNull(organizationInvites.usedAt),
        isNull(organizationInvites.revokedAt),
      ),
    )
    .orderBy(desc(organizationInvites.createdAt))
    .limit(1);

  return invite || null;
};

export const findValidOrganizationInviteByToken = async (token, tx = db) => {
  const [invite] = await tx
    .select()
    .from(organizationInvites)
    .where(
      and(
        eq(organizationInvites.token, token),
        gt(organizationInvites.expiresAt, new Date()),
        isNull(organizationInvites.usedAt),
        isNull(organizationInvites.revokedAt),
      ),
    )
    .limit(1);

  return invite || null;
};

export const findOrganizationInviteById = async (inviteId, tx = db) => {
  const [invite] = await tx
    .select()
    .from(organizationInvites)
    .where(eq(organizationInvites.id, inviteId))
    .limit(1);

  return invite || null;
};

export const listOrganizationInvites = async (orgId, tx = db) => {
  return tx
    .select()
    .from(organizationInvites)
    .where(eq(organizationInvites.orgId, orgId))
    .orderBy(desc(organizationInvites.createdAt));
};

export const markOrganizationInviteUsed = async (
  inviteId,
  acceptedByUserId,
  tx = db,
) => {
  const [invite] = await tx
    .update(organizationInvites)
    .set({ usedAt: new Date(), acceptedByUserId })
    .where(eq(organizationInvites.id, inviteId))
    .returning();

  return invite || null;
};

export const revokeOrganizationInvite = async (inviteId, tx = db) => {
  const [invite] = await tx
    .update(organizationInvites)
    .set({ revokedAt: new Date() })
    .where(eq(organizationInvites.id, inviteId))
    .returning();

  return invite || null;
};
