import { z } from "zod";
import {
  ORGANIZATION_NAME_LIMITS,
  ORGANIZATION_NON_OWNER_ROLE_VALUES,
  ORGANIZATION_ROLE_VALUES,
} from "../../modules/organization/organization.constants.js";

const roleSchema = z.enum(ORGANIZATION_ROLE_VALUES);
const nonOwnerRoleSchema = z.enum(ORGANIZATION_NON_OWNER_ROLE_VALUES);

export const createOrganizationSchema = z.object({
  name: z
    .string()
    .trim()
    .min(ORGANIZATION_NAME_LIMITS.MIN)
    .max(ORGANIZATION_NAME_LIMITS.MAX),
});

export const updateOrganizationSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(ORGANIZATION_NAME_LIMITS.MIN)
      .max(ORGANIZATION_NAME_LIMITS.MAX)
      .optional(),
  })
  .refine((value) => Object.keys(value).length > 0, {
    message: "At least one field must be provided",
  });

export const organizationIdParamSchema = z.object({
  orgId: z.string().uuid(),
});

export const organizationMemberParamSchema = z.object({
  orgId: z.string().uuid(),
  userId: z.string().uuid(),
});

export const inviteIdParamSchema = z.object({
  inviteId: z.string().uuid(),
});

export const createOrganizationInviteSchema = z.object({
  email: z.string().email(),
  role: roleSchema.default("member"),
});

export const acceptOrganizationInviteSchema = z.object({
  token: z.string().min(16),
});

export const inviteTokenParamSchema = z.object({
  token: z.string().min(16),
});

export const updateOrganizationMemberRoleSchema = z.object({
  role: nonOwnerRoleSchema,
});

export const transferOrganizationOwnershipSchema = z.object({
  targetUserId: z.string().uuid(),
  previousOwnerRole: nonOwnerRoleSchema.default("admin"),
});
