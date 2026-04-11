import { COOKIE_NAMES } from "../../core/constants/cookie.constants.js";

export const OPENAPI_COMPONENTS = {
  securitySchemes: {
    bearerAuth: {
      type: "http",
      scheme: "bearer",
      bearerFormat: "JWT",
    },
    cookieAuth: {
      type: "apiKey",
      in: "cookie",
      name: COOKIE_NAMES.ACCESS_TOKEN,
    },
  },
  schemas: {
    ErrorResponse: {
      type: "object",
      properties: {
        error: { type: "string" },
        code: { type: "string" },
        requestId: { type: "string" },
      },
      required: ["error", "code"],
    },
    AuthSession: {
      type: "object",
      properties: {
        id: { type: "string", format: "uuid" },
        userId: { type: "string", format: "uuid" },
        orgId: { type: "string", format: "uuid", nullable: true },
        deviceId: { type: "string" },
        userAgent: { type: "string" },
        ipAddress: { type: "string" },
        version: { type: "integer" },
        isActive: { type: "boolean" },
        lastActivityAt: { type: "string", format: "date-time" },
        createdAt: { type: "string", format: "date-time" },
        expiresAt: { type: "string", format: "date-time" },
      },
    },
    AuthUser: {
      type: "object",
      properties: {
        id: { type: "string", format: "uuid" },
        email: { type: "string", format: "email" },
        name: { type: "string", nullable: true },
        avatarUrl: { type: "string", nullable: true },
        emailVerified: { type: "boolean" },
        lastLoginAt: { type: "string", format: "date-time", nullable: true },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    SignupRequest: {
      type: "object",
      required: ["email", "password"],
      properties: {
        email: { type: "string", format: "email" },
        password: {
          type: "string",
          minLength: 8,
          description: "Must include uppercase, lowercase, number, and symbol.",
        },
        name: { type: "string" },
        avatarUrl: { type: "string", format: "uri" },
      },
    },
    LoginRequest: {
      type: "object",
      required: ["email", "password"],
      properties: {
        email: { type: "string", format: "email" },
        password: { type: "string" },
        orgId: { type: "string", format: "uuid" },
      },
    },
    AuthResponse: {
      type: "object",
      properties: {
        user: { $ref: "#/components/schemas/AuthUser" },
        session: { $ref: "#/components/schemas/AuthSession" },
        accessToken: { type: "string" },
      },
    },
    RefreshResponse: {
      type: "object",
      properties: {
        session: { $ref: "#/components/schemas/AuthSession" },
        accessToken: { type: "string" },
      },
    },
    SessionListResponse: {
      type: "object",
      properties: {
        sessions: {
          type: "array",
          items: { $ref: "#/components/schemas/AuthSession" },
        },
      },
    },
    Organization: {
      type: "object",
      properties: {
        id: { type: "string", format: "uuid" },
        name: { type: "string" },
        slug: { type: "string" },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
      required: ["id", "name", "slug", "createdAt", "updatedAt"],
    },
    OrganizationMembership: {
      type: "object",
      properties: {
        id: { type: "string", format: "uuid" },
        orgId: { type: "string", format: "uuid" },
        userId: { type: "string", format: "uuid" },
        role: { type: "string", enum: ["owner", "admin", "member"] },
        invitedByUserId: { type: "string", format: "uuid", nullable: true },
        email: { type: "string", format: "email" },
        name: { type: "string", nullable: true },
        avatarUrl: { type: "string", nullable: true },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    OrganizationInvite: {
      type: "object",
      properties: {
        id: { type: "string", format: "uuid" },
        orgId: { type: "string", format: "uuid" },
        invitedEmail: { type: "string", format: "email" },
        role: { type: "string", enum: ["owner", "admin", "member"] },
        invitedByUserId: { type: "string", format: "uuid" },
        acceptedByUserId: { type: "string", format: "uuid", nullable: true },
        expiresAt: { type: "string", format: "date-time" },
        createdAt: { type: "string", format: "date-time" },
        usedAt: { type: "string", format: "date-time", nullable: true },
        revokedAt: { type: "string", format: "date-time", nullable: true },
      },
    },
    CreateOrganizationRequest: {
      type: "object",
      required: ["name"],
      properties: {
        name: { type: "string", minLength: 2, maxLength: 255 },
      },
    },
    UpdateOrganizationRequest: {
      type: "object",
      properties: {
        name: { type: "string", minLength: 2, maxLength: 255 },
      },
    },
    CreateOrganizationInviteRequest: {
      type: "object",
      required: ["email"],
      properties: {
        email: { type: "string", format: "email" },
        role: {
          type: "string",
          enum: ["owner", "admin", "member"],
          default: "member",
        },
      },
    },
    AcceptOrganizationInviteRequest: {
      type: "object",
      required: ["token"],
      properties: {
        token: { type: "string" },
      },
    },
    UpdateOrganizationMemberRoleRequest: {
      type: "object",
      required: ["role"],
      properties: {
        role: {
          type: "string",
          enum: ["admin", "member"],
        },
      },
    },
    TransferOrganizationOwnershipRequest: {
      type: "object",
      required: ["targetUserId"],
      properties: {
        targetUserId: { type: "string", format: "uuid" },
        previousOwnerRole: {
          type: "string",
          enum: ["admin", "member"],
          default: "admin",
        },
      },
    },
    OrganizationMemberRoleUpdateResponse: {
      type: "object",
      properties: {
        message: { type: "string" },
        member: { $ref: "#/components/schemas/OrganizationMembership" },
      },
    },
    OrganizationOwnershipTransferResponse: {
      type: "object",
      properties: {
        message: { type: "string" },
        organization: { $ref: "#/components/schemas/Organization" },
        previousOwner: { $ref: "#/components/schemas/OrganizationMembership" },
        newOwner: { $ref: "#/components/schemas/OrganizationMembership" },
      },
    },
    OrganizationListResponse: {
      type: "object",
      properties: {
        organizations: {
          type: "array",
          items: {
            allOf: [
              { $ref: "#/components/schemas/Organization" },
              {
                type: "object",
                properties: {
                  role: {
                    type: "string",
                    enum: ["owner", "admin", "member"],
                  },
                },
              },
            ],
          },
        },
      },
    },
    OrganizationDetailResponse: {
      type: "object",
      properties: {
        organization: { $ref: "#/components/schemas/Organization" },
        members: {
          type: "array",
          items: { $ref: "#/components/schemas/OrganizationMembership" },
        },
      },
    },
  },
};
