import {
  OPENAPI_DESCRIPTIONS,
  OPENAPI_PATHS,
  OPENAPI_SECURITY,
  OPENAPI_TAGS,
} from "./openapi.constants.js";

const jsonRefResponse = (description, ref) => ({
  description,
  content: {
    "application/json": {
      schema: { $ref: ref },
    },
  },
});

const jsonObjectResponse = (description, schema) => ({
  description,
  content: {
    "application/json": {
      schema,
    },
  },
});

export const OPENAPI_PATH_DEFINITIONS = {
  [OPENAPI_PATHS.AUTH_SIGNUP]: {
    post: {
      summary: "Register a new user account",
      tags: [OPENAPI_TAGS.AUTH],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/SignupRequest" },
          },
        },
      },
      responses: {
        201: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.SIGNUP_SUCCESS,
          "#/components/schemas/AuthResponse",
        ),
        400: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.INVALID_INPUT,
          "#/components/schemas/ErrorResponse",
        ),
        409: { description: "Email already exists" },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_LOGIN]: {
    post: {
      summary: "Sign in with email and password",
      tags: [OPENAPI_TAGS.AUTH],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/LoginRequest" },
          },
        },
      },
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.LOGIN_SUCCESS,
          "#/components/schemas/AuthResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.INVALID_CREDENTIALS },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_LOGOUT]: {
    post: {
      summary: "Logout current session",
      tags: [OPENAPI_TAGS.AUTH],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      responses: {
        200: { description: OPENAPI_DESCRIPTIONS.LOGOUT_SUCCESS },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_REFRESH]: {
    post: {
      summary: "Refresh access token using refresh cookie",
      tags: [OPENAPI_TAGS.AUTH],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.TOKEN_REFRESHED,
          "#/components/schemas/RefreshResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.INVALID_REFRESH_TOKEN },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_VERIFY_EMAIL]: {
    get: {
      summary: "Verify user email by one-time token",
      tags: [OPENAPI_TAGS.AUTH],
      parameters: [
        {
          in: "path",
          name: "token",
          required: true,
          schema: { type: "string" },
        },
      ],
      responses: {
        200: { description: OPENAPI_DESCRIPTIONS.EMAIL_VERIFIED },
        401: { description: OPENAPI_DESCRIPTIONS.INVALID_TOKEN },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_RESEND_VERIFICATION]: {
    post: {
      summary: "Resend verification email",
      tags: [OPENAPI_TAGS.AUTH],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["email"],
              properties: {
                email: { type: "string", format: "email" },
              },
            },
          },
        },
      },
      responses: {
        200: { description: OPENAPI_DESCRIPTIONS.REQUEST_ACCEPTED },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_FORGOT_PASSWORD]: {
    post: {
      summary: "Request password reset link",
      tags: [OPENAPI_TAGS.AUTH],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["email"],
              properties: {
                email: { type: "string", format: "email" },
              },
            },
          },
        },
      },
      responses: {
        200: { description: OPENAPI_DESCRIPTIONS.REQUEST_ACCEPTED },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_RESET_PASSWORD]: {
    post: {
      summary: "Reset account password with one-time token",
      tags: [OPENAPI_TAGS.AUTH],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              required: ["token", "password"],
              properties: {
                token: { type: "string" },
                password: { type: "string", minLength: 8 },
              },
            },
          },
        },
      },
      responses: {
        200: { description: OPENAPI_DESCRIPTIONS.PASSWORD_UPDATED },
        401: { description: OPENAPI_DESCRIPTIONS.INVALID_TOKEN },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_SESSIONS]: {
    get: {
      summary: "List active sessions for current user",
      tags: [OPENAPI_TAGS.AUTH],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.SESSION_LIST,
          "#/components/schemas/SessionListResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
  },
  [OPENAPI_PATHS.AUTH_SESSION_BY_ID]: {
    delete: {
      summary: "Revoke a specific session for current user",
      tags: [OPENAPI_TAGS.AUTH],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "id",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: { description: OPENAPI_DESCRIPTIONS.SESSION_REVOKED },
        404: { description: OPENAPI_DESCRIPTIONS.SESSION_NOT_FOUND },
      },
    },
  },
  [OPENAPI_PATHS.USERS_ME]: {
    get: {
      summary: "Get current authenticated user profile",
      tags: [OPENAPI_TAGS.USERS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      responses: {
        200: jsonObjectResponse(OPENAPI_DESCRIPTIONS.CURRENT_USER, {
          type: "object",
          properties: {
            user: { $ref: "#/components/schemas/AuthUser" },
          },
        }),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
    patch: {
      summary: "Update current user profile",
      tags: [OPENAPI_TAGS.USERS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                name: { type: "string" },
                avatarUrl: { type: "string", format: "uri" },
              },
            },
          },
        },
      },
      responses: {
        200: jsonObjectResponse(OPENAPI_DESCRIPTIONS.USER_UPDATED, {
          type: "object",
          properties: {
            user: { $ref: "#/components/schemas/AuthUser" },
          },
        }),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
    delete: {
      summary: "Delete current user account",
      tags: [OPENAPI_TAGS.USERS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      responses: {
        204: { description: OPENAPI_DESCRIPTIONS.USER_DELETED },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATIONS]: {
    post: {
      summary: "Create a new organization",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/CreateOrganizationRequest" },
          },
        },
      },
      responses: {
        201: jsonObjectResponse(OPENAPI_DESCRIPTIONS.ORGANIZATION_CREATED, {
          type: "object",
          properties: {
            organization: { $ref: "#/components/schemas/Organization" },
            membership: { $ref: "#/components/schemas/OrganizationMembership" },
          },
        }),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        409: { description: "Organization name already exists" },
      },
    },
    get: {
      summary: "List organizations for current user",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_LIST,
          "#/components/schemas/OrganizationListResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_BY_ID]: {
    get: {
      summary: "Get organization details for a collaborator",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_DETAILS,
          "#/components/schemas/OrganizationDetailResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization not found" },
      },
    },
    patch: {
      summary: "Update organization metadata",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/UpdateOrganizationRequest" },
          },
        },
      },
      responses: {
        200: jsonObjectResponse(OPENAPI_DESCRIPTIONS.ORGANIZATION_UPDATED, {
          type: "object",
          properties: {
            organization: { $ref: "#/components/schemas/Organization" },
          },
        }),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization not found" },
        409: { description: "Organization name already exists" },
      },
    },
    delete: {
      summary: "Delete organization (owner only)",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: { description: OPENAPI_DESCRIPTIONS.ORGANIZATION_DELETED },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_INVITES]: {
    post: {
      summary: "Invite a collaborator to organization",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/CreateOrganizationInviteRequest",
            },
          },
        },
      },
      responses: {
        201: jsonObjectResponse(OPENAPI_DESCRIPTIONS.ORGANIZATION_INVITE_SENT, {
          type: "object",
          properties: {
            message: { type: "string" },
            invite: { $ref: "#/components/schemas/OrganizationInvite" },
          },
        }),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization not found" },
        409: {
          description:
            "Active invite already exists or user is already a collaborator",
        },
      },
    },
    get: {
      summary: "List organization invites",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonObjectResponse(OPENAPI_DESCRIPTIONS.ORGANIZATION_INVITE_LIST, {
          type: "object",
          properties: {
            invites: {
              type: "array",
              items: { $ref: "#/components/schemas/OrganizationInvite" },
            },
          },
        }),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_INVITE_BY_ID]: {
    delete: {
      summary: "Revoke organization invite",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "inviteId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_INVITE_REVOKED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
              invite: { $ref: "#/components/schemas/OrganizationInvite" },
            },
          },
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Invite not found" },
        409: { description: "Invite already used or revoked" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_MEMBER_ROLE]: {
    patch: {
      summary: "Update organization member role (owner only)",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "userId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/UpdateOrganizationMemberRoleRequest",
            },
          },
        },
      },
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_MEMBER_ROLE_UPDATED,
          "#/components/schemas/OrganizationMemberRoleUpdateResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or member not found" },
        409: { description: "Role change conflict" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_TRANSFER_OWNERSHIP]: {
    post: {
      summary: "Transfer organization ownership to another member",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/TransferOrganizationOwnershipRequest",
            },
          },
        },
      },
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_OWNERSHIP_TRANSFERRED,
          "#/components/schemas/OrganizationOwnershipTransferResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or member not found" },
        409: { description: "Ownership transfer conflict" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENTS]: {
    get: {
      summary: "List organization OAuth clients",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonObjectResponse(OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_LIST, {
          type: "object",
          properties: {
            clients: {
              type: "array",
              items: { $ref: "#/components/schemas/OrganizationClient" },
            },
          },
        }),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization not found" },
      },
    },
    post: {
      summary: "Create organization OAuth client",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/CreateOrganizationClientRequest",
            },
          },
        },
      },
      responses: {
        201: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_CREATED,
          {
            $ref: "#/components/schemas/OrganizationClientSecretResponse",
          },
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization not found" },
        409: { description: "Client name already exists" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_BY_ID]: {
    get: {
      summary: "Get organization OAuth client details",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_DETAILS,
          {
            type: "object",
            properties: {
              client: { $ref: "#/components/schemas/OrganizationClient" },
            },
          },
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
    patch: {
      summary: "Update organization OAuth client",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/UpdateOrganizationClientRequest",
            },
          },
        },
      },
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_UPDATED,
          {
            type: "object",
            properties: {
              client: { $ref: "#/components/schemas/OrganizationClient" },
            },
          },
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
        409: { description: "Client name already exists" },
      },
    },
    delete: {
      summary: "Delete organization OAuth client",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_DELETED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
            },
          },
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_USERS]: {
    get: {
      summary: "List users visible to an organization client",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "query",
          name: "limit",
          required: false,
          schema: { type: "integer", minimum: 1, maximum: 200, default: 50 },
        },
        {
          in: "query",
          name: "offset",
          required: false,
          schema: { type: "integer", minimum: 0, default: 0 },
        },
      ],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_USERS,
          "#/components/schemas/OrganizationClientUsersResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_SECRET_ROTATE]: {
    post: {
      summary: "Rotate organization client secret",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_SECRET_ROTATED,
          "#/components/schemas/OrganizationClientSecretResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_PROVIDERS]: {
    post: {
      summary: "Configure provider credentials for organization client",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/CreateOrganizationClientProviderRequest",
            },
          },
        },
      },
      responses: {
        201: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_PROVIDER_ADDED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
              provider: {
                $ref: "#/components/schemas/OrganizationClientProvider",
              },
            },
          },
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
        409: { description: "Provider is already configured" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_PROVIDER_BY_ID]: {
    patch: {
      summary: "Update provider credentials for organization client",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "provider",
          required: true,
          schema: { type: "string", enum: ["google", "github"] },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/UpdateOrganizationClientProviderRequest",
            },
          },
        },
      },
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_PROVIDER_UPDATED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
              provider: {
                $ref: "#/components/schemas/OrganizationClientProvider",
              },
            },
          },
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization, client, or provider not found" },
      },
    },
    delete: {
      summary: "Remove provider from organization client",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "provider",
          required: true,
          schema: { type: "string", enum: ["google", "github"] },
        },
      ],
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_PROVIDER_REMOVED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
            },
          },
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization, client, or provider not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_WEBHOOK]: {
    post: {
      summary: "Configure organization client logout webhook",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/ConfigureOrganizationClientWebhookRequest",
            },
          },
        },
      },
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_CONFIGURED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
              webhook: {
                $ref: "#/components/schemas/OrganizationClientWebhookConfig",
              },
            },
          },
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
    delete: {
      summary: "Disable organization client logout webhook",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_DISABLED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
            },
          },
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_WEBHOOK_SECRET_ROTATE]: {
    post: {
      summary: "Rotate organization client logout webhook secret",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_SECRET_ROTATED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
              webhook: {
                $ref: "#/components/schemas/OrganizationClientWebhookConfig",
              },
            },
          },
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_WEBHOOK_DELIVERIES]: {
    get: {
      summary: "List organization client webhook deliveries",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "query",
          name: "limit",
          required: false,
          schema: { type: "integer", minimum: 1, maximum: 200, default: 50 },
        },
        {
          in: "query",
          name: "offset",
          required: false,
          schema: { type: "integer", minimum: 0, default: 0 },
        },
        {
          in: "query",
          name: "status",
          required: false,
          schema: { type: "string", enum: ["success", "failed"] },
        },
        {
          in: "query",
          name: "source",
          required: false,
          schema: {
            type: "string",
            enum: ["event", "replay", "test", "verify"],
          },
        },
        {
          in: "query",
          name: "event",
          required: false,
          schema: { type: "string" },
        },
      ],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_DELIVERIES,
          "#/components/schemas/WebhookDeliveriesResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_WEBHOOK_DELIVERY_BY_ID]: {
    get: {
      summary: "Get organization client webhook delivery details",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "deliveryId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_DELIVERY,
          "#/components/schemas/WebhookDeliveryResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization, client, or delivery not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_WEBHOOK_DELIVERY_REPLAY]: {
    post: {
      summary: "Replay a failed organization client webhook delivery",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "deliveryId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        202: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_DELIVERY_REPLAYED,
          "#/components/schemas/ReplayWebhookDeliveryResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization, client, or delivery not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_WEBHOOK_STATUS]: {
    get: {
      summary: "Get organization client webhook delivery status",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_STATUS,
          "#/components/schemas/WebhookStatusResponse",
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_WEBHOOK_TEST]: {
    post: {
      summary: "Send test webhook to organization client receiver",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      requestBody: {
        required: false,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/TestOrganizationClientWebhookRequest",
            },
          },
        },
      },
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_TESTED,
          "#/components/schemas/TestOrganizationClientWebhookResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_CLIENT_WEBHOOK_VERIFY]: {
    post: {
      summary: "Verify organization client webhook receiver ownership",
      tags: [OPENAPI_TAGS.CLIENTS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_CLIENT_WEBHOOK_VERIFIED,
          "#/components/schemas/VerifyOrganizationClientWebhookResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        403: { description: "Forbidden" },
        404: { description: "Organization or client not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_INVITE_BY_TOKEN]: {
    get: {
      summary: "Get invite details by token for current user",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      parameters: [
        {
          in: "path",
          name: "token",
          required: true,
          schema: { type: "string" },
        },
      ],
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_INVITE_DETAILS,
          {
            type: "object",
            properties: {
              invite: { $ref: "#/components/schemas/OrganizationInvite" },
              organization: { $ref: "#/components/schemas/Organization" },
            },
          },
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        404: { description: "Organization not found" },
      },
    },
  },
  [OPENAPI_PATHS.ORGANIZATION_INVITE_ACCEPT]: {
    post: {
      summary: "Accept organization invite",
      tags: [OPENAPI_TAGS.ORGANIZATIONS],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/AcceptOrganizationInviteRequest",
            },
          },
        },
      },
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.ORGANIZATION_INVITE_ACCEPTED,
          {
            type: "object",
            properties: {
              message: { type: "string" },
              member: { $ref: "#/components/schemas/OrganizationMembership" },
              invite: { $ref: "#/components/schemas/OrganizationInvite" },
              organization: { $ref: "#/components/schemas/Organization" },
            },
          },
        ),
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
        409: { description: "User is already a collaborator" },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_AUTHORIZE]: {
    get: {
      summary:
        "Validate OIDC authorize request and redirect to frontend initiation page",
      tags: [OPENAPI_TAGS.SSO],
      parameters: [
        {
          in: "query",
          name: "response_type",
          required: true,
          schema: { type: "string", enum: ["code"] },
        },
        {
          in: "query",
          name: "client_id",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "query",
          name: "redirect_uri",
          required: true,
          schema: { type: "string", format: "uri" },
        },
        {
          in: "query",
          name: "scope",
          required: true,
          schema: { type: "string" },
        },
        {
          in: "query",
          name: "state",
          required: false,
          schema: { type: "string" },
        },
        {
          in: "query",
          name: "nonce",
          required: false,
          schema: { type: "string" },
        },
      ],
      responses: {
        302: { description: OPENAPI_DESCRIPTIONS.OAUTH_AUTHORIZE },
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        404: { description: "Client not found" },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_AUTHORIZE_INIT]: {
    get: {
      summary:
        "Return configured providers and generated authorization URLs for OIDC initiation",
      tags: [OPENAPI_TAGS.SSO],
      parameters: [
        {
          in: "query",
          name: "request",
          required: true,
          schema: { type: "string" },
        },
      ],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.OAUTH_AUTHORIZE_INIT,
          "#/components/schemas/OidcAuthorizeInitResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        404: { description: "Client not found" },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_AUTHORIZE_COMPLETE]: {
    post: {
      summary: "Complete OIDC authorize request after user authentication",
      tags: [OPENAPI_TAGS.SSO],
      security: OPENAPI_SECURITY.AUTHENTICATED,
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/OidcAuthorizeCompleteRequest",
            },
          },
        },
      },
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.OAUTH_AUTHORIZE_COMPLETE,
          "#/components/schemas/OidcAuthorizeCompleteResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_TOKEN]: {
    post: {
      summary: "Exchange OIDC authorization code for tokens",
      tags: [OPENAPI_TAGS.SSO],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/OidcTokenRequest",
            },
          },
          "application/x-www-form-urlencoded": {
            schema: {
              $ref: "#/components/schemas/OidcTokenRequest",
            },
          },
        },
      },
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.OAUTH_TOKEN,
          "#/components/schemas/OidcTokenResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_USERINFO]: {
    get: {
      summary: "Fetch OIDC user claims using access token",
      tags: [OPENAPI_TAGS.SSO],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.OAUTH_USERINFO,
          "#/components/schemas/OidcUserInfoResponse",
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        401: { description: OPENAPI_DESCRIPTIONS.UNAUTHORIZED },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_JWKS]: {
    get: {
      summary: "Get JWKS for OIDC token verification",
      tags: [OPENAPI_TAGS.SSO],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.OAUTH_JWKS,
          "#/components/schemas/OidcJwksResponse",
        ),
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_DISCOVERY]: {
    get: {
      summary: "Get OpenID Provider configuration",
      tags: [OPENAPI_TAGS.SSO],
      responses: {
        200: jsonRefResponse(
          OPENAPI_DESCRIPTIONS.OAUTH_DISCOVERY,
          "#/components/schemas/OidcDiscoveryResponse",
        ),
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_GOOGLE]: {
    get: {
      summary: "Start Google OAuth authorization flow",
      tags: [OPENAPI_TAGS.OAUTH],
      responses: {
        302: { description: OPENAPI_DESCRIPTIONS.OAUTH_PROVIDER_REDIRECT },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_GOOGLE_CALLBACK]: {
    get: {
      summary: "Handle Google OAuth callback and create authenticated session",
      tags: [OPENAPI_TAGS.OAUTH],
      parameters: [
        {
          in: "query",
          name: "code",
          required: true,
          schema: { type: "string" },
        },
      ],
      responses: {
        302: { description: OPENAPI_DESCRIPTIONS.OAUTH_REDIRECT },
        400: { description: OPENAPI_DESCRIPTIONS.MISSING_OR_INVALID_CODE },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_GITHUB]: {
    get: {
      summary: "Start GitHub OAuth authorization flow",
      tags: [OPENAPI_TAGS.OAUTH],
      responses: {
        302: { description: OPENAPI_DESCRIPTIONS.OAUTH_PROVIDER_REDIRECT },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_GITHUB_CALLBACK]: {
    get: {
      summary: "Handle GitHub OAuth callback and create authenticated session",
      tags: [OPENAPI_TAGS.OAUTH],
      parameters: [
        {
          in: "query",
          name: "code",
          required: true,
          schema: { type: "string" },
        },
      ],
      responses: {
        302: { description: OPENAPI_DESCRIPTIONS.OAUTH_REDIRECT },
        400: { description: OPENAPI_DESCRIPTIONS.MISSING_OR_INVALID_CODE },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_ORG_CLIENT_PROVIDERS]: {
    get: {
      summary: "List configured OAuth providers for an organization client",
      tags: [OPENAPI_TAGS.SSO],
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
      ],
      responses: {
        200: jsonObjectResponse(OPENAPI_DESCRIPTIONS.OAUTH_CLIENT_PROVIDERS, {
          type: "object",
          properties: {
            client: {
              type: "object",
              properties: {
                id: { type: "string", format: "uuid" },
                orgId: { type: "string", format: "uuid" },
                name: { type: "string" },
              },
            },
            providers: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  provider: { type: "string", enum: ["google", "github"] },
                  startUrl: { type: "string", format: "uri" },
                },
              },
            },
          },
        }),
        404: { description: "Client not found" },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_ORG_CLIENT_START]: {
    get: {
      summary: "Start organization client OAuth flow",
      tags: [OPENAPI_TAGS.SSO],
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "provider",
          required: true,
          schema: { type: "string", enum: ["google", "github"] },
        },
        {
          in: "query",
          name: "returnTo",
          required: false,
          schema: { type: "string", format: "uri" },
        },
        {
          in: "query",
          name: "flowType",
          required: false,
          schema: { type: "string", enum: ["signin", "signup"] },
        },
      ],
      responses: {
        302: { description: OPENAPI_DESCRIPTIONS.OAUTH_ORG_CLIENT_START },
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
        404: { description: "Client provider not configured" },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_ORG_CLIENT_CALLBACK]: {
    get: {
      summary: "Handle organization client OAuth callback",
      tags: [OPENAPI_TAGS.SSO],
      parameters: [
        {
          in: "path",
          name: "orgId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "clientId",
          required: true,
          schema: { type: "string", format: "uuid" },
        },
        {
          in: "path",
          name: "provider",
          required: true,
          schema: { type: "string", enum: ["google", "github"] },
        },
        {
          in: "query",
          name: "code",
          required: true,
          schema: { type: "string" },
        },
        {
          in: "query",
          name: "state",
          required: true,
          schema: { type: "string" },
        },
      ],
      responses: {
        302: { description: OPENAPI_DESCRIPTIONS.OAUTH_ORG_CLIENT_CALLBACK },
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
      },
    },
  },
  [OPENAPI_PATHS.OAUTH_ORG_CLIENT_CONFIRM]: {
    post: {
      summary: "Confirm relogin challenge for organization OAuth flow",
      tags: [OPENAPI_TAGS.SSO],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              $ref: "#/components/schemas/ConfirmOrganizationOauthChallengeRequest",
            },
          },
        },
      },
      responses: {
        200: jsonObjectResponse(
          OPENAPI_DESCRIPTIONS.OAUTH_CONFIRMATION_COMPLETED,
          {
            type: "object",
            properties: {
              redirectTo: { type: "string", format: "uri" },
            },
          },
        ),
        400: { description: OPENAPI_DESCRIPTIONS.INVALID_INPUT },
      },
    },
  },
};
