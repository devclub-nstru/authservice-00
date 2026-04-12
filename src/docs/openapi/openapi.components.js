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
    OrganizationClientProvider: {
      type: "object",
      properties: {
        id: { type: "string", format: "uuid" },
        provider: { type: "string", enum: ["google", "github"] },
        callbackUrl: { type: "string", format: "uri" },
        isActive: { type: "boolean" },
        secretConfigured: { type: "boolean" },
        providerClientId: { type: "string", nullable: true },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
      },
    },
    OrganizationClient: {
      type: "object",
      properties: {
        id: { type: "string", format: "uuid" },
        orgId: { type: "string", format: "uuid" },
        name: { type: "string" },
        redirectUris: {
          type: "array",
          items: { type: "string", format: "uri" },
        },
        authorizedOrigins: {
          type: "array",
          items: { type: "string", format: "uri" },
        },
        createdByUserId: { type: "string", format: "uuid", nullable: true },
        updatedByUserId: { type: "string", format: "uuid", nullable: true },
        createdAt: { type: "string", format: "date-time" },
        updatedAt: { type: "string", format: "date-time" },
        clientSecretConfigured: { type: "boolean" },
        webhookEnabled: { type: "boolean" },
        webhookUrl: { type: "string", format: "uri", nullable: true },
        webhookSecret: { type: "string", nullable: true },
        providers: {
          type: "array",
          items: { $ref: "#/components/schemas/OrganizationClientProvider" },
        },
      },
    },
    CreateOrganizationClientRequest: {
      type: "object",
      required: ["name", "redirectUris"],
      properties: {
        name: { type: "string", minLength: 2, maxLength: 255 },
        redirectUris: {
          type: "array",
          minItems: 1,
          items: { type: "string", format: "uri" },
        },
        authorizedOrigins: {
          type: "array",
          items: { type: "string", format: "uri" },
          default: [],
        },
      },
    },
    UpdateOrganizationClientRequest: {
      type: "object",
      properties: {
        name: { type: "string", minLength: 2, maxLength: 255 },
        redirectUris: {
          type: "array",
          minItems: 1,
          items: { type: "string", format: "uri" },
        },
        authorizedOrigins: {
          type: "array",
          items: { type: "string", format: "uri" },
        },
      },
    },
    CreateOrganizationClientProviderRequest: {
      type: "object",
      required: ["provider", "providerClientId", "providerClientSecret"],
      properties: {
        provider: { type: "string", enum: ["google", "github"] },
        providerClientId: { type: "string" },
        providerClientSecret: { type: "string", minLength: 8 },
      },
    },
    UpdateOrganizationClientProviderRequest: {
      type: "object",
      properties: {
        providerClientId: { type: "string" },
        providerClientSecret: { type: "string", minLength: 8 },
        isActive: { type: "boolean" },
      },
    },
    ConfigureOrganizationClientWebhookRequest: {
      type: "object",
      required: ["webhookUrl"],
      properties: {
        webhookUrl: { type: "string", format: "uri" },
      },
    },
    OrganizationClientWebhookConfig: {
      type: "object",
      properties: {
        webhookEnabled: { type: "boolean" },
        webhookUrl: { type: "string", format: "uri" },
        webhookSecret: { type: "string" },
      },
    },
    OrganizationClientSecretResponse: {
      type: "object",
      properties: {
        message: { type: "string" },
        client: { $ref: "#/components/schemas/OrganizationClient" },
        clientSecret: { type: "string" },
      },
    },
    OrganizationClientUser: {
      type: "object",
      properties: {
        userId: { type: "string", format: "uuid" },
        email: { type: "string", format: "email" },
        name: { type: "string", nullable: true },
        avatarUrl: { type: "string", format: "uri", nullable: true },
        emailVerified: { type: "boolean" },
        lastLoginAt: { type: "string", format: "date-time", nullable: true },
        firstSignedInAt: { type: "string", format: "date-time" },
        lastSignedInAt: { type: "string", format: "date-time" },
        linkedAt: { type: "string", format: "date-time" },
      },
    },
    OrganizationClientUsersResponse: {
      type: "object",
      properties: {
        users: {
          type: "array",
          items: { $ref: "#/components/schemas/OrganizationClientUser" },
        },
        pagination: {
          type: "object",
          properties: {
            limit: { type: "integer" },
            offset: { type: "integer" },
            count: { type: "integer" },
          },
        },
      },
    },
    ConfirmOrganizationOauthChallengeRequest: {
      type: "object",
      required: ["challengeToken"],
      properties: {
        challengeToken: { type: "string" },
      },
    },
    OidcAuthorizeRequestQuery: {
      type: "object",
      required: ["response_type", "client_id", "redirect_uri", "scope"],
      properties: {
        response_type: { type: "string", enum: ["code"] },
        client_id: { type: "string", format: "uuid" },
        redirect_uri: { type: "string", format: "uri" },
        scope: { type: "string", example: "openid profile email" },
        state: { type: "string" },
        nonce: { type: "string" },
      },
    },
    OidcAuthorizeInitResponse: {
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
        request: {
          type: "object",
          properties: {
            responseType: { type: "string", enum: ["code"] },
            clientId: { type: "string", format: "uuid" },
            redirectUri: { type: "string", format: "uri" },
            scope: {
              type: "array",
              items: { type: "string", enum: ["openid", "profile", "email"] },
            },
            state: { type: "string" },
            nonce: { type: "string" },
          },
        },
        providers: {
          type: "array",
          items: {
            type: "object",
            properties: {
              provider: { type: "string", enum: ["google", "github"] },
              authorizationUrl: { type: "string", format: "uri" },
            },
          },
        },
      },
    },
    OidcAuthorizeCompleteRequest: {
      type: "object",
      required: ["request"],
      properties: {
        request: { type: "string" },
      },
    },
    OidcAuthorizeCompleteResponse: {
      type: "object",
      properties: {
        code: { type: "string" },
        redirectUrl: { type: "string", format: "uri" },
      },
    },
    OidcTokenRequest: {
      type: "object",
      required: ["grant_type", "code", "redirect_uri"],
      properties: {
        grant_type: { type: "string", enum: ["authorization_code"] },
        code: { type: "string" },
        redirect_uri: { type: "string", format: "uri" },
        client_id: { type: "string", format: "uuid" },
        client_secret: { type: "string" },
        code_verifier: { type: "string" },
      },
    },
    OidcTokenResponse: {
      type: "object",
      properties: {
        token_type: { type: "string", example: "Bearer" },
        expires_in: { type: "integer", example: 900 },
        access_token: { type: "string" },
        id_token: { type: "string" },
        scope: { type: "string", example: "openid profile email" },
      },
    },
    OidcUserInfoResponse: {
      type: "object",
      properties: {
        sub: { type: "string", format: "uuid" },
        email: { type: "string", format: "email" },
        email_verified: { type: "boolean" },
        name: { type: "string", nullable: true },
        picture: { type: "string", format: "uri", nullable: true },
      },
    },
    OidcJwksResponse: {
      type: "object",
      properties: {
        keys: {
          type: "array",
          items: { type: "object", additionalProperties: true },
        },
      },
    },
    OidcDiscoveryResponse: {
      type: "object",
      properties: {
        issuer: { type: "string", format: "uri" },
        authorization_endpoint: { type: "string", format: "uri" },
        token_endpoint: { type: "string", format: "uri" },
        userinfo_endpoint: { type: "string", format: "uri" },
        jwks_uri: { type: "string", format: "uri" },
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
