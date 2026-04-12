import { z } from "zod";
import {
  OAUTH_AUTHORIZE_CODE_CHALLENGE_METHODS,
  OAUTH_FLOW_TYPES,
  OAUTH_OIDC_GRANT_TYPES,
  OAUTH_PROVIDERS,
} from "../../modules/oauth/oauth.constants.js";

const OIDC_ALLOWED_SCOPES = ["openid", "profile", "email"];

const normalizeScope = (scopeValue) => {
  const normalized = String(scopeValue || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  return Array.from(new Set(normalized));
};

const oauthProviderSchema = z.enum([
  OAUTH_PROVIDERS.GOOGLE,
  OAUTH_PROVIDERS.GITHUB,
]);

export const organizationOauthParamSchema = z.object({
  orgId: z.string().uuid(),
  clientId: z.string().uuid(),
  provider: oauthProviderSchema,
});

export const organizationOauthProvidersParamSchema = z.object({
  orgId: z.string().uuid(),
  clientId: z.string().uuid(),
});

export const organizationOauthStartQuerySchema = z.object({
  returnTo: z.string().url().optional(),
  flowType: z
    .enum([OAUTH_FLOW_TYPES.SIGNIN, OAUTH_FLOW_TYPES.SIGNUP])
    .default(OAUTH_FLOW_TYPES.SIGNIN),
  clientContext: z.string().trim().min(1).max(255).optional(),
});

export const organizationOauthCallbackQuerySchema = z.object({
  code: z.string().trim().min(1),
  state: z.string().trim().min(20).max(500),
});

export const confirmOrganizationOauthChallengeSchema = z.object({
  challengeToken: z.string().trim().min(20).max(500),
});

export const oidcAuthorizeQuerySchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().uuid(),
  redirect_uri: z.string().url(),
  scope: z
    .string()
    .trim()
    .min(1)
    .transform((value) => normalizeScope(value))
    .refine((scopes) => scopes.includes("openid"), {
      message: "scope must include openid",
    })
    .refine(
      (scopes) => scopes.every((scope) => OIDC_ALLOWED_SCOPES.includes(scope)),
      {
        message: "scope contains unsupported values",
      },
    ),
  state: z.string().trim().min(8).max(500).optional(),
  nonce: z.string().trim().min(8).max(500).optional(),
  code_challenge: z.string().trim().min(43).max(128).optional(),
  code_challenge_method: z
    .enum([OAUTH_AUTHORIZE_CODE_CHALLENGE_METHODS.S256])
    .optional(),
});

export const oidcAuthorizeCompleteBodySchema = z.object({
  request: z.string().trim().min(20).max(500),
});

export const oidcAuthorizeInitQuerySchema = z.object({
  request: z.string().trim().min(20).max(500),
});

export const oidcTokenBodySchema = z.object({
  grant_type: z.literal(OAUTH_OIDC_GRANT_TYPES.AUTHORIZATION_CODE),
  code: z.string().trim().min(20).max(500),
  redirect_uri: z.string().url(),
  client_id: z.string().uuid().optional(),
  client_secret: z.string().trim().min(8).max(500).optional(),
  code_verifier: z.string().trim().min(43).max(128).optional(),
});
