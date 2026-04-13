import { z } from "zod";
import {
  AUTH_CLIENT_CONTEXT_LIMITS,
  AUTH_ONE_TIME_TOKEN_MIN_LENGTH,
  AUTH_PASSWORD_COMPLEXITY_MESSAGE,
  AUTH_PASSWORD_COMPLEXITY_REGEX,
  AUTH_PROFILE_NAME_LIMITS,
} from "../../modules/auth/auth.constants.js";

export const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().regex(AUTH_PASSWORD_COMPLEXITY_REGEX, {
    message: AUTH_PASSWORD_COMPLEXITY_MESSAGE,
  }),
  name: z
    .string()
    .min(AUTH_PROFILE_NAME_LIMITS.MIN)
    .max(AUTH_PROFILE_NAME_LIMITS.MAX)
    .optional(),
  avatarUrl: z.string().url().optional(),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export const logoutSchema = z.object({
  clientId: z.string().uuid().optional(),
  clientContext: z
    .string()
    .trim()
    .min(AUTH_CLIENT_CONTEXT_LIMITS.MIN)
    .max(AUTH_CLIENT_CONTEXT_LIMITS.MAX)
    .optional(),
});

export const resendVerificationSchema = z.object({
  email: z.string().email(),
});

export const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(AUTH_ONE_TIME_TOKEN_MIN_LENGTH),
  password: z.string().regex(AUTH_PASSWORD_COMPLEXITY_REGEX, {
    message: AUTH_PASSWORD_COMPLEXITY_MESSAGE,
  }),
});
