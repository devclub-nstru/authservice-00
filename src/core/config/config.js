import "dotenv/config";
import fs from "node:fs";
import { z } from "zod";

const envSchema = z.object({
  APP_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  FRONTEND_URL: z.string().url(),
  API_BASE_URL: z.string().url().optional(),
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  ACCESS_TOKEN_PRIVATE_KEY_PATH: z.string().min(1),
  ACCESS_TOKEN_PUBLIC_KEY_PATH: z.string().min(1),
  REFRESH_TOKEN_PRIVATE_KEY_PATH: z.string().min(1),
  REFRESH_TOKEN_PUBLIC_KEY_PATH: z.string().min(1),
  ACCESS_TOKEN_TTL: z.string().default("15m"),
  REFRESH_TOKEN_TTL: z.string().default("7d"),
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  GOOGLE_CALLBACK_URL: z.string().url(),
  GITHUB_CLIENT_ID: z.string().min(1),
  GITHUB_CLIENT_SECRET: z.string().min(1),
  GITHUB_CALLBACK_URL: z.string().url(),
  SMTP_HOST: z.string().min(1),
  SMTP_PORT: z.coerce.number().int().positive(),
  SMTP_USER: z.string().min(1),
  SMTP_PASS: z.string().min(1),
  SMTP_FROM: z.string().email().default("no-reply@example.com"),
  COOKIE_DOMAIN: z.string().optional(),
  COOKIE_SECURE: z
    .enum(["true", "false"])
    .optional()
    .transform((value) => value === "true"),
  COOKIE_SAME_SITE: z.enum(["strict", "lax", "none"]).default("lax"),
  SESSION_TTL_DAYS: z.coerce.number().int().positive().default(7),
  BCRYPT_SALT_ROUNDS: z.coerce.number().int().min(10).default(10),
  OAUTH_CLIENT_SECRET_ENCRYPTION_KEY: z.string().min(1),
  OAUTH_STATE_TTL_SECONDS: z.coerce.number().int().positive().default(300),
  OAUTH_RELOGIN_REQUIREMENT_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(86400),
  OAUTH_RELOGIN_CHALLENGE_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(180),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  const details = parsed.error.issues
    .map((issue) => `${issue.path.join(".")}: ${issue.message}`)
    .join("; ");
  throw new Error(`Invalid environment configuration: ${details}`);
}

const envConfig = parsed.data;

if (!envConfig.API_BASE_URL) {
  envConfig.API_BASE_URL = `http://localhost:${envConfig.PORT}`;
}

const ensureFileExists = (pathValue, keyName) => {
  if (!fs.existsSync(pathValue)) {
    throw new Error(
      `Environment ${keyName} points to missing file: ${pathValue}`,
    );
  }
};

ensureFileExists(
  envConfig.ACCESS_TOKEN_PRIVATE_KEY_PATH,
  "ACCESS_TOKEN_PRIVATE_KEY_PATH",
);
ensureFileExists(
  envConfig.ACCESS_TOKEN_PUBLIC_KEY_PATH,
  "ACCESS_TOKEN_PUBLIC_KEY_PATH",
);
ensureFileExists(
  envConfig.REFRESH_TOKEN_PRIVATE_KEY_PATH,
  "REFRESH_TOKEN_PRIVATE_KEY_PATH",
);
ensureFileExists(
  envConfig.REFRESH_TOKEN_PUBLIC_KEY_PATH,
  "REFRESH_TOKEN_PUBLIC_KEY_PATH",
);

export default envConfig;
