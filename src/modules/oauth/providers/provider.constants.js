import { OAUTH_PROVIDERS } from "../oauth.constants.js";

export const OAUTH_PROVIDER_DETAILS = {
  [OAUTH_PROVIDERS.GOOGLE]: {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    profileUrl: "https://www.googleapis.com/oauth2/v2/userinfo",
    scope: "openid email profile",
    accessType: "offline",
    prompt: "consent",
    tokenGrantType: "authorization_code",
  },
  [OAUTH_PROVIDERS.GITHUB]: {
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    profileUrl: "https://api.github.com/user",
    emailsUrl: "https://api.github.com/user/emails",
    scope: "read:user user:email",
    acceptJson: "application/json",
    acceptGithubVnd: "application/vnd.github+json",
  },
};
