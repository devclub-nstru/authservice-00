import axios from "axios";
import env from "../../../core/config/config.js";
import { OAUTH_PROVIDERS } from "../oauth.constants.js";
import { OAUTH_PROVIDER_DETAILS } from "./provider.constants.js";

const GITHUB_PROVIDER = OAUTH_PROVIDER_DETAILS[OAUTH_PROVIDERS.GITHUB];

export const getGithubAuthorizationUrl = () => {
  const params = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    redirect_uri: env.GITHUB_CALLBACK_URL,
    scope: GITHUB_PROVIDER.scope,
  });

  return `${GITHUB_PROVIDER.authUrl}?${params.toString()}`;
};

export const exchangeGithubCode = async (code) => {
  const payload = {
    code,
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    redirect_uri: env.GITHUB_CALLBACK_URL,
  };

  const { data } = await axios.post(GITHUB_PROVIDER.tokenUrl, payload, {
    headers: { Accept: GITHUB_PROVIDER.acceptJson },
  });

  return data;
};

export const fetchGithubProfile = async (accessToken) => {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: GITHUB_PROVIDER.acceptGithubVnd,
  };

  const [{ data: user }, { data: emails }] = await Promise.all([
    axios.get(GITHUB_PROVIDER.profileUrl, { headers }),
    axios.get(GITHUB_PROVIDER.emailsUrl, { headers }),
  ]);

  const primaryEmail =
    emails.find((entry) => entry.primary)?.email || user.email;

  return {
    provider: OAUTH_PROVIDERS.GITHUB,
    providerAccountId: String(user.id),
    email: primaryEmail,
    name: user.name || user.login,
    avatarUrl: user.avatar_url,
  };
};
