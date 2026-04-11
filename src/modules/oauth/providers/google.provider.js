import axios from "axios";
import env from "../../../core/config/config.js";
import { OAUTH_PROVIDERS } from "../oauth.constants.js";
import { OAUTH_PROVIDER_DETAILS } from "./provider.constants.js";

const GOOGLE_PROVIDER = OAUTH_PROVIDER_DETAILS[OAUTH_PROVIDERS.GOOGLE];

export const getGoogleAuthorizationUrl = () => {
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: env.GOOGLE_CALLBACK_URL,
    response_type: "code",
    scope: GOOGLE_PROVIDER.scope,
    access_type: GOOGLE_PROVIDER.accessType,
    prompt: GOOGLE_PROVIDER.prompt,
  });

  return `${GOOGLE_PROVIDER.authUrl}?${params.toString()}`;
};

export const exchangeGoogleCode = async (code) => {
  const payload = new URLSearchParams({
    code,
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    redirect_uri: env.GOOGLE_CALLBACK_URL,
    grant_type: GOOGLE_PROVIDER.tokenGrantType,
  });

  const { data } = await axios.post(
    GOOGLE_PROVIDER.tokenUrl,
    payload.toString(),
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    },
  );

  return data;
};

export const fetchGoogleProfile = async (accessToken) => {
  const { data } = await axios.get(GOOGLE_PROVIDER.profileUrl, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  return {
    provider: OAUTH_PROVIDERS.GOOGLE,
    providerAccountId: data.id,
    email: data.email,
    name: data.name,
    avatarUrl: data.picture,
  };
};
