import { Router } from "express";
import asyncHandler from "../../utils/async-handler.js";
import { requireAuth } from "../auth/auth.middleware.js";
import {
  confirmOrganizationOauthChallengeHandler,
  listOrganizationOauthProvidersHandler,
  oidcAuthorizeCompleteHandler,
  oidcDiscoveryHandler,
  oidcAuthorizeHandler,
  oidcAuthorizeInitHandler,
  oidcJwksHandler,
  oidcTokenHandler,
  oidcUserInfoHandler,
  oauthCallbackHandler,
  oauthStartHandler,
  organizationOauthCallbackHandler,
  organizationOauthStartHandler,
} from "./oauth.controller.js";
import { OAUTH_PROVIDERS, OAUTH_ROUTE_PATHS } from "./oauth.constants.js";

const router = Router();

router.get(OAUTH_ROUTE_PATHS.AUTHORIZE, asyncHandler(oidcAuthorizeHandler));
router.post(
  OAUTH_ROUTE_PATHS.AUTHORIZE_COMPLETE,
  requireAuth,
  asyncHandler(oidcAuthorizeCompleteHandler),
);
router.get(
  OAUTH_ROUTE_PATHS.AUTHORIZE_INIT,
  asyncHandler(oidcAuthorizeInitHandler),
);
router.post(OAUTH_ROUTE_PATHS.TOKEN, asyncHandler(oidcTokenHandler));
router.get(OAUTH_ROUTE_PATHS.USERINFO, asyncHandler(oidcUserInfoHandler));
router.get(OAUTH_ROUTE_PATHS.JWKS, asyncHandler(oidcJwksHandler));
router.get(OAUTH_ROUTE_PATHS.DISCOVERY, asyncHandler(oidcDiscoveryHandler));

router.get(
  OAUTH_ROUTE_PATHS.ORG_CLIENT_PROVIDERS,
  asyncHandler(listOrganizationOauthProvidersHandler),
);

router.get(
  OAUTH_ROUTE_PATHS.ORG_CLIENT_START,
  asyncHandler(organizationOauthStartHandler),
);

router.get(
  OAUTH_ROUTE_PATHS.ORG_CLIENT_CALLBACK,
  asyncHandler(organizationOauthCallbackHandler),
);

router.post(
  OAUTH_ROUTE_PATHS.ORG_CLIENT_CONFIRM,
  asyncHandler(confirmOrganizationOauthChallengeHandler),
);

router.get(
  OAUTH_ROUTE_PATHS.GOOGLE,
  asyncHandler((req, res) => {
    req.params.provider = OAUTH_PROVIDERS.GOOGLE;
    return oauthStartHandler(req, res);
  }),
);

router.get(
  OAUTH_ROUTE_PATHS.GOOGLE_CALLBACK,
  asyncHandler((req, res) => {
    req.params.provider = OAUTH_PROVIDERS.GOOGLE;
    return oauthCallbackHandler(req, res);
  }),
);

router.get(
  OAUTH_ROUTE_PATHS.GITHUB,
  asyncHandler((req, res) => {
    req.params.provider = OAUTH_PROVIDERS.GITHUB;
    return oauthStartHandler(req, res);
  }),
);

router.get(
  OAUTH_ROUTE_PATHS.GITHUB_CALLBACK,
  asyncHandler((req, res) => {
    req.params.provider = OAUTH_PROVIDERS.GITHUB;
    return oauthCallbackHandler(req, res);
  }),
);

export default router;
