import { Router } from "express";
import asyncHandler from "../../utils/async-handler.js";
import { oauthCallbackHandler, oauthStartHandler } from "./oauth.controller.js";
import { OAUTH_PROVIDERS, OAUTH_ROUTE_PATHS } from "./oauth.constants.js";

const router = Router();

/**
 * @openapi
 * /api/oauth/google:
 *   get:
 *     summary: Start Google OAuth authorization flow
 *     tags: [OAuth]
 *     responses:
 *       302:
 *         description: Redirect to Google authorization page
 */

router.get(
  OAUTH_ROUTE_PATHS.GOOGLE,
  asyncHandler((req, res) => {
    req.params.provider = OAUTH_PROVIDERS.GOOGLE;
    return oauthStartHandler(req, res);
  }),
);

/**
 * @openapi
 * /api/oauth/google/callback:
 *   get:
 *     summary: Handle Google OAuth callback and create authenticated session
 *     tags: [OAuth]
 *     parameters:
 *       - in: query
 *         name: code
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       302:
 *         description: Sets auth cookies and redirects to frontend
 *       400:
 *         description: Missing or invalid authorization code
 */

router.get(
  OAUTH_ROUTE_PATHS.GOOGLE_CALLBACK,
  asyncHandler((req, res) => {
    req.params.provider = OAUTH_PROVIDERS.GOOGLE;
    return oauthCallbackHandler(req, res);
  }),
);

/**
 * @openapi
 * /api/oauth/github:
 *   get:
 *     summary: Start GitHub OAuth authorization flow
 *     tags: [OAuth]
 *     responses:
 *       302:
 *         description: Redirect to GitHub authorization page
 */

router.get(
  OAUTH_ROUTE_PATHS.GITHUB,
  asyncHandler((req, res) => {
    req.params.provider = OAUTH_PROVIDERS.GITHUB;
    return oauthStartHandler(req, res);
  }),
);

/**
 * @openapi
 * /api/oauth/github/callback:
 *   get:
 *     summary: Handle GitHub OAuth callback and create authenticated session
 *     tags: [OAuth]
 *     parameters:
 *       - in: query
 *         name: code
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       302:
 *         description: Sets auth cookies and redirects to frontend
 *       400:
 *         description: Missing or invalid authorization code
 */

router.get(
  OAUTH_ROUTE_PATHS.GITHUB_CALLBACK,
  asyncHandler((req, res) => {
    req.params.provider = OAUTH_PROVIDERS.GITHUB;
    return oauthCallbackHandler(req, res);
  }),
);

export default router;
