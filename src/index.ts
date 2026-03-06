/**
 * Email Unsubscriber Open OAuth Service
 *
 * A transparent, open-source OAuth token exchange proxy.
 * This service exchanges authorization codes with OAuth providers (Google, Microsoft)
 * on behalf of the client webapp, providing full visibility into the token exchange process.
 *
 * Deployment:
 * - Production worker: auth.email-unsubscriber.com/api/* (deployed from main branch)
 * - Staging worker: auth.email-unsubscriber.com/api-staging/* (deployed from staging branch)
 *
 * @see https://github.com/xplorya/email-unsubscriber-open-oauth
 */

import type { Env, TokenExchangeRequest, TokenExchangeResponse } from '../lib/types';
import { validateRedirectUri, isAllowedOrigin } from '../lib/validation';
import { exchangeCodeGoogle } from '../lib/oauth-google';
import { exchangeCodeMicrosoft } from '../lib/oauth-microsoft';
import { fetchUserInfo, UserInfoError } from '../lib/user-info';


export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin');

    // Strip route prefix (/api or /api-staging) from pathname
    // CF routes include the prefix in the path, but we want clean route matching
    const pathname = stripRoutePrefix(url.pathname);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return handleCors(origin, env.ALLOWED_REDIRECT_URIS);
    }

    // Health check endpoint
    if (pathname === '/health') {
      return jsonResponse({ status: 'ok', environment: env.ENVIRONMENT }, 200, origin, env.ALLOWED_REDIRECT_URIS);
    }

    // Token exchange endpoint
    if (pathname === '/oauth/token' && request.method === 'POST') {
      return handleTokenExchange(request, env, origin);
    }

    // 404 for unknown routes
    return jsonResponse({ error: 'Not found' }, 404, origin, env.ALLOWED_REDIRECT_URIS);
  },
};

/**
 * Strips the route prefix (/api or /api-staging) from the pathname.
 * This allows clean route matching regardless of which CF route is used.
 */
function stripRoutePrefix(pathname: string): string {
  if (pathname.startsWith('/api-staging')) {
    return pathname.slice('/api-staging'.length) || '/';
  }
  if (pathname.startsWith('/api')) {
    return pathname.slice('/api'.length) || '/';
  }
  return pathname;
}

/**
 * Handles the OAuth token exchange request.
 */
async function handleTokenExchange(request: Request, env: Env, origin: string | null): Promise<Response> {
  const allowedUris = env.ALLOWED_REDIRECT_URIS;
  let req: TokenExchangeRequest;

  // Parse request body
  try {
    req = await request.json();
  } catch {
    return errorResponse('Invalid request body', 400, origin, allowedUris);
  }

  // Validate required fields
  if (!req.code) {
    return errorResponse('code is required', 400, origin, allowedUris);
  }
  if (!req.redirect_uri) {
    return errorResponse('redirect_uri is required', 400, origin, allowedUris);
  }
  if (!req.provider) {
    return errorResponse('provider is required', 400, origin, allowedUris);
  }

  // Validate redirect_uri against allowlist to prevent token theft
  if (!validateRedirectUri(req.redirect_uri, allowedUris)) {
    console.error(`[${env.ENVIRONMENT}] Invalid redirect_uri attempted: ${req.redirect_uri}`);
    return errorResponse('invalid redirect_uri', 400, origin, allowedUris);
  }

  try {
    // Exchange code for tokens based on provider
    let tokenResp: TokenExchangeResponse;
    const provider = req.provider.toLowerCase();

    switch (provider) {
      case 'google':
        tokenResp = await exchangeCodeGoogle(req, env);
        break;
      case 'outlook':
      case 'microsoft':
        tokenResp = await exchangeCodeMicrosoft(req, env);
        break;
      default:
        return errorResponse(`Unsupported OAuth provider: ${provider}`, 400, origin, allowedUris);
    }

    // Validate id_token is present (required for user info fetch)
    if (!tokenResp.id_token) {
      console.error(`[${env.ENVIRONMENT}] id_token missing from provider response`);
      return errorResponse('Token exchange failed', 400, origin, allowedUris);
    }

    // Fetch user info from backend and attach to response
    // CRITICAL: If this fails, the entire OAuth flow fails (no graceful degradation)
    try {
      const referralCode = request.headers.get('x-referral-code') || undefined;
      const userInfo = await fetchUserInfo(tokenResp.id_token, env, referralCode);
      tokenResp.user_info = userInfo;
    } catch (err) {
      console.error(`[${env.ENVIRONMENT}] Failed to fetch user info:`, err);

      // Proxy the intact Backend response to the client
      if (err instanceof UserInfoError) {
        return jsonResponse(err.body, err.status, origin, allowedUris);
      }

      return errorResponse('Failed to retrieve user information', 500, origin, allowedUris);
    }

    return jsonResponse(tokenResp, 200, origin, allowedUris);
  } catch (err) {
    console.error(`[${env.ENVIRONMENT}] OAuth token exchange error:`, err);
    return errorResponse('Token exchange failed', 400, origin, allowedUris);
  }
}

/**
 * Creates a JSON response with CORS headers for allowed origins only.
 * If origin is not in allowlist, CORS headers are omitted.
 */
function jsonResponse(
  data: unknown,
  status: number,
  origin: string | null,
  allowedUris?: string
): Response {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };

  // Only add CORS headers if origin is allowed
  if (origin && allowedUris && isAllowedOrigin(origin, allowedUris)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Referral-Code';
  }

  return new Response(JSON.stringify(data), { status, headers });
}

/**
 * Creates an error response with CORS headers for allowed origins.
 * This allows the browser to read the actual error message.
 */
function errorResponse(
  message: string,
  status: number,
  origin: string | null,
  allowedUris: string
): Response {
  return jsonResponse({ error: message }, status, origin, allowedUris);
}

/**
 * Handles CORS preflight requests for allowed origins only.
 */
function handleCors(origin: string | null, allowedUris: string): Response {
  const headers: HeadersInit = {};

  // Only add CORS headers if origin is allowed
  if (origin && isAllowedOrigin(origin, allowedUris)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type, X-Referral-Code';
    headers['Access-Control-Max-Age'] = '86400';
  }

  return new Response(null, { status: 204, headers });
}
