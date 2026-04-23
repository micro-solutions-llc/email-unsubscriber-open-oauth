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
 *w
 * @see https://github.com/micro-solutions-llc/email-unsubscriber-open-oauth
 */

import type { Env, TokenExchangeRequest, TokenExchangeResponse, OAuthTokens } from '../lib/types';
import { validateRedirectUri, isAllowedOrigin } from '../lib/validation';
import { exchangeCodeGoogle } from '../lib/oauth-google';
import { exchangeCodeMicrosoft } from '../lib/oauth-microsoft';
import { fetchUserInfo } from '../lib/user-info';


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
 *
 * Acts as a transparent proxy: exchanges the auth code with the OAuth provider,
 * then calls the backend /user/info and returns whatever the backend responded
 * with an `oauth` object appended containing the token fields.
 *
 * Response shapes:
 * - Backend reachable: { ...backendBody, oauth: { tokens } } with backend's HTTP status
 * - Backend unreachable: { oauth: { tokens }, error_info: { error, error_description } } with 502
 * - OAuth provider error: { error_info: { error, error_description } } with 400
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

  // --- Phase 1: Exchange code for tokens with the OAuth provider ---
  let tokenResp: TokenExchangeResponse;
  try {
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
        return jsonResponse(
          { error_info: { error: 'unsupported_provider', error_description: `Unsupported OAuth provider: ${provider}` } },
          400,
          origin,
          allowedUris,
        );
    }
  } catch (err) {
    // OAuth provider error — tokens were never obtained
    console.error(`[${env.ENVIRONMENT}] OAuth token exchange error:`, err);
    return jsonResponse(
      { error_info: { error: 'oauth_exchange_failed', error_description: 'Token exchange failed' } },
      400,
      origin,
      allowedUris,
    );
  }

  // Build the oauth object with only token-related fields
  const oauth: OAuthTokens = {
    access_token: tokenResp.access_token,
    id_token: tokenResp.id_token!,
    expires_in: tokenResp.expires_in,
    scope: tokenResp.scope,
    token_type: tokenResp.token_type,
  };

  // --- Phase 2: Call backend /user/info and forward its response transparently ---
  try {
    const referralCode = request.headers.get('x-referral-code') || undefined;
    const result = await fetchUserInfo(tokenResp.id_token!, env, referralCode);

    // Merge backend response body with the oauth object, forward backend's status code
    const backendBody = (typeof result.body === 'object' && result.body !== null) ? result.body : {};
    return jsonResponse(
      { ...backendBody, oauth },
      result.status,
      origin,
      allowedUris,
    );
  } catch (err) {
    // Network/parse error reaching the backend — fetch itself threw
    console.error(`[${env.ENVIRONMENT}] Failed to reach user info service:`, err);
    return jsonResponse(
      { oauth, error_info: { error: 'user_info_unavailable', error_description: 'Failed to reach user info service' } },
      502,
      origin,
      allowedUris,
    );
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
