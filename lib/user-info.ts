import type { Env } from './types';

/**
 * Structured error for user info fetch failures.
 * Carries the HTTP status and parsed response body so callers can
 * forward backend errors (e.g. 403 access denied) transparently.
 */
export class UserInfoError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown, message: string) {
    super(message);
    this.name = 'UserInfoError';
    this.status = status;
    this.body = body;
  }
}

/**
 * Fetches user info from the backend user info service using the ID token.
 * Returns the raw JSON response to keep the OAuth service schema-agnostic.
 *
 * @param idToken - The ID token from the OAuth provider
 * @param env - Worker environment bindings
 * @param referralCode - Optional referral code to forward to the backend
 * @returns Raw user info JSON from the backend
 * @throws {UserInfoError} if the backend returns a non-2xx status (preserves status + body)
 * @throws {Error} if the response cannot be parsed
 */
export async function fetchUserInfo(idToken: string, env: Env, referralCode?: string): Promise<unknown> {
  const userInfoUrl = `${env.USER_INFO_SERVICE_URL}/user/info`;

  const headers: Record<string, string> = {
    'x-auth-token': idToken,
  };

  if (referralCode) {
    headers['x-referral-code'] = referralCode;
  }

  const response = await fetch(userInfoUrl, {
    method: 'GET',
    headers,
  });

  const body = await response.text();

  // For non-2xx status, throw a structured error preserving the HTTP status and body
  if (!response.ok) {
    throw new UserInfoError(
      response.status,
      response.body,
      `User info request failed with status ${response.status}: ${body}`
    );
  }

  try {
    return JSON.parse(body);
  } catch {
    throw new Error(`Failed to parse user info response: ${body}`);
  }
}

/**
 * Extracts the email claim from an ID token JWT.
 * This performs base64 decoding of the payload without signature validation
 * since the token comes directly from the OAuth provider's token endpoint.
 * Supports both Google and Microsoft token formats.
 *
 * @param idToken - The ID token JWT string
 * @returns The email address from the token
 * @throws Error if email cannot be extracted
 */
export function extractEmailFromIdToken(idToken: string): string {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  // Decode the payload (middle part)
  // Handle base64url encoding (replace - with + and _ with /)
  const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if necessary (base64 requires length to be multiple of 4)
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const payload = atob(padded);

  // Parse JSON to extract email
  const claims = JSON.parse(payload);

  // Try "email" claim first (works for both Google and Microsoft)
  if (claims.email && typeof claims.email === 'string') {
    return claims.email;
  }

  // For Microsoft tokens, try alternative claims
  // "preferred_username" often contains email for personal accounts
  if (claims.preferred_username && typeof claims.preferred_username === 'string') {
    if (claims.preferred_username.includes('@')) {
      return claims.preferred_username;
    }
  }

  // "upn" (User Principal Name) is common in work/school accounts
  if (claims.upn && typeof claims.upn === 'string') {
    if (claims.upn.includes('@')) {
      return claims.upn;
    }
  }

  throw new Error('Email claim not found in token');
}
