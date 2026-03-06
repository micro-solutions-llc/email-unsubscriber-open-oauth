# Email Unsubscriber Open OAuth

A transparent, open-source OAuth token exchange proxy for [Email Unsubscriber](https://email-unsubscriber.com).

## Why Open Source?

This service handles OAuth token exchange between your browser and OAuth providers (Google, Microsoft). By open-sourcing this component, we provide full transparency into:

- What data is exchanged with OAuth providers
- How your tokens are handled
- That no tokens are stored or logged

You can audit the code yourself and verify that your credentials are handled securely.

## Architecture

```
┌─────────┐      ┌─────────────────────┐      ┌─────────────────┐
│  Your   │ ───► │  This OAuth Proxy   │ ───► │ Google/Microsoft│
│ Browser │      │   (Cloudflare)      │      │   OAuth APIs    │
└─────────┘      └──────────┬──────────┘      └─────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ Email Unsub   │
                    │   Backend     │
                    └───────────────┘
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/oauth/token` | Exchange authorization code for tokens |
| `GET` | `/health` | Health check |

### POST /oauth/token

Request body:
```json
{
  "code": "authorization_code_from_provider",
  "redirect_uri": "https://app.email-unsubscriber.com/",
  "code_verifier": "pkce_code_verifier_if_used",
  "provider": "google"
}
```

Response:
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "...",
  "refresh_token": "...",
  "id_token": "...",
  "user_info": { ... }
}
```

## Local Development

### Prerequisites

- Node.js 18+
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### Setup

```bash
# Install dependencies
npm install

# Create a .dev.vars file for local secrets
cat > .dev.vars << EOF
GOOGLE_OAUTH_CLIENT_ID=your_google_client_id
GOOGLE_OAUTH_CLIENT_SECRET=your_google_client_secret
MICROSOFT_OAUTH_CLIENT_ID=your_microsoft_client_id
MICROSOFT_OAUTH_CLIENT_SECRET=your_microsoft_client_secret
EOF

# Run locally
npm run dev
```

The worker will be available at `http://localhost:8787`.

### Running with the full stack

```bash
# Terminal 1: OAuth service
cd services/oauth && npm run dev

# Terminal 2: Go backend
go run .

# Terminal 3: Webapp
cd webapp && npm run dev
```

## Deployment

### Cloudflare Workers

This service deploys as **two separate workers** for environment isolation:

| Environment | Worker Name | Route | Branch |
|-------------|-------------|-------|--------|
| Production | `email-unsubscriber-oauth` | `auth.email-unsubscriber.com/api/*` | `main` |
| Staging | `email-unsubscriber-oauth-staging` | `auth.email-unsubscriber.com/api-staging/*` | `staging` |

#### 1. Set up secrets

```bash
# Production secrets
wrangler secret put GOOGLE_OAUTH_CLIENT_ID
wrangler secret put GOOGLE_OAUTH_CLIENT_SECRET
wrangler secret put MICROSOFT_OAUTH_CLIENT_ID
wrangler secret put MICROSOFT_OAUTH_CLIENT_SECRET

# Staging secrets
wrangler secret put GOOGLE_OAUTH_CLIENT_ID --env staging
wrangler secret put GOOGLE_OAUTH_CLIENT_SECRET --env staging
wrangler secret put MICROSOFT_OAUTH_CLIENT_ID --env staging
wrangler secret put MICROSOFT_OAUTH_CLIENT_SECRET --env staging
```

#### 2. Set up routes (Cloudflare Dashboard)

Go to **Workers & Pages → your domain → Routes** and add:

| Route | Worker |
|-------|--------|
| `auth.email-unsubscriber.com/api/*` | `email-unsubscriber-oauth` |
| `auth.email-unsubscriber.com/api-staging/*` | `email-unsubscriber-oauth-staging` |

#### 3. Manual deployment

```bash
# Deploy to production
npm run deploy

# Deploy to staging
npm run deploy:staging
```

#### 4. Automatic deployment (Git integration)

Connect this repository to Cloudflare Workers:

1. Go to Cloudflare Dashboard → Workers & Pages
2. Create a new Worker → Connect to Git
3. Select this repository
4. Configure build settings:
   - **Production branch:** `main` → deploys `email-unsubscriber-oauth`
   - **Staging branch:** `staging` → deploys with `--env staging`

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENVIRONMENT` | Environment name | `production` |
| `USER_INFO_SERVICE_URL` | Backend service URL | `https://api.email-unsubscriber.com/api` |
| `ALLOWED_REDIRECT_URIS` | Comma-separated allowed redirect URIs | See wrangler.toml |

### Secrets

| Secret | Description |
|--------|-------------|
| `GOOGLE_OAUTH_CLIENT_ID` | Google OAuth 2.0 client ID |
| `GOOGLE_OAUTH_CLIENT_SECRET` | Google OAuth 2.0 client secret |
| `MICROSOFT_OAUTH_CLIENT_ID` | Microsoft OAuth 2.0 client ID |
| `MICROSOFT_OAUTH_CLIENT_SECRET` | Microsoft OAuth 2.0 client secret |

## Security

- **Redirect URI validation**: Only whitelisted redirect URIs are accepted
- **No token storage**: Tokens are passed through, never stored
- **No logging of sensitive data**: Only errors are logged, never tokens
- **HTTPS only**: Enforced by Cloudflare Workers

## License

MIT License - see [LICENSE](LICENSE) for details.
