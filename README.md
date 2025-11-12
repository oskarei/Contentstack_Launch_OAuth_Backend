# Contentstack Launch OAuth Backend (Multi-App)

A lightweight Node.js backend for secure OAuth authentication (Authorization Code + PKCE) with **Contentstack** apps or custom fields.

Runs as **serverless functions on Contentstack Launch**, now supporting multiple app configurations (e.g. `?app=interstack`) using label-prefixed environment variables.

---

## 🚀 Features

- Full **OAuth 2.0 Authorization Code + PKCE** flow  
- Supports **multiple apps** via `APP_LABELS` and query `?app=`  
- Secure token exchange & storage (AES-256 encrypted HttpOnly cookies)  
- `/auth/start`, `/auth/callback`, `/auth/token`, `/auth/logout` endpoints  
- Automatic token refresh with `refresh_token`  
- Multi-origin CORS with comma-separated `ALLOWED_ORIGIN`  
- Simple environment-based configuration for Launch + local dev  

---

## 🧩 How It Works

1. `/auth/start?app=interstack` redirects to Contentstack’s OAuth screen.  
2. `/auth/callback` exchanges the `code` for tokens using app-specific secrets.  
3. Tokens are encrypted and stored as HttpOnly cookies.  
4. `/auth/token` returns a valid access token (auto-refreshes).  
5. `/auth/logout` clears cookies.

---

## ⚙️ Environment Variables

| Variable | Description |
|-----------|-------------|
| `APP_LABELS` | Comma-separated app labels (e.g. `interstack,crm`) |
| `<LABEL>_CONTENTSTACK_REGION` | Region prefix (`eu`, `us`, `az`, etc.) |
| `<LABEL>_CONTENTSTACK_APP_UID` | App UID from Developer Hub |
| `<LABEL>_OAUTH_CLIENT_ID` | OAuth client ID |
| `<LABEL>_OAUTH_CLIENT_SECRET` | OAuth client secret |
| `<LABEL>_OAUTH_REDIRECT_URI` | Must point to `/auth/callback` |
| `<LABEL>_OAUTH_SCOPE` | Space-separated scopes |
| `COOKIE_SECRET` | Base64 32-byte key (`openssl rand -base64 32`) |
| `ALLOWED_ORIGIN` | Comma-separated trusted origins |

---

## 🧠 Example `.env.local`

```bash
APP_LABELS=interstack

# shared
ALLOWED_ORIGIN=http://localhost:8787,https://app.contentstack.com,https://eu-app.contentstack.com
COOKIE_SECRET=t7JbI4cvn+xJQqsdzSxQWvlHpHbHsDls6Z0iEktT/YQ=

# Interstack app
INTERSTACK_CONTENTSTACK_REGION=eu
INTERSTACK_CONTENTSTACK_APP_UID=bltInterstackUid
INTERSTACK_OAUTH_CLIENT_ID=interstackClientId
INTERSTACK_OAUTH_CLIENT_SECRET=interstackClientSecret
INTERSTACK_OAUTH_REDIRECT_URI=http://localhost:8787/auth/callback
INTERSTACK_OAUTH_SCOPE=cm.entry:read cm.entry:write cm.entry:publish cm.assets.management:read cm.assets.management:write cm.assets:download cm.entries.management:read cm.entries.management:write