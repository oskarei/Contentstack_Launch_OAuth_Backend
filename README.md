# Contentstack Launch OAuth Backend

A lightweight Node.js backend for handling secure OAuth authentication (Authorization Code + PKCE) with **Contentstack** apps or custom fields.

Runs entirely as **serverless functions on Contentstack Launch**, keeping your `client_secret` and tokens safely on the backend.

---

## 🚀 Features

- Full **OAuth 2.0 Authorization Code + PKCE** flow  
- Secure token exchange & storage (AES-256 encrypted HttpOnly cookies)  
- `/auth/start`, `/auth/callback`, `/auth/token`, `/auth/logout` endpoints  
- Automatic token refresh using `refresh_token`  
- Multi-origin CORS support (comma-separated `ALLOWED_ORIGIN` list)  
- Environment-variable configuration for Launch and local development  

---

## 🧩 How It Works

1. `/auth/start` redirects the user to Contentstack’s OAuth authorization screen.  
2. `/auth/callback` exchanges the returned `code` for tokens using your `client_secret`.  
3. Tokens are encrypted and stored in an HttpOnly cookie.  
4. `/auth/token` returns a fresh access token (auto-refresh if needed).  
5. `/auth/logout` clears cookies and disconnects the session.

---

## ⚙️ Environment Variables

| Variable | Description |
|-----------|-------------|
| `CONTENTSTACK_REGION` | Region prefix (`eu`, `us`, `az`, etc.) |
| `CONTENTSTACK_APP_UID` | Your app UID from Developer Hub |
| `OAUTH_CLIENT_ID` | App client ID |
| `OAUTH_CLIENT_SECRET` | App client secret |
| `OAUTH_REDIRECT_URI` | Must match `/auth/callback` route |
| `OAUTH_SCOPE` | Space-separated OAuth scopes |
| `COOKIE_SECRET` | Base64-encoded 32-byte key (`openssl rand -base64 32`) |
| `ALLOWED_ORIGIN` | Comma-separated list of allowed origins |

---

## 🧠 Example `.env.local`

```bash
CONTENTSTACK_REGION=eu
CONTENTSTACK_APP_UID=blt12345abcde
OAUTH_CLIENT_ID=yourClientId
OAUTH_CLIENT_SECRET=yourClientSecret
OAUTH_REDIRECT_URI=http://localhost:8787/auth/callback
OAUTH_SCOPE=user:read cm.entries.management:read cm.entry:write
COOKIE_SECRET=t7JbI4cvn+xJQqsdzSxQWvlHpHbHsDls6Z0iEktT/YQ=
ALLOWED_ORIGIN=http://localhost:3000,https://app.contentstack.com,https://eu-app.contentstack.com
