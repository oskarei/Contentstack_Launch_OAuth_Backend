# Contentstack_Oauth_Launch_Server
Secure Node.js backend for handling OAuth (Authorization Code + PKCE) with Contentstack apps and custom fields. Runs on Contentstack Launch, exchanges tokens server-side, encrypts them in HttpOnly cookies, and provides /auth/start, /auth/callback, /auth/token, and /auth/logout endpoints with CORS and env-based config.
