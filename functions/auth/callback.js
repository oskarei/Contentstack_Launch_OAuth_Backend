import { serialize as serializeCookie, parse as parseCookie } from "cookie";
import fetch from "node-fetch";
import { EncryptJWT } from "jose";
import { getAppConfig, defaultInstallLabel } from "../_shared/config.js";

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}

function formEncode(obj) {
  return new URLSearchParams(
    Object.entries(obj).filter(([, v]) => v !== undefined && v !== null)
  ).toString();
}

export default async function handler(req, res) {
  if (req.method !== "GET") return sendJson(res, 405, { error: "Method not allowed" });

  const { COOKIE_SECRET } = process.env;
  if (!COOKIE_SECRET) return sendJson(res, 500, { error: "Missing COOKIE_SECRET" });

  const url = new URL(req.url, "http://local");
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  const installationUid = url.searchParams.get("installation_uid");
  const region = url.searchParams.get("region"); // optional from CS
  const appFromQuery = url.searchParams.get("app"); // optional

  // ──────────────────────────────────────────────────────────────
  // A) Developer Hub "Install" flow (no state/cookie, has installation_uid)
  // Exchange code → app token via {BASE_URL}/apps-api/token (form-encoded)
  // ──────────────────────────────────────────────────────────────
  if (installationUid && code && !returnedState) {
    const label = appFromQuery || defaultInstallLabel();
    if (!label) return sendJson(res, 500, { error: "No default app label configured (APP_LABELS is empty)" });

    const cfgRes = getAppConfig(label);
    if (!cfgRes.ok) return sendJson(res, 500, { error: cfgRes.error });
    const { cfg } = cfgRes;

    const tokenUrl = `https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps-api/token`;
    const body = formEncode({
      grant_type: "authorization_code",
      client_id: cfg.OAUTH_CLIENT_ID,
      client_secret: cfg.OAUTH_CLIENT_SECRET,
      redirect_uri: cfg.OAUTH_REDIRECT_URI,
      code
      // no PKCE for install handshake
    });

    const tokenResp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok) {
      return sendJson(res, tokenResp.status, { error: tokenJson.error_description || tokenJson.error || tokenJson });
    }

    // We don't set a user session cookie for install. Returning 200 lets install complete.
    return sendJson(res, 200, {
      ok: true,
      installation_uid: installationUid,
      region,
      app: label,
      authorization_type: tokenJson.authorization_type || "app"
    });
  }

  // ──────────────────────────────────────────────────────────────
  // B) Regular user OAuth flow (PKCE + state, requires pre_auth cookie)
  // ──────────────────────────────────────────────────────────────
  if (!code || !returnedState) return sendJson(res, 400, { error: "Missing code/state" });

  const cookies = parseCookie(req.headers.cookie || "");
  const preAuth = cookies.pre_auth ? JSON.parse(cookies.pre_auth) : null;
  if (!preAuth || preAuth.state !== returnedState) {
    return sendJson(res, 400, { error: "Invalid state" });
  }

  const cfgRes = getAppConfig(preAuth.app);
  if (!cfgRes.ok) return sendJson(res, 500, { error: cfgRes.error });
  const { cfg } = cfgRes;

  const tokenUrl = `https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps-api/token`;
  const body = formEncode({
    grant_type: "authorization_code",
    client_id: cfg.OAUTH_CLIENT_ID,
    client_secret: cfg.OAUTH_CLIENT_SECRET,   // allowed even with PKCE; see note
    redirect_uri: cfg.OAUTH_REDIRECT_URI,
    code,
    code_verifier: preAuth.codeVerifier       // PKCE parameter
  });

  const tokenResp = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const tokenJson = await tokenResp.json();
  if (!tokenResp.ok) {
    return sendJson(res, tokenResp.status, { error: tokenJson.error_description || tokenJson.error || tokenJson });
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    app: preAuth.app,
    accessToken: tokenJson.access_token,
    refreshToken: tokenJson.refresh_token,
    tokenType: tokenJson.token_type || "Bearer",
    scope: tokenJson.scope || cfg.OAUTH_SCOPE || null,
    organizationUid: tokenJson.organization_uid || undefined,
    location: tokenJson.location || undefined,
    authorizationType: tokenJson.authorization_type || "user",
    expiresAt: now + (tokenJson.expires_in || 3600),
    obtainedAt: now
  };

  const secret = Buffer.from(COOKIE_SECRET, "base64");
  const jwe = await new EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime("30d")
    .encrypt(secret);

  // token cookie
  const tokenCookie = serializeCookie("oauth_token", jwe, {
    httpOnly: true,
    secure: true,
    sameSite: "none",   // ⬅️ was "lax"
    path: "/",
    maxAge: 30 * 24 * 60 * 60
  });
  const clearPre = serializeCookie("pre_auth", "", {
    httpOnly: true,
    secure: true,
    sameSite: "none",   // ⬅️ was "lax"
    path: "/",
    maxAge: 0
  });

  res.setHeader("Set-Cookie", [tokenCookie, clearPre]);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html><html><body>
    <script>
      if (window.opener) { try { window.opener.postMessage({ type: 'oauth:complete' }, '*'); } catch (e) {} window.close(); }
      else { location.replace('/auth/success'); }
    </script>
    Success. You can close this window.
  </body></html>`);
}