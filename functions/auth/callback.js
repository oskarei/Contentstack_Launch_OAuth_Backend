import { serialize as serializeCookie, parse as parseCookie } from "cookie";
import fetch from "node-fetch";
import { EncryptJWT } from "jose";
import { getAppConfig, defaultInstallLabel } from "../_shared/config.js";

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
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
  const appFromQuery = url.searchParams.get("app"); // if you ever pass it

  // ─────────────────────────────────────────────────────────────────────────────
  // A) Developer Hub "Install" flow:
  // Contentstack calls redirect_uri with ?code=...&installation_uid=... (no state/cookie)
  // We must accept, exchange code → tokens, and return 200 so install succeeds.
  // Uses the first APP_LABELS entry as the app label (or appFromQuery if you pass one).
  // ─────────────────────────────────────────────────────────────────────────────
  if (installationUid && code && !returnedState) {
    const label = appFromQuery || defaultInstallLabel();
    if (!label) return sendJson(res, 500, { error: "No default app label configured (APP_LABELS is empty)" });

    const cfgRes = getAppConfig(label);
    if (!cfgRes.ok) return sendJson(res, 500, { error: cfgRes.error });
    const { cfg } = cfgRes;

    const tokenUrl = `https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps-api/apps/${cfg.CONTENTSTACK_APP_UID}/tokens`;
    const tokenResp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "authorization_code",
        code,
        redirect_uri: cfg.OAUTH_REDIRECT_URI,
        client_id: cfg.OAUTH_CLIENT_ID,
        client_secret: cfg.OAUTH_CLIENT_SECRET
        // no PKCE verifier for install handshake
      })
    });

    const tokenJson = await tokenResp.json();
    if (!tokenResp.ok) {
      return sendJson(res, tokenResp.status, { error: tokenJson.error_description || tokenJson.error || tokenJson });
    }

    // For install we don't need to set a user session cookie; just return OK.
    // (If you want to persist app-level tokens server-side, do it here.)
    return sendJson(res, 200, {
      ok: true,
      installation_uid: installationUid,
      region,
      app: label
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // B) Regular user OAuth flow (PKCE + state, requires pre_auth cookie)
  // ─────────────────────────────────────────────────────────────────────────────
  if (!code || !returnedState) return sendJson(res, 400, { error: "Missing code/state" });

  const cookies = parseCookie(req.headers.cookie || "");
  const preAuth = cookies.pre_auth ? JSON.parse(cookies.pre_auth) : null;
  if (!preAuth || preAuth.state !== returnedState) {
    return sendJson(res, 400, { error: "Invalid state" });
  }

  const cfgRes = getAppConfig(preAuth.app);
  if (!cfgRes.ok) return sendJson(res, 500, { error: cfgRes.error });
  const { cfg } = cfgRes;

  const tokenUrl = `https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps-api/apps/${cfg.CONTENTSTACK_APP_UID}/tokens`;
  const tokenResp = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      code,
      redirect_uri: cfg.OAUTH_REDIRECT_URI,
      client_id: cfg.OAUTH_CLIENT_ID,
      client_secret: cfg.OAUTH_CLIENT_SECRET,
      code_verifier: preAuth.codeVerifier
    })
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
    expiresAt: now + (tokenJson.expires_in || 3600),
    obtainedAt: now
  };

  const secret = Buffer.from(COOKIE_SECRET, "base64");
  const jwe = await new EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime("30d")
    .encrypt(secret);

  const tokenCookie = serializeCookie("oauth_token", jwe, {
    httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 30 * 24 * 60 * 60
  });
  const clearPre = serializeCookie("pre_auth", "", {
    httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 0
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