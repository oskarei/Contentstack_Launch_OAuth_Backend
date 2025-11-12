import { serialize as serializeCookie, parse as parseCookie } from "cookie";
import fetch from "node-fetch";
import { EncryptJWT } from "jose";
import { getAppConfig } from "../_shared/config.js";

function json(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}

async function handler(req, res) {
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });

  const { COOKIE_SECRET } = process.env;
  if (!COOKIE_SECRET) return json(res, 500, { error: "Missing COOKIE_SECRET" });

  const url = new URL(req.url, "http://local");
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  if (!code || !returnedState) return json(res, 400, { error: "Missing code/state" });

  const cookies = parseCookie(req.headers.cookie || "");
  const preAuth = cookies.pre_auth ? JSON.parse(cookies.pre_auth) : null;
  if (!preAuth || preAuth.state !== returnedState) return json(res, 400, { error: "Invalid state" });

  // Get per-app config from cookie
  const cfgRes = getAppConfig(preAuth.app);
  if (!cfgRes.ok) return json(res, 500, { error: cfgRes.error });
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
    return json(res, tokenResp.status, { error: tokenJson.error_description || tokenJson.error || tokenJson });
  }

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    app: preAuth.app, // persist label for refresh
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

export default handler;