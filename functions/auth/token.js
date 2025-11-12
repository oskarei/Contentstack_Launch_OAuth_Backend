import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import { jwtDecrypt, EncryptJWT } from "jose";
import fetch from "node-fetch";
import { getAppConfig } from "../_shared/config.js";

function handleCors(req, res) {
  const origin = req.headers.origin;
  const allowed = (process.env.ALLOWED_ORIGIN || "").split(",").map(o => o.trim()).filter(Boolean);

  // direct or wildcard-suffix match (e.g., *.contentstack.com)
  let ok = origin && allowed.includes(origin);
  if (!ok && origin) {
    ok = allowed.some(a => a.startsWith("*.") && origin.endsWith(a.substring(1)));
  }
  if (ok) res.setHeader("Access-Control-Allow-Origin", origin);

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") {
    res.statusCode = 200; res.end(); return true;
  }
  return false;
}

function json(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}

async function handler(req, res) {
  if (handleCors(req, res)) return;
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });

  const { COOKIE_SECRET } = process.env;
  if (!COOKIE_SECRET) return json(res, 500, { error: "COOKIE_SECRET missing" });

  const cookies = parseCookie(req.headers.cookie || "");
  const jwe = cookies.oauth_token;
  if (!jwe) return json(res, 401, { error: "Not authenticated" });

  const secret = Buffer.from(COOKIE_SECRET, "base64");
  let { payload } = await jwtDecrypt(jwe, secret);

  // Resolve the app config from the payload label
  const cfgRes = getAppConfig(payload.app);
  if (!cfgRes.ok) return json(res, 500, { error: cfgRes.error });
  const { cfg } = cfgRes;

  const now = Math.floor(Date.now() / 1000);
  const needsRefresh = (payload.expiresAt || 0) - now < 60;

  if (needsRefresh && payload.refreshToken) {
    const tokenUrl = `https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps-api/apps/${cfg.CONTENTSTACK_APP_UID}/tokens`;
    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        grant_type: "refresh_token",
        refresh_token: payload.refreshToken,
        client_id: cfg.OAUTH_CLIENT_ID,
        client_secret: cfg.OAUTH_CLIENT_SECRET
      })
    });

    const jsonBody = await resp.json();
    if (!resp.ok) {
      return json(res, resp.status, { error: jsonBody.error || "Failed to refresh token" });
    }

    payload = {
      ...payload,
      accessToken: jsonBody.access_token || payload.accessToken,
      expiresAt: now + (jsonBody.expires_in || 3600),
      tokenType: jsonBody.token_type || payload.tokenType,
      scope: jsonBody.scope || payload.scope,
      refreshToken: jsonBody.refresh_token || payload.refreshToken,
      obtainedAt: now
    };

    const newJwe = await new EncryptJWT(payload)
      .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
      .setIssuedAt()
      .setExpirationTime("30d")
      .encrypt(secret);

    const tokenCookie = serializeCookie("oauth_token", newJwe, {
      httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 30 * 24 * 60 * 60
    });
    res.setHeader("Set-Cookie", tokenCookie);
  }

  return json(res, 200, {
    app: payload.app,
    tokenType: payload.tokenType || "Bearer",
    accessToken: payload.accessToken,
    expiresAt: payload.expiresAt,
    scope: payload.scope || null
  });
}

export default handler;