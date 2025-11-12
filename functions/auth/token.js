import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import { jwtDecrypt, EncryptJWT } from "jose";
import fetch from "node-fetch";
import { getAppConfig } from "../_shared/config.js";

function handleCors(req, res) {
  const origin = req.headers.origin;
  const allowed = (process.env.ALLOWED_ORIGIN || "")
    .split(",").map(o => o.trim()).filter(Boolean);

  let ok = origin && allowed.includes(origin);
  if (!ok && origin) ok = allowed.some(a => a.startsWith("*.") && origin.endsWith(a.slice(1)));
  if (ok) res.setHeader("Access-Control-Allow-Origin", origin);

  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  if (req.method === "OPTIONS") { res.statusCode = 200; res.end(); return true; }
  return false;
}

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
  if (handleCors(req, res)) return;
  if (req.method !== "GET") return sendJson(res, 405, { error: "Method not allowed" });

  const { COOKIE_SECRET } = process.env;
  if (!COOKIE_SECRET) return sendJson(res, 500, { error: "COOKIE_SECRET missing" });

  const cookies = parseCookie(req.headers.cookie || "");
  const jwe = cookies.oauth_token;
  if (!jwe) return sendJson(res, 401, { error: "Not authenticated" });

  const secret = Buffer.from(COOKIE_SECRET, "base64");
  let { payload } = await jwtDecrypt(jwe, secret);

  const cfgRes = getAppConfig(payload.app);
  if (!cfgRes.ok) return sendJson(res, 500, { error: cfgRes.error });
  const { cfg } = cfgRes;

  const now = Math.floor(Date.now() / 1000);
  const needsRefresh = (payload.expiresAt || 0) - now < 60;

  if (needsRefresh && payload.refreshToken) {
    const tokenUrl = `https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps-api/token`;

    // If you enabled PKCE in the app, omit client_secret on refresh per docs.
    // We include it only if you set it; otherwise it's excluded.
    const body = formEncode({
      grant_type: "refresh_token",
      client_id: cfg.OAUTH_CLIENT_ID,
      redirect_uri: cfg.OAUTH_REDIRECT_URI,
      refresh_token: payload.refreshToken,
      // Optional – include only if you use client_secret in user flow:
      client_secret: cfg.OAUTH_CLIENT_SECRET || undefined
    });

    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });
    const json = await resp.json();
    if (!resp.ok) {
      return sendJson(res, resp.status, { error: json.error || "Failed to refresh token" });
    }

    payload = {
      ...payload,
      accessToken: json.access_token || payload.accessToken,
      expiresAt: now + (json.expires_in || 3600),
      tokenType: json.token_type || payload.tokenType,
      scope: json.scope || payload.scope,
      refreshToken: json.refresh_token || payload.refreshToken,
      location: json.location || payload.location,
      organizationUid: json.organization_uid || payload.organizationUid,
      obtainedAt: now
    };

    const newJwe = await new EncryptJWT(payload)
      .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
      .setIssuedAt()
      .setExpirationTime("30d")
      .encrypt(secret);

    res.setHeader("Set-Cookie", serializeCookie("oauth_token", newJwe, {
      httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 30 * 24 * 60 * 60
    }));
  }

  return sendJson(res, 200, {
    app: payload.app,
    tokenType: payload.tokenType || "Bearer",
    accessToken: payload.accessToken,
    expiresAt: payload.expiresAt,
    scope: payload.scope || null,
    location: payload.location || null,
    organizationUid: payload.organizationUid || null
  });
}