import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import { jwtDecrypt, EncryptJWT } from "jose";
import fetch from "node-fetch";
import { getAppConfig } from "../_shared/config.js";

function handleCors(req, res) {
  const origin = req.headers.origin;
  const allowed = (process.env.ALLOWED_ORIGIN||"").split(",").map(s=>s.trim()).filter(Boolean);
  let ok = origin && allowed.includes(origin);
  if (!ok && origin) ok = allowed.some(a => a.startsWith("*.") && origin.endsWith(a.slice(1)));
  if (ok) res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary","Origin");
  res.setHeader("Access-Control-Allow-Credentials","true");
  res.setHeader("Access-Control-Allow-Headers","Content-Type");
  res.setHeader("Access-Control-Allow-Methods","GET, OPTIONS");
  if (req.method === "OPTIONS") { res.status(200).end(); return true; }
  return false;
}

export default async function handler(req, res) {
  if (handleCors(req, res)) return;
  if (req.method !== "GET") { res.status(405).json({error:"Method not allowed"}); return; }

  const { COOKIE_SECRET } = process.env;
  if (!COOKIE_SECRET) { res.status(500).json({error:"COOKIE_SECRET missing"}); return; }

  const cookies = parseCookie(req.headers.cookie || "");
  const jwe = cookies.oauth_token;
  if (!jwe) { res.status(401).json({error:"Not authenticated"}); return; }

  const secret = Buffer.from(COOKIE_SECRET, "base64");
  let { payload } = await jwtDecrypt(jwe, secret);

  const r = getAppConfig(payload.app);
  if (!r.ok) { res.status(500).json({error:r.error}); return; }
  const cfg = r.cfg;

  const now = Math.floor(Date.now()/1000);
  const needsRefresh = (payload.expiresAt || 0) - now < 60;

  if (needsRefresh && payload.refreshToken) {
    const tokenUrl = `https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps-api/apps/${cfg.CONTENTSTACK_APP_UID}/tokens`;
    const resp = await fetch(tokenUrl, {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({
        grant_type:"refresh_token",
        refresh_token: payload.refreshToken,
        client_id: cfg.OAUTH_CLIENT_ID,
        client_secret: cfg.OAUTH_CLIENT_SECRET
      })
    });
    const json = await resp.json();
    if (!resp.ok) { res.status(resp.status).json({error: json.error || "Failed to refresh token"}); return; }

    payload = {
      ...payload,
      accessToken: json.access_token || payload.accessToken,
      expiresAt: now + (json.expires_in || 3600),
      tokenType: json.token_type || payload.tokenType,
      scope: json.scope || payload.scope,
      refreshToken: json.refresh_token || payload.refreshToken,
      obtainedAt: now
    };

    const newJwe = await new EncryptJWT(payload)
      .setProtectedHeader({alg:"dir",enc:"A256GCM"})
      .setIssuedAt().setExpirationTime("30d").encrypt(secret);

    res.setHeader("Set-Cookie", serializeCookie("oauth_token", newJwe, {
      httpOnly:true, secure:true, sameSite:"lax", path:"/", maxAge: 30*24*60*60
    }));
  }

  res.status(200).json({
    app: payload.app,
    tokenType: payload.tokenType || "Bearer",
    accessToken: payload.accessToken,
    expiresAt: payload.expiresAt,
    scope: payload.scope || null
  });
}