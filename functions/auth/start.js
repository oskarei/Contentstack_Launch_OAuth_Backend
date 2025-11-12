import { serialize as serializeCookie } from "cookie";
import crypto from "crypto";
import { resolveAppLabel, getAppConfig, listAppLabels } from "../_shared/config.js";

function base64Url(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function sha256Base64Url(input) {
  const hash = crypto.createHash("sha256").update(input).digest();
  return base64Url(hash);
}

function json(res, status, obj) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}

async function handler(req, res) {
  if (req.method !== "GET") return json(res, 405, { error: "Method not allowed" });

  const url = new URL(req.url, "http://local");
  const requested = url.searchParams.get("app");
  const app = resolveAppLabel(requested);
  if (!app) {
    return json(res, 400, { error: "Missing or invalid ?app= label", allowed: listAppLabels() });
  }

  const cfgRes = getAppConfig(app);
  if (!cfgRes.ok) return json(res, 500, { error: cfgRes.error });
  const { cfg } = cfgRes;

  const codeVerifier = base64Url(crypto.randomBytes(64));
  const codeChallenge = await sha256Base64Url(codeVerifier);
  const state = crypto.randomUUID();

  // pre_auth stores state, pkce verifier, and app label
  const preAuth = JSON.stringify({ state, codeVerifier, app, t: Date.now() });
  const preAuthCookie = serializeCookie("pre_auth", preAuth, {
    httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: 5 * 60
  });
  res.setHeader("Set-Cookie", preAuthCookie);

  const authUrl = new URL(`https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps/${cfg.CONTENTSTACK_APP_UID}/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", cfg.OAUTH_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", cfg.OAUTH_REDIRECT_URI);
  if (cfg.OAUTH_SCOPE) authUrl.searchParams.set("scope", cfg.OAUTH_SCOPE);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.writeHead(302, { Location: authUrl.toString() });
  res.end();
}

export default handler;