import { serialize as serializeCookie } from "cookie";
import crypto from "crypto";

function b64u(buf){return Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
async function sha256b64u(s){return b64u(crypto.createHash("sha256").update(s).digest());}

export default async function handler(req, res) {
  if (req.method !== "GET") { res.status(405).json({error:"Method not allowed"}); return; }

  const url = new URL(req.url, "http://local");
  const requested = url.searchParams.get("app");

  // multi-app
  const { resolveAppLabel, getAppConfig, listAppLabels } = await import("../_shared/config.js");
  const app = resolveAppLabel(requested);
  if (!app) { res.status(400).json({error:"Missing or invalid ?app=", allowed:listAppLabels()}); return; }

  const r = getAppConfig(app);
  if (!r.ok) { res.status(500).json({error:r.error}); return; }
  const cfg = r.cfg;

  const codeVerifier = b64u(crypto.randomBytes(64));
  const codeChallenge = await sha256b64u(codeVerifier);
  const state = crypto.randomUUID();

  const preAuth = JSON.stringify({ state, codeVerifier, app, t: Date.now() });
  // pre_auth cookie
  res.setHeader("Set-Cookie", serializeCookie("pre_auth", preAuth, {
    httpOnly: true,
    secure: true,
    sameSite: "none",   // ⬅️ was "lax"
    path: "/",
    maxAge: 5 * 60
  }));

  const authUrl = new URL(`https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps/${cfg.CONTENTSTACK_APP_UID}/authorize`);
  authUrl.searchParams.set("response_type","code");
  authUrl.searchParams.set("client_id", cfg.OAUTH_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", cfg.OAUTH_REDIRECT_URI);
  if (cfg.OAUTH_SCOPE) authUrl.searchParams.set("scope", cfg.OAUTH_SCOPE);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method","S256");

  res.redirect(authUrl.toString());
}