import { serialize as serializeCookie, parse as parseCookie } from "cookie";
import fetch from "node-fetch";
import { EncryptJWT } from "jose";
import { getAppConfig } from "../_shared/config.js";

export default async function handler(req, res) {
  if (req.method !== "GET") { res.status(405).json({error:"Method not allowed"}); return; }
  const { COOKIE_SECRET } = process.env;
  if (!COOKIE_SECRET) { res.status(500).json({error:"Missing COOKIE_SECRET"}); return; }

  const url = new URL(req.url, "http://local");
  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  if (!code || !returnedState) { res.status(400).json({error:"Missing code/state"}); return; }

  const cookies = parseCookie(req.headers.cookie || "");
  const preAuth = cookies.pre_auth ? JSON.parse(cookies.pre_auth) : null;
  if (!preAuth || preAuth.state !== returnedState) { res.status(400).json({error:"Invalid state"}); return; }

  const r = getAppConfig(preAuth.app);
  if (!r.ok) { res.status(500).json({error:r.error}); return; }
  const cfg = r.cfg;

  const tokenUrl = `https://${cfg.CONTENTSTACK_REGION}-app.contentstack.com/apps-api/apps/${cfg.CONTENTSTACK_APP_UID}/tokens`;
  const resp = await fetch(tokenUrl, {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({
      grant_type:"authorization_code",
      code,
      redirect_uri: cfg.OAUTH_REDIRECT_URI,
      client_id: cfg.OAUTH_CLIENT_ID,
      client_secret: cfg.OAUTH_CLIENT_SECRET,
      code_verifier: preAuth.codeVerifier
    })
  });
  const json = await resp.json();
  if (!resp.ok) { res.status(resp.status).json({error: json.error_description || json.error || json}); return; }

  const now = Math.floor(Date.now()/1000);
  const payload = {
    app: preAuth.app,
    accessToken: json.access_token,
    refreshToken: json.refresh_token,
    tokenType: json.token_type || "Bearer",
    scope: json.scope || cfg.OAUTH_SCOPE || null,
    expiresAt: now + (json.expires_in || 3600),
    obtainedAt: now
  };

  const secret = Buffer.from(COOKIE_SECRET, "base64");
  const jwe = await new EncryptJWT(payload)
    .setProtectedHeader({ alg:"dir", enc:"A256GCM" })
    .setIssuedAt().setExpirationTime("30d")
    .encrypt(secret);

  const tokenCookie = serializeCookie("oauth_token", jwe, {
    httpOnly:true, secure:true, sameSite:"lax", path:"/", maxAge: 30*24*60*60
  });
  const clearPre = serializeCookie("pre_auth","",{
    httpOnly:true, secure:true, sameSite:"lax", path:"/", maxAge:0
  });

  res.setHeader("Set-Cookie", [tokenCookie, clearPre]);
  res.setHeader("Content-Type","text/html; charset=utf-8");
  res.end(`<!doctype html><html><body>
<script>
if(window.opener){try{window.opener.postMessage({type:'oauth:complete'},'*')}catch(e){};window.close();}
else{location.replace('/auth/success');}
</script>
Success. You can close this window.
</body></html>`);
}