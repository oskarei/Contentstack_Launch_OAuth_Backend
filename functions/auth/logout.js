import { serialize as serializeCookie } from "cookie";

function handler(req, res) {
  const kill = serializeCookie("oauth_token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0
  });
  const killPre = serializeCookie("pre_auth", "", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0
  });
  res.setHeader("Set-Cookie", [kill, killPre]);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify({ ok: true }));
}

export default handler;