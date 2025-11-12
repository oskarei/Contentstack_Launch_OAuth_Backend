import { serialize as serializeCookie } from "cookie";

export default function handler(req, res) {
  const kill = serializeCookie("oauth_token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "none",   // ⬅️ was "lax"
    path: "/",
    maxAge: 0
  });
  const killPre = serializeCookie("pre_auth", "", {
    httpOnly: true,
    secure: true,
    sameSite: "none",   // ⬅️ was "lax"
    path: "/",
    maxAge: 0
  });
  res.setHeader("Set-Cookie",[kill,killPre]);
  res.json({ ok:true });
}