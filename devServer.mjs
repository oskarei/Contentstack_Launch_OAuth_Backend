// Minimal local HTTP server to exercise the handlers without Launch CLI.
// Uses dotenv for local envs in .env.local
import "dotenv/config";
import http from "http";
import startHandler from "./functions/auth/start.js";
import callbackHandler from "./functions/auth/callback.js";
import tokenHandler from "./functions/auth/token.js";
import logoutHandler from "./functions/auth/logout.js";
import successHandler from "./functions/auth/success.js";

const routes = {
  "GET /auth/start": startHandler,
  "GET /auth/callback": callbackHandler,
  "GET /auth/token": tokenHandler,
  "OPTIONS /auth/token": tokenHandler,
  "GET /auth/logout": logoutHandler,
  "GET /auth/success": successHandler
};

const server = http.createServer((req, res) => {
  const key = `${req.method} ${new URL(req.url, "http://localhost").pathname}`;
  const handler = routes[key];
  if (handler) return handler(req, res);
  res.statusCode = 404;
  res.end("Not Found");
});

const port = process.env.PORT || 8787;
server.listen(port, () => {
  console.log(`Dev server on http://localhost:${port}`);
});