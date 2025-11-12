function handler(req, res) {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html><html><body>
    <h1>Connected</h1>
    <p>You can close this tab and return to the app.</p>
  </body></html>`);
}

export default handler;