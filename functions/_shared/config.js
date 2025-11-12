// Strict multi-app config: requires label-prefixed envs only.
// Example label "interstack": INTERSTACK_CONTENTSTACK_APP_UID, etc.

function parseLabels() {
  const raw = process.env.APP_LABELS || "";
  return raw.split(",").map(s => s.trim()).filter(Boolean);
}

function toPrefix(label) {
  return label.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

export function listAppLabels() {
  return parseLabels();
}

export function resolveAppLabel(fromQuery) {
  const labels = parseLabels();
  if (fromQuery && labels.includes(fromQuery)) return fromQuery;
  if (labels.length === 1) return labels[0];
  return ""; // force explicit ?app= when multiple labels exist
}

// NEW: default label for installation callbacks (no ?app= / no cookie)
// picks the first label in APP_LABELS
export function defaultInstallLabel() {
  const labels = parseLabels();
  return labels[0] || "";
}

export function getAppConfig(label) {
  const P = toPrefix(label);

  const cfg = {
    label,
    CONTENTSTACK_REGION: process.env[`${P}_CONTENTSTACK_REGION`] || "",
    CONTENTSTACK_APP_UID: process.env[`${P}_CONTENTSTACK_APP_UID`] || "",
    OAUTH_CLIENT_ID: process.env[`${P}_OAUTH_CLIENT_ID`] || "",
    OAUTH_CLIENT_SECRET: process.env[`${P}_OAUTH_CLIENT_SECRET`] || "",
    OAUTH_REDIRECT_URI: process.env[`${P}_OAUTH_REDIRECT_URI`] || "",
    OAUTH_SCOPE: process.env[`${P}_OAUTH_SCOPE`] || "",
  };

  const missing = [];
  ["CONTENTSTACK_REGION","CONTENTSTACK_APP_UID","OAUTH_CLIENT_ID","OAUTH_CLIENT_SECRET","OAUTH_REDIRECT_URI"]
    .forEach(k => { if (!cfg[k]) missing.push(`${P}_${k}`); });

  if (missing.length) {
    return { ok: false, error: `Missing env for app '${label}': ${missing.join(", ")}` };
  }
  return { ok: true, cfg };
}