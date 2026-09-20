import { randomBytes } from "node:crypto";
import { openDatabase } from "@kumomiru/db";
import { buildApp, adhocIngestDefault } from "./app.js";
import { makeOidcProvider } from "./auth/oidc.js";
import type { AuthOptions } from "./auth/index.js";

/**
 * Entry point for the self-hosted server. The app is built separately (app.ts)
 * so tests can inject requests without binding a port.
 *
 * The database file is shared with the worker (`KUMOMIRU_DB_PATH`, same value
 * in both processes). The server only writes accounts and scan requests.
 */
const port = Number(process.env["PORT"] ?? 4000);
const host = process.env["HOST"] ?? "127.0.0.1";
const dbPath = process.env["KUMOMIRU_DB_PATH"] ?? "./kumomiru.db";

const db = openDatabase(dbPath);

/**
 * OIDC is on when KUMOMIRU_OIDC_ISSUER and KUMOMIRU_OIDC_CLIENT_ID are set.
 * KUMOMIRU_BASE_URL must be the public URL the browser uses (the redirect
 * URI is <base>/auth/callback). KUMOMIRU_SESSION_SECRET signs the cookie; if
 * unset a random one is generated per boot (sessions do not survive
 * restarts). KUMOMIRU_ADMIN_EMAILS is a comma-separated admin bootstrap list.
 */
function authFromEnv(): AuthOptions | undefined {
  const issuer = process.env["KUMOMIRU_OIDC_ISSUER"];
  const clientId = process.env["KUMOMIRU_OIDC_CLIENT_ID"];
  if (!issuer || !clientId) return undefined;
  const baseUrl = process.env["KUMOMIRU_BASE_URL"] ?? `http://${host}:${port}`;
  let sessionSecret = process.env["KUMOMIRU_SESSION_SECRET"];
  if (!sessionSecret) {
    sessionSecret = randomBytes(32).toString("hex");
    console.warn("KUMOMIRU_SESSION_SECRET not set: generated a per-boot secret; sessions will not survive restarts");
  }
  return {
    provider: makeOidcProvider({
      issuer,
      clientId,
      ...(process.env["KUMOMIRU_OIDC_CLIENT_SECRET"] ? { clientSecret: process.env["KUMOMIRU_OIDC_CLIENT_SECRET"] } : {}),
    }),
    sessionSecret,
    baseUrl,
    adminEmails: (process.env["KUMOMIRU_ADMIN_EMAILS"] ?? "").split(",").map((e) => e.trim()).filter(Boolean),
  };
}

const auth = authFromEnv();
const app = await buildApp({ db, adhocIngest: adhocIngestDefault(), ...(auth ? { auth } : {}) });
if (!auth) app.log.warn("OIDC not configured: the API is open to anyone who can reach it");

app
  .listen({ port, host })
  .then((address) => {
    app.log.info(`kumomiru server listening on ${address} (db: ${dbPath})`);
  })
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });

const shutdown = () => {
  void app.close().then(() => {
    db.close();
    process.exit(0);
  });
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
