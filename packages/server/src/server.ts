import { openDatabase } from "@kumomiru/db";
import { buildApp, adhocIngestDefault } from "./app.js";

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
const app = buildApp({ db, adhocIngest: adhocIngestDefault() });

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
