import { buildApp } from "./app.js";

/**
 * Entry point for the self-hosted server. The app is built separately (app.ts)
 * so tests can inject requests without binding a port.
 */
const port = Number(process.env["PORT"] ?? 4000);
const host = process.env["HOST"] ?? "127.0.0.1";

const app = buildApp();

app
  .listen({ port, host })
  .then((address) => {
    app.log.info(`kumomiru server listening on ${address}`);
  })
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
