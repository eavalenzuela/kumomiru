import { test } from "node:test";
import assert from "node:assert/strict";

import { openDatabase } from "@kumomiru/db";
import { buildApp } from "../src/app.js";
import type { OidcProvider } from "../src/auth/oidc.js";

const SECRET = "0123456789abcdef0123456789abcdef";
const ISSUER = "https://idp.example.com";

/** A fake IdP: records the state it was given and returns whoever the test says logs in. */
function fakeProvider(who: { email: string; name?: string; sub: string }): OidcProvider & { lastState: string | null } {
  const p = {
    lastState: null as string | null,
    async authorizationUrl({ state }: { state: string }) {
      p.lastState = state;
      return `${ISSUER}/authorize?state=${state}`;
    },
    async exchange({ state }: { state: string }) {
      if (state !== p.lastState) throw new Error("state mismatch");
      return { sub: who.sub, iss: ISSUER, email: who.email, ...(who.name ? { name: who.name } : {}) };
    },
  };
  return p;
}

async function appWith(provider: OidcProvider, adminEmails: string[] = []) {
  const db = openDatabase(":memory:");
  const app = await buildApp({ logger: false, db, adhocIngest: true, auth: { provider, sessionSecret: SECRET, baseUrl: "http://localhost:4000", adminEmails } });
  return { app, db, close: async () => { await app.close(); db.close(); } };
}

/** Walk the login flow and return the session cookie. */
async function login(app: Awaited<ReturnType<typeof appWith>>["app"]) {
  const start = await app.inject({ method: "GET", url: "/auth/login?next=/map" });
  assert.equal(start.statusCode, 302);
  const loginCookie = start.cookies.find((c) => c.name === "kumomiru_login")!;
  assert.ok(loginCookie, "login cookie set");
  const cb = await app.inject({ method: "GET", url: "/auth/callback?code=x&state=whatever", cookies: { kumomiru_login: loginCookie.value } });
  assert.equal(cb.statusCode, 302, cb.body);
  assert.equal(cb.headers["location"], "/map");
  const session = cb.cookies.find((c) => c.name === "kumomiru_session")!;
  assert.ok(session, "session cookie set");
  assert.ok(session.httpOnly);
  return session.value;
}

test("without auth configured: open access, /auth/me says so", async () => {
  const db = openDatabase(":memory:");
  const app = await buildApp({ logger: false, db, adhocIngest: true });
  const me = await app.inject({ method: "GET", url: "/auth/me" });
  assert.deepEqual(me.json(), { authEnabled: false, user: null });
  const res = await app.inject({ method: "GET", url: "/accounts" });
  assert.equal(res.statusCode, 200);
  await app.close();
  db.close();
});

test("with auth: unauthenticated requests get 401 except exempt routes; login sets a session", async () => {
  const { app, close } = await appWith(fakeProvider({ email: "Alice@Example.com", name: "Alice", sub: "s1" }), ["alice@example.com"]);
  let res = await app.inject({ method: "GET", url: "/accounts" });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().loginUrl, "/auth/login");
  for (const url of ["/health", "/policy/least-privilege", "/auth/me"]) {
    res = await app.inject({ method: "GET", url });
    assert.equal(res.statusCode, 200, url);
  }
  assert.deepEqual((await app.inject({ method: "GET", url: "/auth/me" })).json(), { authEnabled: true, user: null });

  const session = await login(app);
  res = await app.inject({ method: "GET", url: "/auth/me", cookies: { kumomiru_session: session } });
  assert.equal(res.json().user.email, "alice@example.com");
  assert.equal(res.json().user.role, "admin", "listed in adminEmails");
  res = await app.inject({ method: "GET", url: "/accounts", cookies: { kumomiru_session: session } });
  assert.equal(res.statusCode, 200);

  // Tampered cookie → treated as anonymous.
  res = await app.inject({ method: "GET", url: "/accounts", cookies: { kumomiru_session: session.slice(0, -4) + "AAAA" } });
  assert.equal(res.statusCode, 401);

  // Logout clears it.
  res = await app.inject({ method: "POST", url: "/auth/logout", cookies: { kumomiru_session: session } });
  assert.equal(res.statusCode, 200);
  assert.ok(res.cookies.find((c) => c.name === "kumomiru_session")!.value === "");
  await close();
});

test("roles: viewer can read but not mutate; admin can; self-lockout is refused; disabled user is locked out", async () => {
  const { app, db, close } = await appWith(fakeProvider({ email: "bob@example.com", sub: "s2" }), ["root@example.com"]);
  const bob = await login(app);
  let res = await app.inject({ method: "GET", url: "/auth/me", cookies: { kumomiru_session: bob } });
  assert.equal(res.json().user.role, "viewer", "not in adminEmails and the list is non-empty → viewer");
  res = await app.inject({ method: "GET", url: "/findings", cookies: { kumomiru_session: bob } });
  assert.equal(res.statusCode, 200);
  res = await app.inject({ method: "POST", url: "/accounts", cookies: { kumomiru_session: bob }, payload: { id: "123456789012", name: "x", roleArn: "arn:aws:iam::123456789012:role/R" } });
  assert.equal(res.statusCode, 403);
  res = await app.inject({ method: "PATCH", url: `/users/${res.json().id ?? "x"}`, cookies: { kumomiru_session: bob }, payload: { role: "admin" } });
  assert.equal(res.statusCode, 403, "a viewer cannot promote themselves");

  // Promote bob directly in the db (as an admin would via PATCH /users/:id), then he can mutate.
  const bobUser = db.users.getByEmail("bob@example.com")!;
  db.users.setRole(bobUser.id, "admin");
  res = await app.inject({ method: "POST", url: "/accounts", cookies: { kumomiru_session: bob }, payload: { id: "123456789012", name: "x", roleArn: "arn:aws:iam::123456789012:role/R" } });
  assert.equal(res.statusCode, 201);
  res = await app.inject({ method: "PATCH", url: `/users/${bobUser.id}`, cookies: { kumomiru_session: bob }, payload: { role: "viewer" } });
  assert.equal(res.statusCode, 400, "self-demotion refused");
  assert.equal(res.json().error, "self_lockout");
  res = await app.inject({ method: "GET", url: "/users", cookies: { kumomiru_session: bob } });
  assert.equal(res.json().length, 1);

  db.users.setDisabled(bobUser.id, true);
  res = await app.inject({ method: "GET", url: "/accounts", cookies: { kumomiru_session: bob } });
  assert.equal(res.statusCode, 401, "disabled takes effect on the next request");
  await close();
});

test("bootstrap: with an empty admin list the first user becomes admin, the second a viewer", async () => {
  const first = fakeProvider({ email: "first@example.com", sub: "a" });
  const { app, db, close } = await appWith(first, []);
  const s1 = await login(app);
  assert.equal((await app.inject({ method: "GET", url: "/auth/me", cookies: { kumomiru_session: s1 } })).json().user.role, "admin");
  // Swap the fake's identity for the second login.
  Object.assign(first, fakeProvider({ email: "second@example.com", sub: "b" }));
  const s2 = await login(app);
  assert.equal((await app.inject({ method: "GET", url: "/auth/me", cookies: { kumomiru_session: s2 } })).json().user.role, "viewer");
  assert.equal(db.users.count(), 2);
  await close();
});

test("callback without a login cookie, or with a mismatched state, does not create a session", async () => {
  const provider = fakeProvider({ email: "x@example.com", sub: "x" });
  const { app, db, close } = await appWith(provider, []);
  let res = await app.inject({ method: "GET", url: "/auth/callback?code=x&state=nope" });
  assert.equal(res.statusCode, 400);
  await app.inject({ method: "GET", url: "/auth/login" });
  const start = await app.inject({ method: "GET", url: "/auth/login" });
  const cookie = start.cookies.find((c) => c.name === "kumomiru_login")!.value;
  provider.lastState = "tampered";
  res = await app.inject({ method: "GET", url: "/auth/callback?code=x&state=y", cookies: { kumomiru_login: cookie } });
  assert.equal(res.statusCode, 401);
  assert.equal(db.users.count(), 0);
  await close();
});
