import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import cookie from "@fastify/cookie";
import { z } from "zod";
import type { Database, UserRecord, UserRole } from "@kumomiru/db";

import { pkce, type OidcProvider } from "./oidc.js";

/**
 * OIDC single sign-on + role guard (docs/cspm-roadmap.md Phase 5).
 *
 * Session: a signed, HttpOnly, SameSite=Lax cookie holding only the user id
 * and expiry. The user row is loaded on every request so role changes and
 * disabling take effect immediately. Login state (PKCE verifier + state) is a
 * separate short-lived signed cookie. No tokens are stored anywhere.
 *
 * Roles: `viewer` may read; `admin` may also mutate (POST/PUT/PATCH/DELETE).
 * Bootstrap: emails in `adminEmails` become admin on login; if that list is
 * empty, the very first user to log in becomes admin (logged loudly).
 *
 * Exempt: /health, /auth/*, and /policy/least-privilege (public by design —
 * it is the policy you attach *before* you can log in anywhere).
 */
export interface AuthOptions {
  provider: OidcProvider;
  /** Secret for cookie signing; ≥ 32 chars. */
  sessionSecret: string;
  /** Public base URL of this server (for the OIDC redirect URI). */
  baseUrl: string;
  adminEmails?: string[];
  /** Session lifetime; default 12h. */
  sessionTtlSeconds?: number;
  /** Where to send the browser after login; default "/". */
  postLoginRedirect?: string;
}

const SESSION_COOKIE = "kumomiru_session";
const LOGIN_COOKIE = "kumomiru_login";
const EXEMPT = [/^\/health$/, /^\/auth\//, /^\/policy\/least-privilege$/];
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

declare module "fastify" {
  interface FastifyRequest {
    user: UserRecord | null;
  }
}

interface SessionPayload {
  uid: string;
  exp: number;
}

function encode(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}
function decode<T>(s: string): T | null {
  try {
    return JSON.parse(Buffer.from(s, "base64url").toString("utf8")) as T;
  } catch {
    return null;
  }
}

export async function registerAuth(app: FastifyInstance, db: Database, opts: AuthOptions): Promise<void> {
  if (opts.sessionSecret.length < 32) throw new Error("sessionSecret must be at least 32 characters");
  await app.register(cookie, { secret: opts.sessionSecret });
  app.decorateRequest("user", null);

  const ttl = opts.sessionTtlSeconds ?? 12 * 3600;
  const adminEmails = new Set((opts.adminEmails ?? []).map((e) => e.toLowerCase()));
  const redirectUri = new URL("/auth/callback", opts.baseUrl).toString();
  const secure = opts.baseUrl.startsWith("https://");

  const readSession = (request: FastifyRequest): UserRecord | null => {
    const raw = request.cookies[SESSION_COOKIE];
    if (!raw) return null;
    const un = request.unsignCookie(raw);
    if (!un.valid || !un.value) return null;
    const p = decode<SessionPayload>(un.value);
    if (!p || p.exp < Date.now() / 1000) return null;
    const user = db.users.get(p.uid);
    return user && !user.disabled ? user : null;
  };

  app.addHook("onRequest", async (request, reply) => {
    request.user = readSession(request);
    const path = request.url.split("?")[0] ?? request.url;
    if (EXEMPT.some((re) => re.test(path))) return;
    if (!request.user) {
      return reply.status(401).send({ error: "unauthenticated", loginUrl: "/auth/login" });
    }
    if (MUTATING.has(request.method) && request.user.role !== "admin") {
      return reply.status(403).send({ error: "forbidden", message: "admin role required" });
    }
  });

  app.get("/auth/login", async (request, reply) => {
    const verifier = pkce.verifier();
    const state = pkce.state();
    const challenge = await pkce.challenge(verifier);
    const next = typeof (request.query as { next?: string }).next === "string" ? (request.query as { next: string }).next : opts.postLoginRedirect ?? "/";
    reply.setCookie(LOGIN_COOKIE, encode({ verifier, state, next: next.startsWith("/") ? next : "/" }), {
      signed: true, httpOnly: true, sameSite: "lax", secure, path: "/auth", maxAge: 600,
    });
    const url = await opts.provider.authorizationUrl({ redirectUri, state, codeChallenge: challenge });
    return reply.redirect(url);
  });

  app.get("/auth/callback", async (request, reply) => {
    const raw = request.cookies[LOGIN_COOKIE];
    const un = raw ? request.unsignCookie(raw) : { valid: false, value: null };
    const login = un.valid && un.value ? decode<{ verifier: string; state: string; next: string }>(un.value) : null;
    reply.clearCookie(LOGIN_COOKIE, { path: "/auth" });
    if (!login) return reply.status(400).send({ error: "login_expired", message: "start again at /auth/login" });
    let claims;
    try {
      claims = await opts.provider.exchange({
        callbackUrl: new URL(request.url, opts.baseUrl).toString(),
        redirectUri,
        state: login.state,
        codeVerifier: login.verifier,
      });
    } catch (err) {
      request.log.warn({ err: err instanceof Error ? err.message : String(err) }, "oidc exchange failed");
      return reply.status(401).send({ error: "login_failed" });
    }
    const email = claims.email.toLowerCase();
    const bootstrapAdmin = adminEmails.has(email) || (adminEmails.size === 0 && db.users.count() === 0);
    const user = db.users.upsertOnLogin({
      email,
      name: claims.name ?? null,
      idpSubject: claims.sub,
      idpIssuer: claims.iss,
      ...(bootstrapAdmin ? { role: "admin" as const } : {}),
    });
    if (bootstrapAdmin && adminEmails.size === 0) {
      request.log.warn({ email }, "first user granted admin (KUMOMIRU_ADMIN_EMAILS is empty)");
    }
    if (user.disabled) return reply.status(403).send({ error: "user_disabled" });
    reply.setCookie(SESSION_COOKIE, encode({ uid: user.id, exp: Math.floor(Date.now() / 1000) + ttl } satisfies SessionPayload), {
      signed: true, httpOnly: true, sameSite: "lax", secure, path: "/", maxAge: ttl,
    });
    return reply.redirect(login.next || "/");
  });

  app.post("/auth/logout", async (_request, reply) => {
    reply.clearCookie(SESSION_COOKIE, { path: "/" });
    return { ok: true };
  });

  app.get("/auth/me", async (request) => ({
    authEnabled: true,
    user: request.user ? publicUser(request.user) : null,
  }));

  // --- user administration ---------------------------------------------------------
  app.get("/users", async () => db.users.list().map(publicUser));

  const Patch = z.object({ role: z.enum(["viewer", "admin"]).optional(), disabled: z.boolean().optional() });
  app.patch("/users/:id", async (request, reply) => {
    const id = (request.params as { id: string }).id;
    const parsed = Patch.safeParse(request.body);
    if (!parsed.success) return reply.status(400).send({ error: "invalid_user_patch", issues: parsed.error.issues });
    const target = db.users.get(id);
    if (!target) return reply.status(404).send({ error: "not_found" });
    if (target.id === request.user?.id && (parsed.data.role === "viewer" || parsed.data.disabled)) {
      return reply.status(400).send({ error: "self_lockout", message: "you cannot demote or disable yourself" });
    }
    if (parsed.data.role) db.users.setRole(id, parsed.data.role as UserRole);
    if (parsed.data.disabled !== undefined) db.users.setDisabled(id, parsed.data.disabled);
    return publicUser(db.users.get(id)!);
  });
}

/** When auth is not configured: report it so the UI can hide login, and allow everything. */
export function registerNoAuth(app: FastifyInstance): void {
  app.decorateRequest("user", null);
  app.get("/auth/me", async () => ({ authEnabled: false, user: null }));
}

function publicUser(u: UserRecord) {
  return { id: u.id, email: u.email, name: u.name, role: u.role, disabled: u.disabled, lastLoginAt: u.lastLoginAt };
}
