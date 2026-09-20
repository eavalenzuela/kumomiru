import { randomUUID } from "node:crypto";
import type BetterSqlite3 from "better-sqlite3";
import type { UserRecord, UserRepo, UserRole } from "./repository.js";

interface Row {
  id: string;
  email: string;
  name: string | null;
  idp_subject: string;
  idp_issuer: string;
  role: string;
  created_at: string;
  last_login_at: string | null;
  disabled: number;
}

function toUser(r: Row): UserRecord {
  return {
    id: r.id,
    email: r.email,
    name: r.name,
    idpSubject: r.idp_subject,
    idpIssuer: r.idp_issuer,
    role: r.role as UserRole,
    createdAt: r.created_at,
    lastLoginAt: r.last_login_at,
    disabled: r.disabled === 1,
  };
}

export function userRepo(db: BetterSqlite3.Database, now: () => string): UserRepo {
  const list = db.prepare("SELECT * FROM users ORDER BY email");
  const get = db.prepare("SELECT * FROM users WHERE id = ?");
  const byEmail = db.prepare("SELECT * FROM users WHERE email = ?");
  const bySubject = db.prepare("SELECT * FROM users WHERE idp_issuer = ? AND idp_subject = ?");
  const insert = db.prepare(`
    INSERT INTO users (id, email, name, idp_subject, idp_issuer, role, created_at, last_login_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  const touch = db.prepare("UPDATE users SET email = ?, name = ?, role = COALESCE(?, role), last_login_at = ? WHERE id = ?");
  const setRole = db.prepare("UPDATE users SET role = ? WHERE id = ?");
  const setDisabled = db.prepare("UPDATE users SET disabled = ? WHERE id = ?");
  const count = db.prepare("SELECT COUNT(*) AS n FROM users");
  const tx = db.transaction((input: Parameters<UserRepo["upsertOnLogin"]>[0]): UserRecord => {
    const ts = now();
    const email = input.email.toLowerCase();
    const existing = (bySubject.get(input.idpIssuer, input.idpSubject) ?? byEmail.get(email)) as Row | undefined;
    if (existing) {
      touch.run(email, input.name ?? existing.name, input.role ?? null, ts, existing.id);
      return toUser(get.get(existing.id) as Row);
    }
    const id = randomUUID();
    insert.run(id, email, input.name ?? null, input.idpSubject, input.idpIssuer, input.role ?? "viewer", ts, ts);
    return toUser(get.get(id) as Row);
  });
  return {
    list: () => (list.all() as Row[]).map(toUser),
    get: (id) => {
      const r = get.get(id) as Row | undefined;
      return r ? toUser(r) : null;
    },
    getByEmail: (email) => {
      const r = byEmail.get(email.toLowerCase()) as Row | undefined;
      return r ? toUser(r) : null;
    },
    upsertOnLogin: (input) => tx(input),
    setRole: (id, role) => setRole.run(role, id).changes > 0,
    setDisabled: (id, disabled) => setDisabled.run(disabled ? 1 : 0, id).changes > 0,
    count: () => (count.get() as { n: number }).n,
  };
}
