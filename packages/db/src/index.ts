/**
 * @kumomiru/db — persistence behind a repository interface. SQLite today;
 * the interface is kept free of SQLite specifics so Postgres can follow.
 */
export { openDatabase } from "./sqlite.js";
export type { OpenOptions } from "./sqlite.js";
export type * from "./repository.js";
