/** Minimal structured logger so jobs are testable without a log framework. */
export interface Logger {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}

export const consoleLogger: Logger = {
  info: (msg, f) => console.log(JSON.stringify({ level: "info", msg, ...f })),
  warn: (msg, f) => console.warn(JSON.stringify({ level: "warn", msg, ...f })),
  error: (msg, f) => console.error(JSON.stringify({ level: "error", msg, ...f })),
};

export const silentLogger: Logger = { info() {}, warn() {}, error() {} };
