/**
 * The credential broker (component "A" in the design). Credentials we CONSUME
 * to scan live only for the duration of one discovery run and are then dropped
 * — never persisted, never logged. This module models that lifecycle explicitly
 * so the rule is enforced by structure, not discipline.
 *
 * We deliberately prefer short-lived STS material (sessionToken present): a
 * leaked dump expires in hours. Long-lived access keys are accepted but flagged.
 */

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  /** Present for STS/assume-role sessions; strongly preferred. */
  sessionToken?: string;
  region: string;
}

export interface CredentialMeta {
  region: string;
  /** True when a sessionToken was supplied (short-lived). */
  temporary: boolean;
}

/**
 * Holds credentials for exactly one run. `use` runs the callback with the
 * credentials, then scrubs them from memory in a finally block regardless of
 * outcome. After `use` resolves, the broker is spent and throws if reused.
 */
export class CredentialBroker {
  #creds: AwsCredentials | null;

  constructor(creds: AwsCredentials) {
    this.#creds = creds;
  }

  get meta(): CredentialMeta {
    if (!this.#creds) throw new Error("credential broker already spent");
    return {
      region: this.#creds.region,
      temporary: Boolean(this.#creds.sessionToken),
    };
  }

  /**
   * Run `fn` with the credentials, then scrub. The credentials are never
   * returned to the caller — only borrowed inside the callback — so they cannot
   * outlive the run.
   */
  async use<T>(fn: (creds: AwsCredentials) => Promise<T>): Promise<T> {
    if (!this.#creds) throw new Error("credential broker already spent");
    const creds = this.#creds;
    try {
      return await fn(creds);
    } finally {
      this.#scrub();
    }
  }

  #scrub(): void {
    if (this.#creds) {
      // Overwrite the secret material before dropping the reference.
      this.#creds.accessKeyId = "";
      this.#creds.secretAccessKey = "";
      this.#creds.sessionToken = "";
      this.#creds = null;
    }
  }
}
