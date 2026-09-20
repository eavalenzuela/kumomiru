import * as oidc from "openid-client";

/**
 * The slice of OpenID Connect the server needs, behind an interface so tests
 * can inject a fake identity provider. The real implementation wraps
 * openid-client with discovery + PKCE; it works with Okta, Entra ID, Google,
 * and any other compliant issuer.
 */
export interface OidcClaims {
  sub: string;
  iss: string;
  email: string;
  name?: string;
  emailVerified?: boolean;
}

export interface OidcProvider {
  /** Build the IdP authorization URL for one login attempt. */
  authorizationUrl(input: { redirectUri: string; state: string; codeChallenge: string }): Promise<string>;
  /** Exchange the callback for verified id-token claims. Throws on any failure. */
  exchange(input: { callbackUrl: string; redirectUri: string; state: string; codeVerifier: string }): Promise<OidcClaims>;
}

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  /** Scopes beyond openid; email and profile are required for the user record. */
  scopes?: string[];
}

export function makeOidcProvider(config: OidcConfig): OidcProvider {
  let configuration: Promise<oidc.Configuration> | null = null;
  const discover = () => {
    if (!configuration) {
      configuration = oidc.discovery(new URL(config.issuer), config.clientId, config.clientSecret);
    }
    return configuration;
  };
  const scope = ["openid", "email", "profile", ...(config.scopes ?? [])].join(" ");
  return {
    async authorizationUrl({ redirectUri, state, codeChallenge }) {
      const c = await discover();
      return oidc
        .buildAuthorizationUrl(c, { redirect_uri: redirectUri, scope, state, code_challenge: codeChallenge, code_challenge_method: "S256" })
        .toString();
    },
    async exchange({ callbackUrl, redirectUri, state, codeVerifier }) {
      const c = await discover();
      const tokens = await oidc.authorizationCodeGrant(c, new URL(callbackUrl), {
        pkceCodeVerifier: codeVerifier,
        expectedState: state,
        ...(redirectUri ? {} : {}),
      });
      const claims = tokens.claims();
      if (!claims?.sub || !claims.iss) throw new Error("id token missing sub/iss");
      const email = typeof claims["email"] === "string" ? claims["email"] : undefined;
      if (!email) throw new Error("id token has no email claim; add the email scope/claim in the IdP");
      return {
        sub: claims.sub,
        iss: claims.iss,
        email,
        ...(typeof claims["name"] === "string" ? { name: claims["name"] } : {}),
        ...(typeof claims["email_verified"] === "boolean" ? { emailVerified: claims["email_verified"] } : {}),
      };
    },
  };
}

export const pkce = {
  verifier: () => oidc.randomPKCECodeVerifier(),
  challenge: (verifier: string) => oidc.calculatePKCECodeChallenge(verifier),
  state: () => oidc.randomState(),
};
