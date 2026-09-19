# @kumomiru/aws

The one place the AWS SDK is used. Everything here is read-only by
construction.

| File | Role |
|---|---|
| `client.ts` | `makeSdkClient(creds)` — the SDK-backed `DiscoveryClient`. Declares `DISCOVERY_ACTIONS`, the exact IAM actions it calls. |
| `regions.ts` | `listEnabledRegions(creds)` — the regions a scheduled scan should cover. |
| `sts.ts` | `assumeScanRole(...)` — host identity (instance profile, IRSA, task role) → temporary credentials for one target account. `hostIdentity()` for onboarding. |
| `policy.ts` | `LEAST_PRIVILEGE_POLICY`, generated from the actions above; `DENIED_ACTION_PREFIXES`, the data-plane reads that must never appear. |

`docs/least-privilege-policy.json` is generated from `policy.ts`:

```sh
pnpm policy:gen
```

A test fails if the file drifts from the code, and another fails if any denied
action ever appears in the policy.
