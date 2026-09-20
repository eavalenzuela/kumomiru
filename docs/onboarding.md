# Onboarding accounts

kumomiru scans accounts with a read-only role it assumes from its own host
identity. This page is the operator checklist.

## 1. Give the worker an identity

Run the worker somewhere with an AWS identity: an EC2 instance profile, an EKS
service account (IRSA), an ECS task role, or a local `AWS_PROFILE`. Attach
[`worker-host-policy.json`](./worker-host-policy.json). It allows exactly two
things: assuming `KumomiruScanRole` in any account, and (optionally) reading
the Organizations tree.

At start the worker records its identity; `GET /onboarding` shows it as
`workerHostIdentity`, together with the estate-wide `externalId` kumomiru
generated.

## 2. Create the scan role in each target account

Download the CloudFormation template:

```sh
curl -s localhost:4000/onboarding/stackset.yaml -o kumomiru-scan-role.yaml
```

It creates `KumomiruScanRole` with the generated read-only policy
([`least-privilege-policy.json`](./least-privilege-policy.json)) and a trust
policy that only the worker's role, presenting the ExternalId, can use.
Deploy it:

- **One account:** `aws cloudformation deploy --template-file kumomiru-scan-role.yaml --stack-name kumomiru-scan-role --capabilities CAPABILITY_NAMED_IAM`
- **An organization:** create a StackSet from the template in the management
  (or delegated) account and target the OUs you want scanned. New accounts in
  those OUs get the role automatically.

kumomiru never deploys this itself: it holds no write permission anywhere.

## 3. Register accounts

**Manually**, one at a time (`POST /accounts`), then verify:

```sh
curl -s -X POST localhost:4000/accounts/123456789012/scans -H 'content-type: application/json' -d '{"trigger":"verify"}'
```

**Or from Organizations**: enable sync and let the worker do it.

```sh
curl -s -X POST localhost:4000/onboarding/org-sync -H 'content-type: application/json' -d '{"enabled":true}'
```

Every hour the worker lists the organization's active accounts, registers
each one as `pending` (keeping anything you already set), and queues a
verification. An account flips to `active` once its scan role can be assumed,
and scans start on its schedule. Suspended accounts are skipped; nothing is
ever deleted.

## 4. Sign-in

Set these to turn on OIDC single sign-on (Okta, Entra ID, Google, ...):

| Variable | Meaning |
|---|---|
| `KUMOMIRU_OIDC_ISSUER` | Issuer URL (discovery document at `/.well-known/openid-configuration`). |
| `KUMOMIRU_OIDC_CLIENT_ID`, `KUMOMIRU_OIDC_CLIENT_SECRET` | The app registration. Redirect URI is `<KUMOMIRU_BASE_URL>/auth/callback`. |
| `KUMOMIRU_BASE_URL` | Public URL of the server as the browser sees it. |
| `KUMOMIRU_SESSION_SECRET` | ≥ 32 characters; signs the session cookie. |
| `KUMOMIRU_ADMIN_EMAILS` | Comma-separated emails that get the `admin` role on login. If empty, the first user to sign in becomes admin. |

`viewer` can read everything; `admin` can also register accounts, start scans,
manage suppressions, and change roles (`PATCH /users/:id`). Without the OIDC
variables the API is open, which is fine on a laptop and wrong anywhere
shared; the server logs a warning at start.

## Cross-account trust inside your estate

When account A trusts a role in account B and both are registered, the
external principal is marked `knownAccount` and the finding steps down one
severity with an explanation. It is still shown: cross-account trust inside
the estate is worth knowing about, just not a critical alarm.
