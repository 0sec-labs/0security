# License tools

Offline tools for issuing and revoking 0security enterprise licenses. They open no network connection. The private key is read only from a file path given on the command line, never from the environment, and is never printed.

| Tool | Purpose |
|---|---|
| `generate-keypair.mjs <private-key-file>` | Create an Ed25519 signing keypair (private PEM, mode 0600, and a base64 public key). |
| `issue-license.mjs` | Sign a v2 token from a customer file (or a v1 token from flags). |
| `sign-revocations.mjs` | Sign a revocation list, or check one against a public key. |

## Token formats

`payload.signature`, both base64url. The signature is Ed25519 over the exact payload bytes. The verifier is `enterprise/src/license.ts`; the contract is `enterprise/test-vectors/license-vectors.json`.

v2 payload: `v, id, customer, plan, seats, aud, entitlements, issuedAt, nbf, expires, kid, rid`.

- `aud` lists the components that may honour the token: `cli`, `hub`, `brain`, `runner`.
- `entitlements` maps a name to its limits, for example `{"saml": {}, "bb-managed": {"repos": 200}}`. Limits are whole numbers. Builds ignore names they do not know.
- `rid` is the revocation id; it defaults to `id`.
- Terms: monthly customers get 35 days, annual customers 400 days. Give `term` in the customer file, or an explicit `expires`.

Customer file:

```json
{ "customer": "Acme", "plan": "team", "seats": 25, "aud": ["cli", "hub"],
  "entitlements": { "saml": {}, "bb-managed": { "repos": 200 } }, "term": "annual" }
```

Tokens carry no secrets. Anyone holding one can use it until it expires or is revoked, so send it over a private channel.

## Signing ceremony

The signing key lives on an offline machine (or in a hardware token), never on a laptop that browses, never in CI, never in this repository.

1. On the offline machine, check out a clean copy of this repository at a reviewed commit.
2. Write the customer file. A second person reads it against the order: customer, plan, seats, audiences, entitlements, limits, term.
3. Run `issue-license.mjs --key <private-key-file> --customer-file acme.json`. Keep the token. Do not paste the key path or key anywhere else.
4. Check the token with `0security config get license` using `ZERO_LICENSE_FILE`.
5. Append `id`, `rid`, customer, plan, issuedAt, expires and the operator to the ledger kept outside this repository. The ledger is the only way to find a `rid` to revoke.
6. Carry the token (not the key) off the machine and send it to the customer.

Rotation: run `generate-keypair.mjs`, add the new public key under a new `kid` in `PRODUCTION_PUBLIC_KEYS`, ship a release, then issue under the new `kid`. A leaked token family is retired by removing its `kid` in a release.

## Revocation

A token is valid until it expires. Online components (hub, brain, runner heartbeat) also fetch a signed revocation list and refuse a token whose `rid` is listed once the entry's `effective` time has passed, within 15 minutes of publication. The offline CLI cannot be revoked before expiry. That is why terms are short and why a leaked key is handled by `kid` rotation. Say this plainly to customers.

List payload: `{ "v": 1, "kind": "revocations", "kid", "seq", "issuedAt", "entries": [ { "rid", "effective" } ] }`, signed like a token. Rules for readers:

- Accept a list only when its signature verifies under a trusted `kid` and its `seq` is higher than the last one seen. Keep the last good list when a newer one fails to verify.
- Each list is complete: it replaces the previous one, so keep earlier entries when you publish the next list.
- A token is revoked when `now >= effective` for its `rid`. Set `effective` in the past to cut a token off at once.

```bash
node enterprise/tools/sign-revocations.mjs --key <private-key-file> --kid k2 --seq 3 \
  --entries revocations.json --revoke lic_ab12@2027-03-01T00:00:00Z > revocations.txt
node enterprise/tools/sign-revocations.mjs --verify revocations.txt --pub k2.pub.b64
```
