# enterprise/

This folder holds the paid features of 0security. The source is public so you can read it. Running it in production needs a license key.

The rest of the repository is open source under MIT OR Apache-2.0 and needs no key. See [LICENSING.md](../LICENSING.md).

## What is here

- The license check: a signed key, verified offline with a public key. It never contacts a server.
- The list of paid features: `findings-server`, `rbac`, `scim`, `saml`, `evidence-signing`, `audit-chain` and `retention`.
- SAML 2.0 sign-in for the team workspace (`saml`), in `src/saml/`. It uses the node-saml library for XML signatures and adds the SAML profile checks. See [SAML sign-in](../docs/src/content/docs/server-mode.md).
- Tools to create a signing keypair and to issue a key.

## Use it

Set one of these in the environment of the process that runs 0security:

```bash
export ZERO_LICENSE="<your key>"
export ZERO_LICENSE_FILE=/path/to/license.txt
```

Check what the key unlocks:

```bash
0security config get license
```

A key is read only from the environment or from the file that ZERO_LICENSE_FILE names. A repository or project file cannot supply one.

## When a key expires

Paid features keep working for 30 days with a warning. After that, paid writes stop. Reading, exporting and verifying your data keeps working, and the server always starts.

## Rules

Read [LICENSE](LICENSE). You can view and modify the code, and use it freely for development and testing. Production use needs a valid key. You cannot redistribute it, offer it as a service or remove the key check.

We do not accept outside pull requests for this folder.

## Develop

```bash
cd enterprise
npx vitest run
```

Every source file starts with a one-line header that points to `enterprise/LICENSE`. `node scripts/check-enterprise-boundary.mjs` enforces that, and keeps code outside this folder from importing it.
