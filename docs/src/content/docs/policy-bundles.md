---
title: Signed policy bundles
description: Use a fix policy that was signed by a key you trust, and refuse tampered or replayed copies.
---

A policy bundle is your fix policy (the same file `--policy` takes) wrapped in a small signed envelope. Use it when a team or a central owner hands policy to many machines and you want each machine to check where it came from.

Verification is offline and uses Ed25519. It only checks and applies. It does not schedule fetches and it adds no policy language: the verified text goes through the same parser as `--policy`, so approved libraries, rules and pull request settings behave the same.

```bash
0security findings fix <id> --policy-bundle ./policy.bundle.json --policy-bundle-key-file /etc/0/policy-signer.pub
0security findings fix <id> --policy-bundle https://example.com/policy.bundle.json --policy-bundle-key-file /etc/0/policy-signer.pub
```

## Keys

You choose which keys to trust, through two separate options that never fall back to each other. `--policy-bundle-key` takes the key itself as inline text: PEM, or 32 raw bytes in base64 or hex. It is never opened as a path, so a bad value is an error and a file in the repository with the same name changes nothing. `--policy-bundle-key-file` takes a file holding one key. The path must be absolute, must not be a symlink, and must be outside the current folder, its git working tree, and every repository the command reads (the one named with `--repo` and the repository it resolves to), checked after resolving symlinks, because a repository could otherwise plant its own key. Repeat either option for several keys, or set `ZERO_POLICY_BUNDLE_KEY` (inline, comma separated) or `ZERO_POLICY_BUNDLE_KEY_FILE` (paths, comma separated). With no key configured a bundle is always refused.

## Format

```json
{ "format": "0-policy-bundle/1", "version": 3, "policy": "<base64 of the policy file>", "signature": "<base64 Ed25519 signature>" }
```

The signature covers the text `0-policy-bundle/1`, a newline, the version, a newline, then the exact policy bytes. Changing the policy or the version breaks it.

## What is refused

- A signature that matches none of your keys (tampered content or a different signer).
- A malformed envelope: bad JSON, wrong format, a version that is not a positive integer, bad base64, a policy that is not UTF-8.
- A replay. After a bundle is accepted, its version is stored per signing key in `~/.0/policy-bundle-state.json`. A lower version is refused, and so is the same version with different content. The same bundle again is fine. If the state file is damaged the run stops rather than resetting the floor.
- A URL that is not https, a redirect, or an address on a private or local network. A bundle is at most 192 KiB.

A refused bundle is never applied and never recorded. `--policy-bundle` cannot be combined with `--policy`. `ZERO_ENTERPRISE` blocks the URL form; a file path still works. See [Data flow](/data-flow/) for the single request a URL makes.

## Signing

Any Ed25519 tool works. With Node:

```js
import { sign } from "node:crypto";
const bytes = Buffer.from(policyText);
const signature = sign(null, Buffer.concat([Buffer.from(`0-policy-bundle/1\n${version}\n`), bytes]), privateKey).toString("base64");
```

Keep the private key off the machines that verify.
