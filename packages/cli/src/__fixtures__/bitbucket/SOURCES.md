Pinned excerpts of the vendors' published API contracts, used by the Bitbucket contract tests.

- cloud-contract.json: https://api.bitbucket.org/swagger.json (retrieved 2026-11-23)
- dc-contract.json: https://dac-static.atlassian.com/server/bitbucket/9.6.swagger.v3.json (retrieved 2026-11-23)
- dc-pr-from-ref-updated.json: the pr:from_ref_updated sample at https://confluence.atlassian.com/bitbucketserver/event-payload-938025882.html (trimmed: links and unused user fields removed)
- cloud-pullrequest-created.json: built from the Pull Request property shown at https://support.atlassian.com/bitbucket-cloud/docs/event-payloads/ (the page documents the shape; the values are made up)
- Webhook signature: both products send `X-Hub-Signature: sha256=<hex HMAC of the body>`. The test vector (secret "It's a Secret to Everybody", body "Hello World!", signature sha256=a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9) is from https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/

Nothing here was checked against a live Bitbucket.
