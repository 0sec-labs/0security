---
title: Replicas and a shared database
description: Run several server replicas that share one PostgreSQL database for coordination (preview, enterprise license).
---

Server mode can run several replicas that share one PostgreSQL database. This page covers what the replicas share today, how to set it up and how to operate it. It is a preview, so read [what is not shared](#what-is-not-shared) before you rely on it.

## What is shared

With a shared database, the replicas share:

- One scheduler role. One replica leads and starts Sentinel triggers. The others stand by.
- A durable job queue. A job that a replica leaves unfinished goes back to the queue for another replica.
- Readiness. A replica that cannot reach the database answers 503 on `/readyz`, so the load balancer stops sending it requests.
- A sign-in session store. The store is built and tested. The server does not use it yet.

## What is not shared

These stay on each replica's own volume:

- Findings, scans, reports and Thread transcripts.
- Team accounts, SCIM tokens, API keys and the audit log.
- Sentinels and their triggers.

A standby replica does not run the Sentinel triggers stored in its own volume. A request that lands on another replica does not see this data. Until these move to the database, do not use replicas for production availability. Use one replica, as described in [Server mode and Docker](/server-mode/).

## Requirements

- The enterprise license feature `ha`. See [Free and paid](/server-mode/#free-and-paid).
- PostgreSQL 16 or newer, with TLS, backups and its own failover. 0 does not run a database for you.
- The same access token or team sign-in on every replica.
- A load balancer that checks `/readyz`.

## Connect the replicas to the database

Set the database in the process environment of every replica. Use a file for the URL so the password stays out of the process list:

```bash
export ZERO_HA_DATABASE_URL_FILE=/etc/0security/database-url
export ZERO_LICENSE_FILE=/etc/0security/license.txt
```

The file holds one line:

```
postgres://user:password@db.example.com:5432/zero?sslmode=verify-full
```

You can set `ZERO_HA_DATABASE_URL` instead, but not both. A database on another machine needs `sslmode` of `require`, `verify-ca` or `verify-full`. A repository, a project file or the database cannot set the URL.

Start each replica in server mode:

```bash
0security --host 0.0.0.0 --server-mode
```

The first replica creates the tables. The others wait for it, then check the version. Each replica prints which role it holds:

```
Shared database: db.example.com:5432/zero, this replica leads
```

## Run on Kubernetes

Create two Secrets. One holds the database URL, the other the license file:

```bash
kubectl -n zero create secret generic zero-db --from-file=database-url=./database-url
kubectl -n zero create secret generic zero-license --from-file=license=./license.txt
```

Install the chart with replicas turned on:

```bash
helm install zero deploy/helm/zero -n zero \
  --set secrets.existingSecret=zero-secrets \
  --set highAvailability.enabled=true \
  --set highAvailability.replicas=2 \
  --set highAvailability.databaseSecret.name=zero-db \
  --set highAvailability.licenseSecret.name=zero-license \
  --set 'highAvailability.databaseCIDRs={10.0.0.0/24}'
```

The chart gives each replica its own volume, keeps one replica up during a node drain and waits before SIGTERM so the load balancer drops the replica first. It refuses an install with no database Secret, no license Secret, no shared sign-in or no database address.

## Run with Compose

The file `deploy/compose/docker-compose.ha.yml` runs two replicas behind Caddy. Put the database URL and the license in `deploy/compose/secrets/`, then start it:

```bash
docker compose -f docker-compose.ha.yml up -d
```

The file does not start a database. Use a managed PostgreSQL with TLS.

## Upgrade without downtime

Upgrade one replica at a time. The first upgraded replica migrates the database. Older replicas keep working with the added tables.

A replica refuses to start when the database is newer than its version. Upgrade it to the same version as the others.

## Stop a replica

On SIGTERM a replica answers 503 on `/readyz`, gives up the scheduler role and stops taking jobs. Running jobs finish within the shutdown time. Set it with `--shutdown-timeout` (20 seconds by default). A job still running at the deadline goes back to the queue and runs again on another replica from the start.

Another replica takes the scheduler role within about 5 seconds.

If a replica is killed, its jobs wait out their 30 second lease. Then another replica takes them, and the attempt counts.

## Back up and restore

Back up the database with your provider's backups and point-in-time recovery. Back up each replica's volume as described in [Server mode and Docker](/server-mode/#back-up).

To restore, stop all replicas. Restore the database and the volumes from the same time. Then start the replicas.

## When the database is down

Every replica answers 503 on `/readyz`, so the load balancer sends no requests. The replicas keep running. They recover on their own within a few seconds of the database returning. `/healthz` stays 200, so the platform does not restart them.

## Troubleshooting

If the server stops at start with a license message, the license is missing, expired past its grace period, or lacks the `ha` feature. Check it with `0security config get license`.

If it stops with a message about the URL, the database is on another machine and the URL has no `sslmode`. Add one.

If it says the database is newer than this build, upgrade the replica.

If no replica leads, check that every replica reaches the same database and that connections to it are not cut after a short idle time.

## Limits

This preview has no load test and no test on a real cluster. The data that is not shared is listed above. Sessions are not stored in the database yet, so use one access token or OIDC with every replica.
