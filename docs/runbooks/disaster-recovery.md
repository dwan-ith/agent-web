# Disaster recovery and HA runbook

## Backup contract

Choose and document an RPO, RTO, retention schedule, encrypted off-site target, and restore owner before public operation. Include every content, authorization, nonce, WNS, and Registry database that the service must recover. Database snapshots are individually verified with SHA-256 plus SQLite quick and full integrity checks; the bundle is written to a new path and never overwrites an existing backup.

For one or more writer replicas, invoke every direct replica control origin rather than a load-balancer address:

```powershell
agent-web-ops coordinated-backup `
  --maintenance-url https://replica-a.publisher.example `
  --maintenance-url https://replica-b.publisher.example `
  --operator-token-file C:\secure\operator.token `
  --database content=C:\agent-web\content.db `
  --database authorization=C:\agent-web\authorization.db `
  --database nonces=C:\agent-web\nonces.db `
  --database wns=C:\agent-web\wns.db `
  --destination D:\backups\publisher-2026-08-06
```

The command drains every listed HTTP writer before snapshotting and releases all replicas in reverse order. It attempts release after partial drain or backup failure. Operators must separately stop scheduled indexers, migrations, administrative tools, and any writer not behind the maintenance middleware. Missing a replica or offline writer invalidates the coordinated-snapshot claim.

## Restore and failover

1. Isolate the failed deployment and preserve its disks and logs.
2. Run `agent-web-ops verify --bundle ...` on a host that cannot modify production state.
3. Restore into a new empty directory with `agent-web-ops restore`; never restore over live data.
4. Mount restored data read-write only to a quarantined publisher with external traffic disabled.
5. Confirm `/ready`, DID and WNS exact binding, object proofs, authorization grants, audit continuity, Registry source proofs, and human-view canonical links.
6. Exercise an authenticated read and a separately approved mutation, then create and verify a new backup.
7. Promote through the gateway, watch error, latency, security, and readiness alerts, and retain the old deployment for rollback until the recovery window closes.

SQLite is appropriate for the current single-writer reference services. Active-active multi-writer HA requires a transactional shared store or explicit partitioning and is not supplied by this repository. Multiple HTTP replicas must either share a storage design proven safe for SQLite in that environment or remain active-passive. The separate ANP access-token key must also be consistently available to replicas that validate each other's bearer tokens.

Run a restore drill at least quarterly and after schema, identity, key-custody, or deployment changes. Record achieved RPO/RTO, missing evidence, operator actions, alert delivery, and whether the restored service passed the public federation gate.
