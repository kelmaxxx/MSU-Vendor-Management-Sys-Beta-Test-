# MSU Akan Vendor Management Portal

Vendor-side component of the MSU Akan Student Digital Wallet Security Framework.

A high-speed, security-hardened portal for authorized campus vendors to receive student payments, verify them in real time, view their own transaction ledger, and generate daily settlement reports.

## What's in the box

| Pillar | Implementation |
|---|---|
| **Real-time payments** | Express + Socket.IO. The dashboard's large status indicator flips green (`✓ Success`) or red (`✗ Failed`) within ~hundreds of ms of a payment. |
| **AES-256 at rest** | `aes-256-gcm` with random 12-byte IV + 16-byte auth tag per record, applied to balances, amounts, and the encrypted MFA secret. Master key in env, never in DB. |
| **TLS in transit** | HTTPS server (`https.createServer`) with self-signed cert for local demo. HSTS, CSP, no-referrer enforced via Helmet. |
| **RBAC + Least Privilege** | Two Postgres roles — `admin_migration_role` owns the schema; `vendor_app_role` (the app) gets `SELECT` on lookup tables, `INSERT` on `transactions` / `audit_logs`, **no** `UPDATE`/`DELETE`/`DROP`/`ALTER`/`GRANT`/`TRUNCATE` anywhere. Mutations go through `SECURITY DEFINER` functions that validate inputs. |
| **Row-Level Security** | RLS policies on `vendors`, `transactions`, `audit_logs` enforce vendor scoping at the DB layer using `app.current_vendor_id`. Defense-in-depth even if app checks are bypassed. |
| **Prepared statements** | Every query is parameterized via `pg` (`$1, $2, …`). No string concatenation. |
| **Immutable audit log** | Postgres trigger writes an `audit_logs` row on every transaction insert. Separate triggers raise on any `UPDATE` or `DELETE` against `audit_logs`. SHA-256 transaction hash bound to `(student_id, vendor_id, amount, ts, nonce)`. |
| **Unauthorized-access logging** | Event trigger on `sql_drop` and a `log_unauthorized_access()` SECURITY DEFINER function that the app middleware calls when it catches `permission denied` (42501). |
| **TOTP MFA** | `speakeasy`-based; required at login, before `POST /settlements/generate`, and before any `/security/*` change. Encrypted secret at rest. |
| **CSRF, rate limits, sessions** | `csurf` for all forms; `express-rate-limit` on `/login`, `/mfa`, `/api/payments`; `express-session` with `connect-pg-simple` storage and `httpOnly`, `secure`, `sameSite=strict` cookies. |

## Project layout

```
db/        SQL — schema, RBAC, triggers, seed
scripts/   Node migration + seed runners
src/
  config.js           env loader, validates MASTER_KEY
  server.js           HTTPS + Express + Socket.IO bootstrap
  crypto/             AES-256-GCM, transaction hash, bcrypt
  auth/               password, MFA (speakeasy + qrcode), RBAC middleware
  middleware/         security headers, rate limiting, audit error wrapper
  db/                 pg pool with per-request RLS context, parameterized queries
  routes/             auth, dashboard, payments, transactions, settlements, security
  realtime/io.js      Socket.IO server (room-per-vendor)
  views/              EJS templates
public/    static assets (CSS + dashboard.js)
tests/     SQLi, RBAC, audit, crypto suites
```

## Quick start (local demo)

```bash
# 1. Postgres
docker compose up -d

# 2. Install deps
npm install

# 3. Generate keys for .env
cp .env.example .env
# Set MASTER_KEY, SESSION_SECRET (each: `openssl rand -hex 32`)

# 4. Self-signed TLS cert
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
  -keyout certs/server.key -out certs/server.cert \
  -subj "/CN=localhost"

# 5. Apply schema, RBAC, triggers, then seed encrypted demo data
npm run db:migrate
npm run db:seed

# 6. Run
npm start
# → https://localhost:3443
```

Demo logins (printed by `db:seed`):

- `vendor1@msu.test` / `Vendor1!Demo` (Akan Campus Cafe)
- `vendor2@msu.test` / `Vendor2!Demo` (Akan Bookshop)

After login you'll be guided through TOTP enrollment (scan the QR with Google Authenticator).

### Demo a payment

From the dashboard, fill in **Student code** (e.g. `S-2026-0001`) and **Amount**, then **Charge**. The status card will flash green within a fraction of a second; the transaction lands in `transactions`, and the trigger immediately appends an `audit_logs` row with the SHA-256 transaction hash.

## Tests

```bash
npm test
```

Covers (per the brief's Phase 4):

- **`tests/sqli.test.js`** — fires `' OR 1=1 --`, `UNION SELECT`, and stacked-statement payloads at every input field; asserts no data leak.
- **`tests/rbac.test.js`** — vendor A cannot read vendor B's transactions even by guessing IDs (RLS enforces).
- **`tests/audit.test.js`** — `UPDATE audit_logs` and `DELETE FROM audit_logs` raise `audit_logs is append-only`.
- **`tests/crypto.test.js`** — encrypt → decrypt round-trip succeeds; flipping any byte of `ct` or `tag` causes `decrypt` to throw.

## Roadmap mapping

| Phase | Where it lives |
|---|---|
| **1. Architecture** — schema + protocols | `db/01_schema.sql`, `db/02_rbac.sql`, `db/03_triggers.sql`, `package.json`, `docker-compose.yml`, `src/server.js` |
| **2. Logic** — payment API + secure queries | `src/routes/*`, `src/db/queries.js`, `src/realtime/io.js`, `src/views/*` |
| **3. Hardening** — encryption, MFA, audit triggers | `src/crypto/*`, `src/auth/mfa.js`, `src/middleware/*`, `db/03_triggers.sql` |
| **4. Testing** — SQLi simulation + audit verification | `tests/*` |

## Security notes

- **MASTER_KEY rotation** is intentionally manual and out of scope for the local demo. In production we'd front it with a KMS (AWS KMS, GCP KMS, HashiCorp Vault).
- The self-signed cert in `certs/` is only valid on `localhost`. Browsers will warn — this is expected for the academic build.
- `.env` is gitignored. Never commit it.


