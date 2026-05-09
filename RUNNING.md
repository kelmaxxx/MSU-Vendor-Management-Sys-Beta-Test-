# Running the MSU Vendor Portal — Step-by-Step (Windows)

Zero-to-running guide for someone new to Docker. All commands are PowerShell.

## What you need installed first

1. **Node.js 20+** — https://nodejs.org → "LTS" installer. After install, open a new PowerShell and run `node -v` (should print `v20.x` or higher).
2. **Docker Desktop for Windows** — https://www.docker.com/products/docker-desktop/. After install, **launch it once** and let it finish initializing (the whale icon in the system tray turns solid). Docker Desktop starts a Linux VM in the background; you don't have to do anything with it.
3. **OpenSSL** — usually already on your machine via **Git for Windows** (https://git-scm.com/download/win). Test with `openssl version`. If not found, install Git for Windows and re-open PowerShell.

That's it. You don't need to learn Docker — we use one command to start a database container and one to stop it.

## Step-by-step (run each block in PowerShell, in the project folder)

```powershell
cd "C:\kelma\Dev\MSU-Vendor Management Sys"
```

### 1. Install Node packages

```powershell
npm install
```

This reads `package.json` and downloads everything into `node_modules/`. Takes ~1 minute.

### 2. Start Postgres in Docker

```powershell
docker compose up -d
```

What this does: reads `docker-compose.yml`, downloads the `postgres:16-alpine` image (~80 MB, only the first time), starts a container named `msu_wallet_db`, and exposes Postgres on `localhost:5432`. The `-d` means "detached" — runs in the background.

Verify it's up:

```powershell
docker compose ps
```

You should see `msu_wallet_db` with status `running (healthy)`. If status says `starting`, wait ~10 seconds and re-check.

### 3. Create your `.env` file

```powershell
Copy-Item .env.example .env
```

Now generate two 64-char hex keys and paste them in:

```powershell
node -e "console.log('MASTER_KEY=' + require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
```

Open `.env` in your editor and **replace** the `MASTER_KEY=...` and `SESSION_SECRET=...` lines with the two values it printed. Leave the other values at their defaults — they match `docker-compose.yml` and the SQL files.

### 4. Generate the self-signed TLS certificate

```powershell
New-Item -ItemType Directory -Force -Path certs | Out-Null
openssl req -x509 -newkey rsa:4096 -nodes -days 365 `
  -keyout certs/server.key -out certs/server.cert `
  -subj "/CN=localhost"
```

This is what enables HTTPS. Browsers will warn about the cert (expected for local self-signed) — you'll click through it once.

### 5. Apply the database schema, RBAC, triggers, and seed

```powershell
npm run db:migrate
npm run db:seed
```

`db:migrate` runs the four `db/*.sql` files in order — creates tables, the two Postgres roles, RLS policies, and the audit triggers. `db:seed` then logs in as `admin_migration_role`, encrypts demo balances with your `MASTER_KEY`, and prints the demo logins.

You should see at the end:

```
Demo logins:
  vendor1@msu.test / Vendor1!Demo
  vendor2@msu.test / Vendor2!Demo
```

### 6. Start the portal

```powershell
npm start
```

You'll see: `MSU Vendor Portal listening on https://localhost:3443`.

Open **https://localhost:3443** in your browser. You'll get a "Your connection is not private" warning — that's the self-signed cert. Click **Advanced → Proceed to localhost (unsafe)**. (In Chrome/Edge you can also type `thisisunsafe` while the warning is focused.)

### 7. Try it end-to-end

1. Sign in as `vendor1@msu.test` / `Vendor1!Demo`.
2. The MFA setup page shows a QR code. Open Google Authenticator (or Microsoft Authenticator / Authy) on your phone and scan it. Enter the 6-digit code → click **Verify and enable**.
3. You're on the **Dashboard**. The big card says "Awaiting payment".
4. In the **Charge a student** form, enter `S-2026-0001` and amount `25.50`, click **Charge**. The status card flips green within a fraction of a second. The payment also lands in the **Recent transactions** table.
5. Visit **Transaction History** — your charge appears, scoped only to you.
6. Visit **Settlement Reports**, pick today's date, click **Generate** — it'll prompt for your TOTP code, then show the daily total.
7. Visit **Security** to see the audit log entries that were written automatically by the database trigger.

Stop the server with `Ctrl+C`.

## Run the security tests

```powershell
npm test
```

Runs four suites:
- **`crypto.test.js`** — AES-GCM round-trip + tamper detection (works without DB).
- **`sqli.test.js`** — fires `' OR 1=1 --`, UNION SELECT, stacked-statement payloads at every input. Asserts no data leaks (skips if DB unreachable).
- **`rbac.test.js`** — vendor A queries vendor B's transactions; RLS must return zero rows.
- **`audit.test.js`** — `UPDATE` and `DELETE` on `audit_logs` must be rejected by the trigger.

## Stopping / starting later

```powershell
# Stop the database container (data persists in a Docker volume)
docker compose stop

# Start it again next time
docker compose start

# Wipe everything and start fresh (deletes the data!)
docker compose down -v
```

## Common Windows gotchas

- **Port 5432 already in use** — you have another Postgres installed. Either stop it (`Stop-Service postgresql-x64-16`) or change the port in `docker-compose.yml` and `.env` (`PGPORT`).
- **Port 3443 already in use** — change `HTTPS_PORT` in `.env`.
- **`docker: command not found`** — Docker Desktop isn't running. Open it from the Start menu and wait for the whale icon to go solid.
- **`openssl: command not found`** — install Git for Windows, then re-open PowerShell.
- **TLS warning every time** — that's the self-signed cert. For a campus demo it's fine; for production you'd swap it for a real cert from Let's Encrypt or MSU IT.
- **Browser refuses to load Socket.IO** — make sure you accepted the TLS warning; the WebSocket uses the same cert.

That's the whole loop. The system is fully runnable as-is.
