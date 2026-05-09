-- MSU Akan Wallet — Vendor Portal schema
-- Run as the bootstrap superuser before 02_rbac.sql.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Vendors: campus merchants authorized to receive payments.
CREATE TABLE IF NOT EXISTS vendors (
  id              SERIAL PRIMARY KEY,
  vendor_code     TEXT NOT NULL UNIQUE,
  name            TEXT NOT NULL,
  email           TEXT NOT NULL UNIQUE,
  password_hash   TEXT NOT NULL,
  mfa_secret_ct   BYTEA,
  mfa_secret_iv   BYTEA,
  mfa_secret_tag  BYTEA,
  mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
  role            TEXT NOT NULL DEFAULT 'vendor' CHECK (role IN ('vendor', 'admin')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Students: wallet holders. Balance is encrypted at rest.
CREATE TABLE IF NOT EXISTS students (
  id            SERIAL PRIMARY KEY,
  student_code  TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  balance_ct    BYTEA NOT NULL,
  balance_iv    BYTEA NOT NULL,
  balance_tag   BYTEA NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Transactions: vendor receivables. Amount encrypted at rest.
CREATE TABLE IF NOT EXISTS transactions (
  id          SERIAL PRIMARY KEY,
  txn_hash    TEXT NOT NULL UNIQUE,
  student_id  INT NOT NULL REFERENCES students(id),
  vendor_id   INT NOT NULL REFERENCES vendors(id),
  amount_ct   BYTEA NOT NULL,
  amount_iv   BYTEA NOT NULL,
  amount_tag  BYTEA NOT NULL,
  status      TEXT NOT NULL CHECK (status IN ('success', 'failed', 'pending')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_txn_vendor_created
  ON transactions (vendor_id, created_at DESC);

-- Audit log: append-only. Every transaction + every sensitive action lands here.
CREATE TABLE IF NOT EXISTS audit_logs (
  id         BIGSERIAL PRIMARY KEY,
  ts         TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id    INT,
  vendor_id  INT,
  action     TEXT NOT NULL,
  txn_hash   TEXT,
  ip         INET,
  success    BOOLEAN NOT NULL DEFAULT TRUE,
  detail     JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_vendor_ts
  ON audit_logs (vendor_id, ts DESC);

-- Unauthorized access attempts (RBAC denials, RLS failures, etc.)
CREATE TABLE IF NOT EXISTS unauthorized_access_log (
  id                BIGSERIAL PRIMARY KEY,
  ts                TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempted_role    TEXT,
  attempted_action  TEXT,
  attempted_table   TEXT,
  ip                INET,
  detail            JSONB
);

-- Sessions table for connect-pg-simple.
CREATE TABLE IF NOT EXISTS "session" (
  sid     VARCHAR NOT NULL COLLATE "default" PRIMARY KEY,
  sess    JSON NOT NULL,
  expire  TIMESTAMP(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_expire ON "session" (expire);
