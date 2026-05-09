// Postgres pool + per-request session-scoped vendor id (for RLS).
// Every query path that runs in a request context goes through withVendor()
// so RLS policies on transactions/audit_logs/vendors are enforced.

'use strict';

const { Pool } = require('pg');
const { db } = require('../config');

const pool = new Pool({
  host: db.host,
  port: db.port,
  database: db.database,
  user: db.user,
  password: db.password,
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  console.error('pg pool error', err);
});

// Run a callback inside a checked-out client where app.current_vendor_id
// has been set for the life of the transaction. RLS policies read this GUC.
async function withVendor(vendorId, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT set_config($1, $2, true)', [
      'app.current_vendor_id',
      String(vendorId),
    ]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) { /* ignore */ }
    throw err;
  } finally {
    client.release();
  }
}

// Anonymous query — used only for SECURITY DEFINER functions (login lookup,
// student lookup, etc.) that bypass RLS by design.
async function query(text, params) {
  return pool.query(text, params);
}

async function close() {
  await pool.end();
}

module.exports = { pool, withVendor, query, close };
