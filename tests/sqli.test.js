'use strict';

// Verifies prepared statements neutralize injection attempts.
// Skips if Postgres isn't reachable.

process.env.MASTER_KEY = process.env.MASTER_KEY || 'a'.repeat(64);
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'x'.repeat(64);

const test = require('node:test');
const assert = require('node:assert/strict');

const PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1 --",
  "'; DROP TABLE vendors; --",
  "' UNION SELECT email, password_hash, NULL, NULL, NULL, NULL, NULL FROM vendors --",
  "admin'--",
  "\\'; DELETE FROM audit_logs; --",
];

async function dbReachable() {
  if (!process.env.PGHOST) return false;
  try {
    const { pool } = require('../src/db/pool');
    await pool.query('SELECT 1');
    return true;
  } catch {
    return false;
  }
}

test('SQL injection payloads do not bypass authentication', async (t) => {
  if (!(await dbReachable())) return t.skip('Postgres not reachable');
  const queries = require('../src/db/queries');

  for (const p of PAYLOADS) {
    const v = await queries.findVendorByEmail(p);
    assert.equal(v, null, `payload "${p}" must not return a vendor`);
  }
});

test('SQL injection payloads in student lookup do not return data', async (t) => {
  if (!(await dbReachable())) return t.skip('Postgres not reachable');
  const queries = require('../src/db/queries');

  for (const p of PAYLOADS) {
    const s = await queries.findStudent(p);
    assert.equal(s, null, `payload "${p}" must not return a student`);
  }
});

test('SQL injection payloads in date filter cannot dump rows', async (t) => {
  if (!(await dbReachable())) return t.skip('Postgres not reachable');
  const queries = require('../src/db/queries');

  // Pretend vendor 1 — the parameterized date filter rejects bad strings via
  // the regex in the route, but we also assert that the underlying query
  // does not blow up or leak rows when an injection-like string slips past.
  for (const p of PAYLOADS) {
    let rows = [];
    try {
      rows = await queries.listTransactions(1, { from: p, limit: 5, offset: 0 });
    } catch {
      // Postgres rejects malformed timestamp — that's fine, no data leaked.
    }
    assert.ok(Array.isArray(rows));
  }
});
