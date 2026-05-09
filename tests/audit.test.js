'use strict';

// Verifies audit_logs immutability: triggers raise on UPDATE / DELETE.

process.env.MASTER_KEY = process.env.MASTER_KEY || 'a'.repeat(64);
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'x'.repeat(64);

const test = require('node:test');
const assert = require('node:assert/strict');

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

test('UPDATE on audit_logs raises append-only exception', async (t) => {
  if (!(await dbReachable())) return t.skip('Postgres not reachable');
  const { pool } = require('../src/db/pool');

  // Insert a row first (the app role is allowed to INSERT).
  await pool.query(
    `INSERT INTO audit_logs (action, success) VALUES ($1, $2)`,
    ['test.audit_immutability', true]
  );

  await assert.rejects(
    () => pool.query(
      `UPDATE audit_logs SET action = 'tampered' WHERE action = $1`,
      ['test.audit_immutability']
    ),
    /append-only|permission/i,
    'UPDATE on audit_logs must be rejected'
  );
});

test('DELETE on audit_logs raises append-only exception', async (t) => {
  if (!(await dbReachable())) return t.skip('Postgres not reachable');
  const { pool } = require('../src/db/pool');

  await assert.rejects(
    () => pool.query(
      `DELETE FROM audit_logs WHERE action = $1`,
      ['test.audit_immutability']
    ),
    /append-only|permission/i,
    'DELETE on audit_logs must be rejected'
  );
});
