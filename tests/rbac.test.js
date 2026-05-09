'use strict';

// Verifies Row-Level Security: vendor A cannot read vendor B's transactions.
// Requires the demo seed (npm run db:seed).

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

test('listTransactions for vendor A excludes vendor B rows', async (t) => {
  if (!(await dbReachable())) return t.skip('Postgres not reachable');

  const queries = require('../src/db/queries');
  const { pool, withVendor } = require('../src/db/pool');

  // Find two vendor ids.
  const { rows: vs } = await pool.query(
    'SELECT id FROM vendors ORDER BY id LIMIT 2'
  );
  if (vs.length < 2) return t.skip('Need at least 2 seeded vendors');

  const [vA, vB] = vs;

  // While scoped to vendor A, query for vendor B's rows directly.
  const bRowsViaA = await withVendor(vA.id, async (client) => {
    const { rows } = await client.query(
      'SELECT id FROM transactions WHERE vendor_id = $1', [vB.id]
    );
    return rows;
  });

  assert.equal(bRowsViaA.length, 0,
    'Vendor A must not see any of vendor B\'s transactions');
});
