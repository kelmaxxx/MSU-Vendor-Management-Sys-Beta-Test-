// Populates encrypted columns + bcrypt password hashes for demo accounts.
// Connects as admin_migration_role so it can UPDATE balances and password_hash.

'use strict';

require('dotenv').config();
const { Client } = require('pg');
const bcrypt = require('bcrypt');
const { encrypt } = require('../src/crypto/aes');

async function run() {
  const client = new Client({
    host: process.env.PGHOST,
    port: Number(process.env.PGPORT || 5432),
    database: process.env.PGDATABASE,
    user: process.env.PG_ADMIN_USER,
    password: process.env.PG_ADMIN_PASSWORD,
  });
  await client.connect();

  const vendors = [
    { email: 'vendor1@msu.test', password: 'Vendor1!Demo' },
    { email: 'vendor2@msu.test', password: 'Vendor2!Demo' },
  ];

  for (const v of vendors) {
    const hash = await bcrypt.hash(v.password, 12);
    await client.query(
      'UPDATE vendors SET password_hash = $1 WHERE email = $2',
      [hash, v.email]
    );
    console.log(`Set password for ${v.email}`);
  }

  const balances = [
    { code: 'S-2026-0001', amount: '500.00' },
    { code: 'S-2026-0002', amount: '250.00' },
    { code: 'S-2026-0003', amount: '120.50' },
  ];
  for (const b of balances) {
    const enc = encrypt(b.amount);
    await client.query(
      `UPDATE students
          SET balance_ct = $1, balance_iv = $2, balance_tag = $3
        WHERE student_code = $4`,
      [enc.ct, enc.iv, enc.tag, b.code]
    );
    console.log(`Set balance for ${b.code} = ${b.amount}`);
  }

  await client.end();
  console.log('Seed complete. Demo logins:');
  for (const v of vendors) console.log(`  ${v.email} / ${v.password}`);
}

run().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
