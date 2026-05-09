// Apply db/*.sql files in order, connected as the bootstrap superuser
// for the first run (so it can create roles), then handing schema ownership
// to admin_migration_role.

'use strict';

require('dotenv').config();
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

async function run() {
  const client = new Client({
    host: process.env.PGHOST,
    port: Number(process.env.PGPORT || 5432),
    database: process.env.PGDATABASE,
    user: 'postgres',
    password: process.env.POSTGRES_PASSWORD,
  });
  await client.connect();

  const files = ['01_schema.sql', '02_rbac.sql', '03_triggers.sql', '04_seed.sql'];
  for (const f of files) {
    const sql = fs.readFileSync(path.join(__dirname, '..', 'db', f), 'utf8');
    process.stdout.write(`Applying ${f} ... `);
    await client.query(sql);
    console.log('ok');
  }

  await client.end();
  console.log('Migration complete.');
}

run().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
