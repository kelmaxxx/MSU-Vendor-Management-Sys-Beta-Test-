'use strict';

require('dotenv').config();

function required(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const masterKeyHex = required('MASTER_KEY');
if (!/^[0-9a-fA-F]{64}$/.test(masterKeyHex)) {
  throw new Error('MASTER_KEY must be 32 bytes (64 hex chars). Generate with: openssl rand -hex 32');
}

module.exports = {
  env: process.env.NODE_ENV || 'development',
  httpsPort: Number(process.env.HTTPS_PORT || 3443),
  tls: {
    keyPath: process.env.TLS_KEY_PATH || './certs/server.key',
    certPath: process.env.TLS_CERT_PATH || './certs/server.cert',
  },
  db: {
    host: process.env.PGHOST,
    port: Number(process.env.PGPORT || 5432),
    database: process.env.PGDATABASE,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
  },
  masterKey: Buffer.from(masterKeyHex, 'hex'),
  sessionSecret: required('SESSION_SECRET'),
  mfa: {
    issuer: process.env.MFA_ISSUER || 'MSU Akan Wallet',
    windowMinutes: Number(process.env.MFA_WINDOW_MINUTES || 5),
  },
};
