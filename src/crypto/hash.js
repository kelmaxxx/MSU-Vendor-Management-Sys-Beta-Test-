// Transaction hash + bcrypt helpers.

'use strict';

const crypto = require('node:crypto');
const bcrypt = require('bcrypt');

function transactionHash({ studentId, vendorId, amount, ts }) {
  const nonce = crypto.randomBytes(8).toString('hex');
  const payload = `${studentId}|${vendorId}|${amount}|${ts}|${nonce}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

async function hashPassword(plain) {
  return bcrypt.hash(plain, 12);
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

module.exports = { transactionHash, hashPassword, verifyPassword };
