// AES-256-GCM authenticated encryption.
// Random 12-byte IV per record; 16-byte auth tag.
// Tampered ciphertext or tag triggers a decryption error.

'use strict';

const crypto = require('node:crypto');
const { masterKey } = require('../config');

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;
const TAG_LEN = 16;

function encrypt(plaintext) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, masterKey, iv, { authTagLength: TAG_LEN });
  const ct = Buffer.concat([
    cipher.update(Buffer.from(String(plaintext), 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return { ct, iv, tag };
}

function decrypt({ ct, iv, tag }) {
  if (!ct || !iv || !tag) throw new Error('decrypt: missing field');
  const decipher = crypto.createDecipheriv(ALGO, masterKey, iv, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString('utf8');
}

module.exports = { encrypt, decrypt };
