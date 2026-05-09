'use strict';

// Round-trip + tamper detection for AES-256-GCM.
// Run with: node --test tests/crypto.test.js
// Requires MASTER_KEY in env (any 32-byte hex value works for tests).

process.env.MASTER_KEY = process.env.MASTER_KEY ||
  'a'.repeat(64);
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'x'.repeat(64);

const test = require('node:test');
const assert = require('node:assert/strict');
const { encrypt, decrypt } = require('../src/crypto/aes');

test('encrypt → decrypt round-trip', () => {
  const e = encrypt('500.00');
  assert.equal(decrypt(e), '500.00');
});

test('flipping a ciphertext byte rejects decryption', () => {
  const e = encrypt('hello world');
  const ct = Buffer.from(e.ct);
  ct[0] = ct[0] ^ 0xff;
  assert.throws(() => decrypt({ ct, iv: e.iv, tag: e.tag }));
});

test('flipping an auth-tag byte rejects decryption', () => {
  const e = encrypt('hello world');
  const tag = Buffer.from(e.tag);
  tag[0] = tag[0] ^ 0xff;
  assert.throws(() => decrypt({ ct: e.ct, iv: e.iv, tag }));
});

test('IV is 12 bytes and tag is 16 bytes', () => {
  const e = encrypt('x');
  assert.equal(e.iv.length, 12);
  assert.equal(e.tag.length, 16);
});

test('two encryptions of same plaintext produce different ciphertexts', () => {
  const a = encrypt('same');
  const b = encrypt('same');
  assert.notEqual(a.ct.toString('hex'), b.ct.toString('hex'));
  assert.notEqual(a.iv.toString('hex'), b.iv.toString('hex'));
});
