// TOTP MFA via speakeasy (RFC 6238). Secret is encrypted at rest with AES-256-GCM.

'use strict';

const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { encrypt, decrypt } = require('../crypto/aes');
const { mfa: cfg } = require('../config');
const queries = require('../db/queries');

async function beginEnrollment(vendor) {
  const secret = speakeasy.generateSecret({
    name: `${cfg.issuer} (${vendor.email})`,
    issuer: cfg.issuer,
    length: 20,
  });
  const otpauth = secret.otpauth_url;
  const qrDataUrl = await qrcode.toDataURL(otpauth);
  return { base32: secret.base32, otpauth, qrDataUrl };
}

async function completeEnrollment(vendorId, base32Secret, token) {
  const ok = speakeasy.totp.verify({
    secret: base32Secret,
    encoding: 'base32',
    token,
    window: 1,
  });
  if (!ok) return false;
  const enc = encrypt(base32Secret);
  await queries.enrollMfa(vendorId, enc.ct, enc.iv, enc.tag);
  return true;
}

async function verifyToken(vendorId, token) {
  const row = await queries.getMfaSecret(vendorId);
  if (!row || !row.mfa_enabled || !row.mfa_secret_ct) return false;
  const base32 = decrypt({
    ct: row.mfa_secret_ct,
    iv: row.mfa_secret_iv,
    tag: row.mfa_secret_tag,
  });
  return speakeasy.totp.verify({
    secret: base32,
    encoding: 'base32',
    token,
    window: 1,
  });
}

// requireMfa middleware: forces a fresh MFA check (within window) before
// fund-settlement or security-setting changes.
function requireMfa(req, res, next) {
  const ts = req.session && req.session.mfaVerifiedAt;
  const ok = ts && Date.now() - ts < cfg.windowMinutes * 60 * 1000;
  if (!ok) {
    req.session.mfaReturnTo = req.originalUrl;
    return res.redirect('/mfa/verify');
  }
  next();
}

module.exports = { beginEnrollment, completeEnrollment, verifyToken, requireMfa };
