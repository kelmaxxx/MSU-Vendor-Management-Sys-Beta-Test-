'use strict';

const express = require('express');
const queries = require('../db/queries');
const { verifyPassword, hashPassword } = require('../auth/password');
const mfa = require('../auth/mfa');
const { asyncHandler } = require('../middleware/audit');
const { loginLimiter, mfaLimiter } = require('../middleware/rateLimit');

const router = express.Router();

router.get('/login', (req, res) => {
  res.render('login', { error: null, csrfToken: req.csrfToken() });
});

router.post('/login', loginLimiter, asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  const vendor = await queries.findVendorByEmail(String(email || ''));
  const ok = vendor && (await verifyPassword(String(password || ''), vendor.password_hash));
  if (!ok) {
    await queries.writeAudit({
      action: 'login.failed',
      ip: req.ip,
      success: false,
      detail: { email: String(email || '').slice(0, 80) },
    }).catch(() => {});
    return res.status(401).render('login', {
      error: 'Invalid credentials.',
      csrfToken: req.csrfToken(),
    });
  }

  req.session.vendor = {
    id: vendor.id,
    code: vendor.vendor_code,
    name: vendor.name,
    email: vendor.email,
    role: vendor.role,
  };
  req.session.mfaPending = vendor.mfa_enabled;

  await queries.writeAudit({
    userId: vendor.id, vendorId: vendor.id,
    action: 'login.success', ip: req.ip, success: true,
  }).catch(() => {});

  if (vendor.mfa_enabled) return res.redirect('/mfa/verify');
  return res.redirect('/mfa/setup');
}));

router.get('/mfa/setup', asyncHandler(async (req, res) => {
  if (!req.session.vendor) return res.redirect('/login');
  const enrollment = await mfa.beginEnrollment(req.session.vendor);
  req.session.pendingMfaSecret = enrollment.base32;
  res.render('mfa-setup', {
    qr: enrollment.qrDataUrl,
    secret: enrollment.base32,
    csrfToken: req.csrfToken(),
    error: null,
  });
}));

router.post('/mfa/setup', mfaLimiter, asyncHandler(async (req, res) => {
  if (!req.session.vendor || !req.session.pendingMfaSecret) {
    return res.redirect('/login');
  }
  const ok = await mfa.completeEnrollment(
    req.session.vendor.id,
    req.session.pendingMfaSecret,
    String(req.body.token || '')
  );
  if (!ok) {
    const enrollment = await mfa.beginEnrollment(req.session.vendor);
    req.session.pendingMfaSecret = enrollment.base32;
    return res.status(400).render('mfa-setup', {
      qr: enrollment.qrDataUrl,
      secret: enrollment.base32,
      csrfToken: req.csrfToken(),
      error: 'Invalid code. Try again.',
    });
  }
  delete req.session.pendingMfaSecret;
  req.session.mfaVerifiedAt = Date.now();
  req.session.mfaPending = false;
  await queries.writeAudit({
    userId: req.session.vendor.id, vendorId: req.session.vendor.id,
    action: 'mfa.enrolled', ip: req.ip, success: true,
  }).catch(() => {});
  res.redirect('/dashboard');
}));

router.get('/mfa/verify', (req, res) => {
  if (!req.session.vendor) return res.redirect('/login');
  res.render('mfa-verify', { csrfToken: req.csrfToken(), error: null });
});

router.post('/mfa/verify', mfaLimiter, asyncHandler(async (req, res) => {
  if (!req.session.vendor) return res.redirect('/login');
  const ok = await mfa.verifyToken(
    req.session.vendor.id,
    String(req.body.token || '')
  );
  if (!ok) {
    await queries.writeAudit({
      userId: req.session.vendor.id, vendorId: req.session.vendor.id,
      action: 'mfa.failed', ip: req.ip, success: false,
    }).catch(() => {});
    return res.status(401).render('mfa-verify', {
      csrfToken: req.csrfToken(),
      error: 'Invalid code.',
    });
  }
  req.session.mfaVerifiedAt = Date.now();
  req.session.mfaPending = false;
  await queries.writeAudit({
    userId: req.session.vendor.id, vendorId: req.session.vendor.id,
    action: 'mfa.verified', ip: req.ip, success: true,
  }).catch(() => {});
  const ret = req.session.mfaReturnTo || '/dashboard';
  delete req.session.mfaReturnTo;
  res.redirect(ret);
}));

router.post('/logout', (req, res) => {
  const v = req.session.vendor;
  req.session.destroy(() => {
    if (v) {
      queries.writeAudit({
        userId: v.id, vendorId: v.id, action: 'logout',
        ip: req.ip, success: true,
      }).catch(() => {});
    }
    res.redirect('/login');
  });
});

module.exports = router;
