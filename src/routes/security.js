'use strict';

const express = require('express');
const queries = require('../db/queries');
const { hashPassword, verifyPassword } = require('../auth/password');
const { requireAuth } = require('../auth/rbac');
const { requireMfa } = require('../auth/mfa');
const { asyncHandler } = require('../middleware/audit');

const router = express.Router();

router.get('/security', requireAuth, asyncHandler(async (req, res) => {
  const v = req.session.vendor;
  const audit = await queries.recentAuditLogs(v.id, 25);
  res.render('security', {
    vendor: v, audit,
    csrfToken: req.csrfToken(),
    notice: null, error: null,
    active: 'security',
  });
}));

router.post('/security/password', requireAuth, requireMfa, asyncHandler(async (req, res) => {
  const v = req.session.vendor;
  const current = String(req.body.current || '');
  const next = String(req.body.next || '');
  if (next.length < 10) {
    const audit = await queries.recentAuditLogs(v.id, 25);
    return res.status(400).render('security', {
      vendor: v, audit, csrfToken: req.csrfToken(),
      error: 'New password must be at least 10 characters.',
      notice: null, active: 'security',
    });
  }
  const row = await queries.findVendorByEmail(v.email);
  if (!row || !(await verifyPassword(current, row.password_hash))) {
    await queries.writeAudit({
      userId: v.id, vendorId: v.id, action: 'security.password_change.failed',
      ip: req.ip, success: false,
    }).catch(() => {});
    const audit = await queries.recentAuditLogs(v.id, 25);
    return res.status(401).render('security', {
      vendor: v, audit, csrfToken: req.csrfToken(),
      error: 'Current password is incorrect.', notice: null,
      active: 'security',
    });
  }
  await queries.changePassword(v.id, await hashPassword(next));
  await queries.writeAudit({
    userId: v.id, vendorId: v.id, action: 'security.password_changed',
    ip: req.ip, success: true,
  }).catch(() => {});
  const audit = await queries.recentAuditLogs(v.id, 25);
  res.render('security', {
    vendor: v, audit, csrfToken: req.csrfToken(),
    notice: 'Password updated.', error: null,
    active: 'security',
  });
}));

module.exports = router;
