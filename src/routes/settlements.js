'use strict';

const express = require('express');
const queries = require('../db/queries');
const { decrypt } = require('../crypto/aes');
const { requireAuth } = require('../auth/rbac');
const { requireMfa } = require('../auth/mfa');
const { asyncHandler } = require('../middleware/audit');

const router = express.Router();

router.get('/settlements', requireAuth, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  res.render('settlements', {
    vendor: req.session.vendor,
    date: req.query.date || today,
    summary: null,
    csrfToken: req.csrfToken(),
    active: 'settlements',
  });
});

router.post('/settlements/generate', requireAuth, requireMfa, asyncHandler(async (req, res) => {
  const v = req.session.vendor;
  const date = String(req.body.date || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return res.status(400).render('settlements', {
      vendor: v, date: '', summary: null,
      csrfToken: req.csrfToken(),
      error: 'Invalid date.',
      active: 'settlements',
    });
  }

  const rows = await queries.settlementForDate(v.id, date);
  let total = 0, successCount = 0, failedCount = 0;
  const items = rows.map((r) => {
    const amount = Number(decrypt({ ct: r.amount_ct, iv: r.amount_iv, tag: r.amount_tag }));
    if (r.status === 'success') { total += amount; successCount += 1; }
    else { failedCount += 1; }
    return {
      txn_hash: r.txn_hash,
      status: r.status,
      amount: amount.toFixed(2),
      created_at: r.created_at,
    };
  });

  await queries.writeAudit({
    userId: v.id, vendorId: v.id, action: 'settlement.generated',
    ip: req.ip, success: true,
    detail: { date, total: total.toFixed(2), count: items.length },
  }).catch(() => {});

  const summary = {
    date, total: total.toFixed(2), successCount, failedCount, items,
  };

  if (req.body.format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition',
      `attachment; filename="settlement-${date}.csv"`);
    res.write('txn_hash,status,amount,created_at\n');
    for (const it of items) {
      res.write(`${it.txn_hash},${it.status},${it.amount},${it.created_at.toISOString()}\n`);
    }
    res.write(`,,${summary.total},TOTAL\n`);
    return res.end();
  }

  res.render('settlements', {
    vendor: v, date, summary,
    csrfToken: req.csrfToken(),
    active: 'settlements',
  });
}));

module.exports = router;
