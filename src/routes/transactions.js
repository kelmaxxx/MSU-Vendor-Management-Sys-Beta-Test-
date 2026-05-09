'use strict';

const express = require('express');
const queries = require('../db/queries');
const { decrypt } = require('../crypto/aes');
const { requireAuth } = require('../auth/rbac');
const { asyncHandler } = require('../middleware/audit');

const router = express.Router();

router.get('/transactions', requireAuth, asyncHandler(async (req, res) => {
  const v = req.session.vendor;
  const { from, to, status, page } = req.query;
  const pageNum = Math.max(1, Number(page) || 1);
  const limit = 50;
  const offset = (pageNum - 1) * limit;

  const rows = await queries.listTransactions(v.id, {
    from: from && /^\d{4}-\d{2}-\d{2}$/.test(from) ? from : null,
    to:   to   && /^\d{4}-\d{2}-\d{2}$/.test(to)   ? to   : null,
    status,
    limit,
    offset,
  });

  const txns = rows.map((t) => ({
    id: t.id,
    txn_hash: t.txn_hash,
    status: t.status,
    created_at: t.created_at,
    amount: decrypt({ ct: t.amount_ct, iv: t.amount_iv, tag: t.amount_tag }),
  }));

  if (req.query.format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition',
      `attachment; filename="transactions-${pageNum}.csv"`);
    res.write('id,txn_hash,status,amount,created_at\n');
    for (const t of txns) {
      res.write(`${t.id},${t.txn_hash},${t.status},${t.amount},${t.created_at.toISOString()}\n`);
    }
    return res.end();
  }

  res.render('transactions', {
    vendor: v, txns,
    filters: { from: from || '', to: to || '', status: status || '' },
    page: pageNum,
    csrfToken: req.csrfToken(),
    active: 'transactions',
  });
}));

module.exports = router;
