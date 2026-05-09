'use strict';

const express = require('express');
const queries = require('../db/queries');
const { decrypt } = require('../crypto/aes');
const { requireAuth } = require('../auth/rbac');
const { asyncHandler } = require('../middleware/audit');

const router = express.Router();

router.get('/dashboard', requireAuth, asyncHandler(async (req, res) => {
  const v = req.session.vendor;
  const txns = await queries.listTransactions(v.id, { limit: 5, offset: 0 });
  const recent = txns.map((t) => ({
    id: t.id,
    txn_hash: t.txn_hash,
    status: t.status,
    created_at: t.created_at,
    amount: decrypt({ ct: t.amount_ct, iv: t.amount_iv, tag: t.amount_tag }),
  }));
  res.render('dashboard', {
    vendor: v,
    recent,
    csrfToken: req.csrfToken(),
    active: 'dashboard',
  });
}));

module.exports = router;
