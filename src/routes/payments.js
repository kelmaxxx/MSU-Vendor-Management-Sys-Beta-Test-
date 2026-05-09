'use strict';

const express = require('express');
const queries = require('../db/queries');
const { encrypt, decrypt } = require('../crypto/aes');
const { transactionHash } = require('../crypto/hash');
const { requireAuth } = require('../auth/rbac');
const { asyncHandler } = require('../middleware/audit');
const { paymentLimiter } = require('../middleware/rateLimit');

const router = express.Router();

// POST /api/payments
// Body: { studentCode, amount }  — vendor identity comes from the session.
router.post('/api/payments', requireAuth, paymentLimiter, asyncHandler(async (req, res) => {
  const v = req.session.vendor;
  const studentCode = String(req.body.studentCode || '').trim();
  const amountRaw = String(req.body.amount || '').trim();

  if (!/^[A-Za-z0-9-]{3,32}$/.test(studentCode)) {
    return res.status(400).json({ error: 'invalid_student_code' });
  }
  const amount = Number(amountRaw);
  if (!Number.isFinite(amount) || amount <= 0 || amount > 1000000) {
    return res.status(400).json({ error: 'invalid_amount' });
  }
  const amountStr = amount.toFixed(2);

  const student = await queries.findStudent(studentCode);
  if (!student) {
    await queries.writeAudit({
      userId: null, vendorId: v.id, action: 'payment.unknown_student',
      ip: req.ip, success: false, detail: { studentCode },
    }).catch(() => {});
    return res.status(404).json({ error: 'unknown_student' });
  }

  const balance = Number(decrypt({
    ct: student.balance_ct, iv: student.balance_iv, tag: student.balance_tag,
  }));
  if (balance < amount) {
    await queries.writeAudit({
      userId: student.id, vendorId: v.id,
      action: 'payment.insufficient_funds',
      ip: req.ip, success: false,
      detail: { studentCode, amount: amountStr },
    }).catch(() => {});
    const result = { status: 'failed', reason: 'insufficient_funds' };
    req.io && req.io.to(`vendor:${v.id}`).emit('payment:received', result);
    return res.status(402).json(result);
  }

  const newBal = (balance - amount).toFixed(2);
  const ts = new Date().toISOString();
  const txnHash = transactionHash({
    studentId: student.id, vendorId: v.id, amount: amountStr, ts,
  });

  const txnId = await queries.postPayment({
    vendorId: v.id,
    studentId: student.id,
    newBalance: encrypt(newBal),
    amount: encrypt(amountStr),
    txnHash,
  });

  const payload = {
    status: 'success',
    transactionId: txnId,
    txnHash,
    studentCode,
    studentName: student.name,
    amount: amountStr,
    ts,
  };
  req.io && req.io.to(`vendor:${v.id}`).emit('payment:received', payload);
  res.json(payload);
}));

module.exports = router;
