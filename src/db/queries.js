// Every database call lives here. ALL parameterized — no string concat.
// Functions that bypass RLS (login, student lookup) call SECURITY DEFINER fns.

'use strict';

const { pool, withVendor, query } = require('./pool');

async function findVendorByEmail(email) {
  const { rows } = await query('SELECT * FROM find_vendor_for_login($1)', [email]);
  return rows[0] || null;
}

async function findStudent(studentCode) {
  const { rows } = await query('SELECT * FROM find_student($1)', [studentCode]);
  return rows[0] || null;
}

async function getMfaSecret(vendorId) {
  const { rows } = await query('SELECT * FROM get_mfa_secret($1)', [vendorId]);
  return rows[0] || null;
}

async function enrollMfa(vendorId, ct, iv, tag) {
  await query('SELECT enroll_mfa($1, $2, $3, $4)', [vendorId, ct, iv, tag]);
}

async function changePassword(vendorId, newHash) {
  await query('SELECT change_password($1, $2)', [vendorId, newHash]);
}

// Reads vendor's own transactions, scoped by RLS to the current vendor.
async function listTransactions(vendorId, { from, to, status, limit = 50, offset = 0 }) {
  return withVendor(vendorId, async (client) => {
    const params = [];
    const where = ['vendor_id = $1'];
    params.push(vendorId);

    if (from) { params.push(from); where.push(`created_at >= $${params.length}`); }
    if (to)   { params.push(to);   where.push(`created_at <= $${params.length}`); }
    if (status && ['success', 'failed', 'pending'].includes(status)) {
      params.push(status); where.push(`status = $${params.length}`);
    }
    params.push(limit, offset);
    const sql = `
      SELECT id, txn_hash, student_id, vendor_id, amount_ct, amount_iv, amount_tag,
             status, created_at
        FROM transactions
       WHERE ${where.join(' AND ')}
       ORDER BY created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`;
    const { rows } = await client.query(sql, params);
    return rows;
  });
}

async function postPayment({
  vendorId, studentId, newBalance, amount, txnHash,
}) {
  // newBalance and amount are { ct, iv, tag } objects from aes.encrypt().
  return withVendor(vendorId, async (client) => {
    const { rows } = await client.query(
      `SELECT post_payment($1,$2,$3,$4,$5,$6,$7,$8,$9) AS id`,
      [
        studentId, vendorId,
        newBalance.ct, newBalance.iv, newBalance.tag,
        amount.ct, amount.iv, amount.tag,
        txnHash,
      ]
    );
    return rows[0].id;
  });
}

async function settlementForDate(vendorId, dateISO) {
  return withVendor(vendorId, async (client) => {
    const { rows } = await client.query(
      `SELECT id, txn_hash, amount_ct, amount_iv, amount_tag, status, created_at
         FROM transactions
        WHERE vendor_id = $1
          AND created_at >= $2::date
          AND created_at < ($2::date + INTERVAL '1 day')
        ORDER BY created_at ASC`,
      [vendorId, dateISO]
    );
    return rows;
  });
}

async function recentAuditLogs(vendorId, limit = 50) {
  return withVendor(vendorId, async (client) => {
    const { rows } = await client.query(
      `SELECT id, ts, action, txn_hash, ip, success, detail
         FROM audit_logs
        WHERE vendor_id = $1
        ORDER BY ts DESC
        LIMIT $2`,
      [vendorId, limit]
    );
    return rows;
  });
}

async function writeAudit({ userId, vendorId, action, txnHash, ip, success, detail }) {
  return withVendor(vendorId || -1, async (client) => {
    await client.query(
      `INSERT INTO audit_logs (user_id, vendor_id, action, txn_hash, ip, success, detail)
       VALUES ($1, $2, $3, $4, $5::inet, $6, $7)`,
      [userId || null, vendorId || null, action, txnHash || null,
       ip || null, success !== false, detail ? JSON.stringify(detail) : null]
    );
  });
}

async function logUnauthorized({ role, action, table, ip, detail }) {
  await query(
    'SELECT log_unauthorized_access($1, $2, $3, $4, $5::jsonb)',
    [role || null, action || null, table || null, ip || '',
     detail ? JSON.stringify(detail) : null]
  );
}

module.exports = {
  pool,
  findVendorByEmail,
  findStudent,
  getMfaSecret,
  enrollMfa,
  changePassword,
  listTransactions,
  postPayment,
  settlementForDate,
  recentAuditLogs,
  writeAudit,
  logUnauthorized,
};
