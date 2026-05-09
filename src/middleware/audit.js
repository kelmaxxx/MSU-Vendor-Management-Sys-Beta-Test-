// Wraps a handler so any caught permission error is logged to
// unauthorized_access_log via the SECURITY DEFINER function.

'use strict';

const queries = require('../db/queries');

const PERM_DENIED_CODES = new Set(['42501', '42P01']); // insufficient_privilege, undefined_table

function isPermissionError(err) {
  return err && (PERM_DENIED_CODES.has(err.code) ||
    /permission denied|policy/i.test(err.message || ''));
}

function asyncHandler(fn) {
  return async (req, res, next) => {
    try {
      await fn(req, res, next);
    } catch (err) {
      if (isPermissionError(err)) {
        try {
          await queries.logUnauthorized({
            role: 'vendor_app_role',
            action: req.method + ' ' + req.path,
            table: null,
            ip: req.ip,
            detail: { code: err.code, msg: err.message },
          });
        } catch (logErr) {
          console.error('unauthorized log failed', logErr);
        }
        return res.status(403).json({ error: 'forbidden' });
      }
      next(err);
    }
  };
}

module.exports = { asyncHandler, isPermissionError };
