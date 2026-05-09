// Role-based access control middleware.

'use strict';

function requireAuth(req, res, next) {
  if (!req.session || !req.session.vendor) {
    if (req.accepts('html')) return res.redirect('/login');
    return res.status(401).json({ error: 'unauthenticated' });
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    const v = req.session && req.session.vendor;
    if (!v) return res.status(401).json({ error: 'unauthenticated' });
    if (!roles.includes(v.role)) return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

module.exports = { requireAuth, requireRole };
