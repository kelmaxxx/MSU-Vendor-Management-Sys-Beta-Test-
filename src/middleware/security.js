'use strict';

const helmet = require('helmet');

// Strict security headers. CSP allows inline event handlers from our own
// templates only via 'self'; Socket.IO connect-src allows wss to same origin.
function applySecurity(app) {
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'", 'wss:'],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: false,
      hsts: { maxAge: 15552000, includeSubDomains: true, preload: false },
      referrerPolicy: { policy: 'no-referrer' },
    })
  );
}

module.exports = { applySecurity };
