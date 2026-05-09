'use strict';

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const csrf = require('csurf');

const config = require('./config');
const { applySecurity } = require('./middleware/security');
const { pool } = require('./db/queries');
const realtime = require('./realtime/io');

const authRouter = require('./routes/auth');
const dashboardRouter = require('./routes/dashboard');
const paymentsRouter = require('./routes/payments');
const transactionsRouter = require('./routes/transactions');
const settlementsRouter = require('./routes/settlements');
const securityRouter = require('./routes/security');

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

applySecurity(app);

app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.json({ limit: '64kb' }));
app.use('/static', express.static(path.join(__dirname, '..', 'public'), {
  maxAge: '1h',
  fallthrough: true,
  index: false,
}));

const sessionMiddleware = session({
  store: new PgSession({ pool, tableName: 'session' }),
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000,
  },
  name: 'msu.sid',
});
app.use(sessionMiddleware);

const csrfProtection = csrf();
app.use(csrfProtection);

// Make the Socket.IO instance available to handlers via req.io. Wired below
// after we create the https server.
let ioRef = null;
app.use((req, _res, next) => { req.io = ioRef; next(); });

app.get('/', (req, res) => {
  if (req.session && req.session.vendor) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.use(authRouter);
app.use(dashboardRouter);
app.use(paymentsRouter);
app.use(transactionsRouter);
app.use(settlementsRouter);
app.use(securityRouter);

app.use((err, req, res, _next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('Invalid CSRF token.');
  }
  console.error(err);
  res.status(500).send('Internal error');
});

if (require.main === module) {
  const tlsOpts = {
    key: fs.readFileSync(path.resolve(config.tls.keyPath)),
    cert: fs.readFileSync(path.resolve(config.tls.certPath)),
  };
  const httpsServer = https.createServer(tlsOpts, app);
  ioRef = realtime.attach(httpsServer, sessionMiddleware);
  httpsServer.listen(config.httpsPort, () => {
    console.log(`MSU Vendor Portal listening on https://localhost:${config.httpsPort}`);
  });
}

module.exports = { app };
