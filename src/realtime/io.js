// Socket.IO bootstrap. Each vendor joins room "vendor:<id>" after handshake
// and only receives events targeted at that room.

'use strict';

const { Server } = require('socket.io');

function attach(httpsServer, sessionMiddleware) {
  const io = new Server(httpsServer, {
    cors: { origin: false },
    // Serve /socket.io/socket.io.js so the dashboard can pull the client
    // script from the same origin (allowed by the strict CSP).
    serveClient: true,
  });

  // Share the express-session with Socket.IO so we can read the authenticated
  // vendor id from the socket handshake.
  io.engine.use(sessionMiddleware);

  io.on('connection', (socket) => {
    const sess = socket.request.session;
    const vendor = sess && sess.vendor;
    if (!vendor) {
      socket.emit('auth:error');
      socket.disconnect(true);
      return;
    }
    socket.join(`vendor:${vendor.id}`);
    socket.emit('ready', { vendorId: vendor.id });
  });

  return io;
}

module.exports = { attach };
