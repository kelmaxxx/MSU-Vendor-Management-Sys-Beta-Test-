// Dashboard real-time + charge form. No frameworks; runs under strict CSP.

(function () {
  'use strict';

  const card = document.getElementById('payment-status');
  const headline = document.getElementById('status-headline');
  const detail = document.getElementById('status-detail');

  function setStatus(kind, head, sub) {
    card.classList.remove('status-idle', 'status-success', 'status-failed');
    card.classList.add('status-' + kind);
    card.querySelector('.status-icon').textContent =
      kind === 'success' ? '✓' : kind === 'failed' ? '✗' : '•';
    headline.textContent = head;
    detail.textContent = sub;
  }

  // Socket.IO live updates
  try {
    const socket = io({ transports: ['websocket'] });
    socket.on('payment:received', (p) => {
      if (p.status === 'success') {
        setStatus(
          'success',
          'Payment received',
          'GHS ' + p.amount + ' from ' + (p.studentName || p.studentCode || 'student') +
          ' — ' + p.txnHash.slice(0, 16) + '…'
        );
      } else {
        setStatus(
          'failed',
          'Payment failed',
          (p.reason || 'unknown error').replace(/_/g, ' ')
        );
      }
    });
    socket.on('disconnect', () => {
      setStatus('idle', 'Reconnecting…', 'Real-time channel dropped. Retrying.');
    });
    socket.on('connect', () => {
      setStatus('idle', 'Awaiting payment', 'Live channel connected.');
    });
  } catch (e) {
    console.warn('Socket.IO unavailable', e);
  }

  // Charge form
  const form = document.getElementById('charge-form');
  if (form) {
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const fd = new FormData(form);
      const csrf = fd.get('_csrf');
      const body = {
        studentCode: fd.get('studentCode'),
        amount: fd.get('amount'),
      };
      const res = await fetch('/api/payments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrf },
        body: JSON.stringify(body),
        credentials: 'same-origin',
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'request_failed' }));
        setStatus('failed', 'Charge rejected', (err.error || 'request failed').replace(/_/g, ' '));
        return;
      }
      // Success: status will arrive over the socket too; keep both paths.
      const ok = await res.json();
      if (ok.status !== 'success') {
        setStatus('failed', 'Payment failed', (ok.reason || '').replace(/_/g, ' '));
      }
      form.reset();
    });
  }
})();
