-- Demo data. The migration script also populates the encrypted columns via
-- Node so they are produced with the real MASTER_KEY. This file inserts the
-- non-encrypted scaffolding (vendor codes, names, emails) and is followed by
-- scripts/seed.js to fill encrypted balances and the bcrypt password hash.
-- Idempotent: ON CONFLICT DO NOTHING.

INSERT INTO vendors (vendor_code, name, email, password_hash, role)
VALUES
  ('V-CAFE-01', 'Akan Campus Cafe',  'vendor1@msu.test', 'PLACEHOLDER', 'vendor'),
  ('V-BOOK-02', 'Akan Bookshop',     'vendor2@msu.test', 'PLACEHOLDER', 'vendor')
ON CONFLICT (vendor_code) DO NOTHING;

INSERT INTO students (student_code, name, balance_ct, balance_iv, balance_tag)
VALUES
  ('S-2026-0001', 'Abdulmalik Gampong',  '\x00', '\x00', '\x00'),
  ('S-2026-0002', 'Abdensa Macatanong',  '\x00', '\x00', '\x00'),
  ('S-2026-0003', 'Huamza Ampaso',    '\x00', '\x00', '\x00')
ON CONFLICT (student_code) DO NOTHING;
